"""Deviation 9 adapters. Legacy replay remains an independent unchanged route.

Production selection requires a sealed mechanism receipt; rehearsal results use
their own namespace and never call D1-D3 with mechanism conditions.
"""
import copy,csv,json,math,shutil
from pathlib import Path
from . import replay,dispatcher_tables as tables
from src.paper2.model.engine import Model,run_model
from src.paper2.model.explicit import ExplicitModel
from src.paper2.model.dispatcher import SCHEMA,LiteralCosts
from src.paper2.model.service_times import job_draw_integer,JOB_CLASSES,sha256_file
from src.paper2.verify.invariants import check
from .replay_progress import tracked_run,record_source_commit

def bind(packet,inputs):
    """Packet holds hashes; canonical control holds the single calibration copy."""
    replay.verify_files(packet,'REPLAY_MANIFEST.json');info=replay.read(Path(packet)/'info.json');refs={}
    for slot in tables.SLOTS:
        table=tables.verify(inputs[slot],info['backend'],info['cell']['k'],slot)
        refs[slot]=dict(schema=tables.SCHEMA,manifest_sha256=sha256_file(Path(inputs[slot])/'COST_MANIFEST.json'),
            table_sha256=sha256_file(Path(inputs[slot])/'tables.json'),support=table['support'],backend=table['backend'],k=table['k'],host=table['host'])
    if refs['primary']['host']!=refs['held_out']['host']:raise ValueError('calibration slots differ in host')
    info['dispatcher_inputs']=dict(schema=tables.SCHEMA,slots=refs,
        roles=dict(primary=[0,1],held_out=[2],rates_stationarity=[0,1,2]),
        storage='canonical control calibration files; packet contains hash references only')
    replay.save(Path(packet)/'info.json',info);replay.seal(packet,'REPLAY_MANIFEST.json')

def verified_inputs(packet,inputs):
    replay.verify_files(packet,'REPLAY_MANIFEST.json');info=replay.read(Path(packet)/'info.json')
    refs=info.get('dispatcher_inputs')
    if not refs or refs['schema']!=tables.SCHEMA:raise ValueError('missing or mixed empirical replay inputs')
    out={}
    for slot in tables.SLOTS:
        root=Path(inputs[slot]);r=refs['slots'][slot]
        if sha256_file(root/'COST_MANIFEST.json')!=r['manifest_sha256'] or sha256_file(root/'tables.json')!=r['table_sha256']:
            raise ValueError('cost input seal differs from packet binding')
        out[slot]=tables.verify(root,info['backend'],info['cell']['k'],slot)
        if out[slot]['host']!=r['host'] or out[slot]['support']!=r['support']:raise ValueError('cost identity/support differs')
    return out

def physical_draw(config,cls,tx_id=None,bid=None):
    key=['admission',tx_id] if cls=='admission' else ['block_tx',bid,tx_id] if cls=='block_tx' else ['block_sig',bid]
    return job_draw_integer(config['run_id'],config.get('replicate',0),'service_'+cls,key)

class Prepared:
    """Resolve known tuples before start; never redraw occupancy at acceptance."""
    def __init__(self,config,table):
        self.sampler=tables.Sampler(table,config['run_id'],config.get('replicate',0));self.rows={};self.draws={}
        self.arrivals={};self.block_arrivals={};self.accepts={};self.current=None
        self.inputs=[];self.spec=dict(schema=SCHEMA,mode='explicit',costs={},jobs={},blocks={})
        def job(jid,cls,tx=None,bid=None):
            label=tx['sig_label'] if tx else next(b.get('block_sig_label','valid') for b in config['blocks'] if b['block_id']==bid)
            integer=physical_draw(config,cls,tx['tx_id'] if tx else None,bid)
            donor=self.sampler.physical(cls,label,integer,False);self.rows[jid]=donor;self.draws[jid]=integer
            values={};send=donor['send'];completion=donor['completion']
            for family,component in (('send',send),('completion_'+cls,completion)):
                if component is None:
                    component=self.sampler.marginal(cls,'send' if family=='send' else 'completion',jid)
                for name,ns in component['costs'].items():
                    if name not in ('loop','poll'):values[name]=ns/1e9
            self.spec['jobs'][jid]=values
        for i,a in enumerate(config.get('admissions',[])):
            tx=config['transactions'][a['tx_id']];jid='admission:'+str(i)
            # Cost support for invalid arrivals is independent of valid worker
            # service support. Physical invalid labels still fail if unobserved.
            donor=self.sampler.select('arrival',-1,'valid' if tx.get('structurally_valid',True) else 'invalid',jid)
            job(jid,'admission',tx)
            self.spec['jobs'][jid].update({n:v/1e9 for n,v in donor['costs'].items() if n in ('arrival_pre','arrival_tail')})
        for i,b in enumerate(config.get('blocks',[])):
            bid=b['block_id'];n=len(b['tx_ids']);branch='valid' if b.get('structurally_valid',True) else 'invalid'
            donor=self.sampler.select('block_arrival',n,branch,bid)
            # Prove support before simulation, even if a block later rejects.
            accepted=self.sampler.select('acceptance',n,'valid',bid)
            lookups=donor['lookups']
            if len(lookups)!=n:raise ValueError('donor lookup arity differs from exact block size')
            self.spec['blocks'][bid]=dict(build=donor['costs'].get('block_build',0)/1e9,
                lookups=[v/1e9 for v in lookups],tail=donor['costs'].get('block_tail',0)/1e9,
                accept=accepted['costs'].get('block_accept',0)/1e9,accept_tail=accepted['costs'].get('block_accept_tail',0)/1e9)
            for j,txid in enumerate(b['tx_ids']):job(f'block:{i}:tx:{j}','block_tx',config['transactions'][txid],bid)
            job(f'block:{i}:sig','block_sig',bid=bid)
        LiteralCosts(self.spec)  # reject negative/nonfinite costs/mixed keys

    def sample(self,cls,label,integer):
        row=self.sampler.physical(cls,label,integer)
        if self.current is None or row['id']!=self.rows[self.current.job_id]['id']:raise ValueError('service/own-stage tuple changed')
        return row['occupancy_ns']/1e9,'valid' if label=='valid' else 'invalid'

def keys(packet,config):
    # Reuse the legacy input-binding validation without constructing another
    # simulation/model or changing the legacy adapter's routing/outputs.
    computed=replay.read(Path(packet)/'keys.json')
    if config.get('g3_input_version')==6:
        from . import public_corpus
        from .compact import unpack,expand
        import zipfile
        info=replay.read(Path(packet)/'info.json');archive=(replay.safe_file(Path(packet).parent,info['public_corpus_ref']) if info.get('public_corpus_ref') else Path(packet)/'prototype/public-corpus.zip')
        public_corpus.validate_archive(archive,info['public_corpus'])
        with zipfile.ZipFile(archive) as z:doc=expand(unpack(z.read('corpus.bin')))
        actual={n:dict(cache_key=e['cache_key'],size_bytes=doc['workload']['transactions'][n]['size_bytes']) for n,e in doc['transactions'].items()}
        if actual!=computed or doc['workload']['transactions']!=config['transactions'] or doc['workload']['blocks']!=config['blocks']:
            raise ValueError('compact corpus/key/workload mismatch')
    return computed

class EmpiricalModel(ExplicitModel):
    def __init__(self,config,packet,prepared):
        self.directory=Path(packet);self.keys=keys(packet,config);self.prepared=prepared
        from .cycle_protocol import model_config
        value=model_config(config);value['dispatcher']=prepared.spec
        super().__init__(value);self.service=prepared
        self.config['prototype']=dict(mode='precomputed-key-replay-v1')
    def _key(self,tx):return self.keys[tx['tx_id']]['cache_key']
    def _enqueue(self,job):
        self.prepared.current=job
        return super()._enqueue(job)
    def _block_work(self,bid,kind,n,index=None):
        if kind=='accept':
            active=self.dispatcher.active[1]['identity'];own=self.prepared.rows[active]
            _,checks=self.ledger.check_block(self.block_transactions[bid])
            branch='rejected' if self.block_reasons[bid] or not all(r['passed'] for r in checks) else 'valid'
            donor=own.get('acceptance')
            if donor and donor['size']==n:
                support=self.prepared.sampler.table['support'].get('acceptance',{}).get(str(n),[])
                if branch in support and donor['branch']!=branch:donor=None
            else:donor=None
            if donor:
                self.prepared.sampler.events.append(dict(family='acceptance',identity=bid,donor_id=donor['source_hash'],
                    fallback=branch not in support,paired=True,branch=branch,approximation=None))
            else:
                donor=self.prepared.sampler.select('acceptance',n,branch,bid)
                self.prepared.sampler.events[-1]['approximation']='independent acceptance marginal: own physical tuple has no compatible acceptance'
            costs=donor['costs'];profile=self.literal.blocks[bid]
            profile.update(accept=costs.get('block_accept',0)/1e9,accept_tail=costs.get('block_accept_tail',0)/1e9)
            self.config['dispatcher']['blocks'][bid].update(profile)
        return super()._block_work(bid,kind,n,index)
    def extra_manifest(self,directory):
        result=super().extra_manifest(directory)
        result.update(replay.ReplayModel.extra_manifest(self,directory))
        replay.save(directory/'cost-sampling.json',self.prepared.sampler.receipt())
        result['dispatcher_costs']=dict(schema=tables.SCHEMA,path='cost-sampling.json',sha256=sha256_file(directory/'cost-sampling.json'))
        return result

class ZeroEmpiricalModel(replay.ReplayModel):
    def __init__(self,config,packet,sample,prepared):
        super().__init__(config,packet,sample);self.service=prepared;self.prepared=prepared
    def _enqueue(self,job):self.prepared.current=job;return super()._enqueue(job)
    def extra_manifest(self,directory):
        value=super().extra_manifest(directory);replay.save(directory/'cost-sampling.json',self.prepared.sampler.receipt());return value

def simulate(packet,table,sample,output):
    config=replay.read(Path(packet)/'config.json')
    if config.get('structural_cost',0) or config.get('state_cost',0) or 'dispatcher' in config:
        raise ValueError('mixed legacy/explicit dispatcher charges or versions')
    config.update(output='full',output_dir=str(output),structural_cost=0,state_cost=0,
        service=dict(mode='constant',seconds={c:dict(valid=0,bit_flip=0,random_bytes=0) for c in JOB_CLASSES}))
    prepared=Prepared(config,table)
    if LiteralCosts(prepared.spec).positive:factory=lambda c:EmpiricalModel(c,packet,prepared)
    else:factory=lambda c:ZeroEmpiricalModel(c,packet,sample,prepared)
    return run_model(config,model_type=factory)

def historical_selection(receipt,code_commit):
    """Phase E reference only; never called by the production selector."""
    if receipt is None:raise ValueError('production refuses without sealed rehearsal-v2 mechanism receipt')
    replay.verify_files(receipt,'MECHANISM_MANIFEST.json');value=replay.read(Path(receipt)/'mechanism.json')
    if value.get('namespace')!='rehearsal-v2 mechanism; excluded from G3' or value.get('code_commit')!=code_commit:
        raise ValueError('wrong mechanism namespace/source commit')
    records=[]
    for directory in sorted((Path(receipt)/'embedded').iterdir()):
        manifest=replay.read(directory/'RESULT_MANIFEST.json')
        if sha256_file(directory/'RESULT_MANIFEST.json')!=(directory/'RESULT_MANIFEST.json.sha256').read_text().strip():raise ValueError('embedded result seal mismatch')
        entry=next(r for r in manifest['files'] if r['path']=='result.json')
        if sha256_file(directory/'result.json')!=entry['sha256']:raise ValueError('embedded result differs from its source seal')
        result=replay.read(directory/'result.json')
        if result['code_commit']!=code_commit:raise ValueError('embedded result code mismatch')
        records.append(result)
    computed=mechanism(records)
    if computed['reading']!=value['reading'] or computed['comparisons']!=value['comparisons']:raise ValueError('mechanism reading does not reproduce sealed inputs')
    if value['reading']=='MECHANISM SUPPORTED':return 'explicit'
    if value['reading']=='NOT SUPPORTED':return 'legacy'
    raise ValueError('undefined mechanism model selection')


def selection(receipt,code_commit):
    """Production accepts only the sealed, reproducible rehearsal-v2 Q7 reader."""
    if receipt is None:raise ValueError('production refuses without sealed rehearsal-v2 Q7 receipt')
    from . import rehearsal_v2_q7 as q7
    receipt=Path(receipt)
    from .input_trust import reject
    reject(receipt)
    if not (receipt/'RESULT_MANIFEST.json').is_file():raise ValueError('requires sealed rehearsal-v2 Q7 reader verdict')
    replay.verify_files(receipt,'RESULT_MANIFEST.json')
    value=replay.read(receipt/'result.json')
    reader=sha256_file(Path(q7.__file__))
    if (value.get('namespace')!='paper2-g3-rehearsal-v2' or value.get('code_commit')!=code_commit or
            value.get('reader_source_sha256')!=reader):
        raise ValueError('wrong Q7 reader digest, namespace or source commit')
    records=[]
    for directory in sorted((receipt/'cells').iterdir()) if (receipt/'cells').is_dir() else ():
        replay.verify_files(directory,'RESULT_MANIFEST.json')
        original=directory/'ORIGINAL_RESULT_MANIFEST.json'
        if sha256_file(original)!=(directory/'ORIGINAL_RESULT_MANIFEST.json.sha256').read_text().strip():
            raise ValueError('embedded original result seal mismatch')
        seal=replay.read(original);result=replay.read(directory/'result.json')
        row=next(r for r in seal['files'] if r['path']=='result.json')
        if sha256_file(directory/'result.json')!=row['sha256']:raise ValueError('embedded original result content mismatch')
        provenance=seal['provenance']
        if (result.get('namespace')!='paper2-g3-rehearsal-v2' or result.get('code_commit')!=code_commit or
            result.get('reader_source_sha256')!=reader or provenance.get('source_code_commit')!=code_commit or
            provenance.get('replay_code_commit')!=code_commit or provenance.get('replay_tree_clean') is not True):
            raise ValueError('embedded Q7 reader digest or source provenance mismatch')
        records.append(result)
    computed=q7.evaluate(records)
    if any(value.get(k)!=v for k,v in computed.items()):raise ValueError('Q7 verdict does not reproduce sealed inputs')
    if computed['verdict']=='SUPPORTED':return 'explicit'
    if computed['verdict']=='NOT SUPPORTED':return 'legacy'
    raise ValueError('INVALID Q7 evidence: no model selection')

@tracked_run
def execute(packet,inputs,output,*,purpose,mechanism=None,identity=None):
    packet=Path(packet);data=replay.stage('empirical input verification',verified_inputs,packet,inputs);info=replay.read(packet/'info.json')
    record_source_commit(info['source_commit'])
    import os
    if os.environ.get('GITHUB_ACTIONS')=='true':
        from src.paper2.model.engine import _git_state
        if _git_state()['commit']!=info['source_commit']:raise ValueError('replay checkout differs from recorded source commit')
    if purpose not in ('rehearsal-v2','production'):raise ValueError('explicit replay purpose required')
    models=('legacy','explicit') if purpose=='rehearsal-v2' else (selection(mechanism,info['source_commit']),)
    output=Path(output)
    from .replay_progress import owns_output
    if output.exists() and not owns_output(output):raise FileExistsError('model/slot outputs must be new')
    output.mkdir(parents=True,exist_ok=owns_output(output))
    result=dict(namespace=purpose,code_commit=info['source_commit'],cell=info['cell'],
        calibration_inputs=info['dispatcher_inputs'],atomic_group_spreads={s:data[s]['atomic_groups'] for s in data},
        prototype=replay.postprocess_prototype(packet,output/'prototype-check'),models={})
    if identity:result.update(identity)
    if purpose=='production':
        from .measurement_conditions import apply
        apply(result['prototype'],packet,info['window'])
    # Diagnostic rehearsal always reports both models, including invalid cases.
    # Production INVALID repetitions retain prototype correctness evidence; D2
    # remains applied by the existing production gather, never by Q7.
    if purpose!='production' or result['prototype']['validity']['passed']:
        for name in models:
            result['models'][name]={}
            for slot,sample in (('primary','primary.csv'),('held_out','held-out.csv')):
                target=output/name/slot
                e,m=(replay.stage(name+' '+slot+' simulation',replay.simulate,packet,packet/sample,target) if name=='legacy'
                     else replay.stage(name+' '+slot+' simulation',simulate,packet,data[slot],packet/sample,target))
                value=dict(metrics=replay.stage(name+' '+slot+' metrics',replay.metrics,e,e.parent/'jobs.csv',m,*info['window']),
                    violations=replay.stage(name+' '+slot+' full invariant checker',check,e,e.parent/'jobs.csv',m))
                value['comparison']=replay.stage(name+' '+slot+' comparison',replay.compare,result['prototype']['metrics'],value['metrics'],diagnostic=slot=='held_out')
                value['cost_sampling']=replay.read(target/'cost-sampling.json') if name=='explicit' else None
                value['service_and_cycle']=cycle_diagnostics(e,data[slot],name)
                result['models'][name][slot]=value
    if purpose=='production':
        for slot in ('primary','held_out'):
            if models[0] in result['models']:result[slot]=result['models'][models[0]][slot]
    replay.save(output/'result.json',result);replay.seal(output,'RESULT_MANIFEST.json');return result

def cycle_diagnostics(events,table,mode):
    """Streaming diagnostic, never a service input or agreement/validity gate."""
    import statistics
    def stats(values):
        if not values:return dict(count=0,mean=None,p50=None,p95=None,p99=None,max=None)
        v=sorted(values);n=len(v)
        return dict(count=n,mean=statistics.fmean(v),p50=statistics.median(v),p95=v[math.ceil(.95*n)-1],p99=v[math.ceil(.99*n)-1],max=v[-1])
    last={};cycles={c:[] for c in JOB_CLASSES};service={c:[] for c in JOB_CLASSES};gaps={c:[] for c in JOB_CLASSES};stages={};excluded=0
    with Path(events).open(newline='') as f:
        for row in csv.DictReader(f):
            event=row['event'];cls=row['job_class'];worker=row['worker_id']
            if event=='start' and worker in last:
                c,start,end,waiting=last.pop(worker)
                if waiting:cycles[c].append(float(row['t'])-start);gaps[c].append(float(row['t'])-end)
                else:excluded+=1
            if event=='end':
                service[cls].append(float(row['service_time']));last[worker]=(cls,float(row['start_t']),float(row['t']),int(row['q_admission'])+int(row['q_block'])>0)
            if event=='dispatcher_stage_end':
                stage=json.loads(row['detail']);stages[stage['kind']]=stages.get(stage['kind'],0)+stage['duration']
    result={}
    for cls in JOB_CLASSES:
        donors=table['tuples'].get(cls,[]);cal={n:stats([r[n+'_ns']/1e9 for r in donors]) for n in ('occupancy','primitive','cycle')}
        observed=stats(cycles[cls]);mean=cal['cycle']['mean']
        result[cls]=dict(calibration=cal,simulated_service=stats(service[cls]),implied_cycle=observed,following_gap=stats(gaps[cls]),
            implied_minus_calibration_cycle=observed['mean']-mean if observed['mean'] is not None and mean is not None else None)
    return dict(report_only=True,service_quantity='occupancy' if mode=='explicit' else 'legacy cycle',classes=result,
        excluded_empty_queue_cycles=excluded,dispatcher_exclusive_seconds=stages,dispatcher_union_seconds=sum(stages.values()),
        collection_wait_limitation=table['collection_wait_limitation'],capture_overhead=table['overhead'])

def mechanism(records):
    comparisons=[]
    for cell,record in enumerate(records):
        for slot in ('primary','held_out'):
            passed=False;closure=None;admission_reduced=False
            try:
                p=record['prototype']['metrics'];old=record['models']['legacy'][slot];new=record['models']['explicit'][slot]
                gap=abs(p['mean_block_delay']-old['metrics']['mean_block_delay'])
                if gap>0:closure=1-abs(p['mean_block_delay']-new['metrics']['mean_block_delay'])/gap
                admission_reduced=abs(p['mean_admission_wait']-new['metrics']['mean_admission_wait'])<abs(p['mean_admission_wait']-old['metrics']['mean_admission_wait'])
                metrics_complete=all(set(replay.BANDS)<=set(m) for m in (p,old['metrics'],new['metrics']))
                # Q7 is only the registered gap-closure/admission reading.
                # Validity/invariant facts remain in the sealed source result;
                # they are not a new threshold or a D1-D3 mechanism input.
                passed=closure is not None and closure>=.7 and admission_reduced and metrics_complete
            except (KeyError,TypeError,ValueError):pass
            comparisons.append(dict(cell=cell,slot=slot,closure=closure,admission_difference_strictly_reduced=admission_reduced,passed=passed))
    identities={(r.get('cell',{}).get('backend'),r.get('cell',{}).get('k')) for r in records}
    return dict(namespace='rehearsal-v2 mechanism; excluded from G3',reading='MECHANISM SUPPORTED' if len(records)==2 and len(identities)==2 and len(comparisons)==4 and all(r['passed'] for r in comparisons) else 'NOT SUPPORTED',comparisons=comparisons,
        no_tuning=True,affects_D1_D3=False)

def gather(results,output):
    output=Path(output)
    if output.exists():raise FileExistsError('mechanism gather must be new')
    output.mkdir(parents=True);records=[];commits=set()
    for i,directory in enumerate(results):
        replay.verify_files(directory,'RESULT_MANIFEST.json');value=replay.read(Path(directory)/'result.json')
        if value.get('namespace')!='rehearsal-v2':raise ValueError('production data cannot feed exploratory mechanism')
        records.append(value);commits.add(value['code_commit']);target=output/'embedded'/str(i);target.mkdir(parents=True)
        # Sealed source result + its manifest are embedded, preserving hashes.
        for name in ('result.json','RESULT_MANIFEST.json','RESULT_MANIFEST.json.sha256'):shutil.copyfile(Path(directory)/name,target/name)
    if len(commits)!=1:raise ValueError('mechanism sources differ in code commit')
    result=mechanism(records);result['code_commit']=commits.pop()
    replay.save(output/'mechanism.json',result);replay.seal(output,'MECHANISM_MANIFEST.json');return result

def execute_from_index(root,run_id,inputs,output,*,purpose,mechanism=None):
    index=replay.verify_index(root);run=next(r for r in index['runs'] if r['run_id']==run_id)
    directory,info=replay.packet(root,index,run)
    identity=dict(run_id=run_id,cell_id=run['cell_id'],replicate=run['replicate'],input_sha256=run['manifest_sha256'],
        code_commit=index['code_commit'],source_run_id=run.get('source_run_id',index['source_run_id']),seeds=info['seeds'])
    return execute(directory,inputs,output,purpose=purpose,mechanism=mechanism,identity=identity)
