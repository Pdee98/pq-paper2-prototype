"""Calibration-only empirical dispatcher bundles, exact-size support and seals.

Never reads measured prototype stages to fill calibration support. This module
is post-processing: JSON/catalog allocation is outside every measured loop.
"""
import csv,hashlib,json,math,shutil
from pathlib import Path
from . import stage_capture as capture

SCHEMA='paper2-dispatcher-empirical-v1'
ALGORITHM='calibration-exclusive-final-milestone-v1'
DRAW_VERSION='paper2-dispatcher-cost-draw-v1'
SLOTS={'primary':(0,1),'held_out':(2,)}

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def read(path):return json.loads(Path(path).read_bytes())
def write(path,value):Path(path).write_bytes(canonical(value)+b'\n')

def draw(run_id,replicate,family,identity):
    """New named stream; no call to or consumption of old service/workload RNGs."""
    return int.from_bytes(hashlib.sha256(canonical([DRAW_VERSION,run_id,replicate,'dispatcher_cost_'+family,identity])).digest(),'big')

def support(families):
    return {name:{str(size):sorted({r['branch'] for r in rows if r['size']==size})
        for size in sorted({r['size'] for r in rows})} for name,rows in sorted(families.items())}

def callback_bundles(directory):
    """Stream exclusive intervals, retaining only active nested callbacks."""
    directory=Path(directory);spec=read(directory/'stages.json')
    context=spec['context']
    if context.get('window')!='representative-cycle' or context.get('calibration_only') is not True:
        raise ValueError('empirical inputs must be representative calibration, never prototype/proxy')
    audit=capture.audit(directory)
    if not audit['passed']:raise ValueError('invalid calibration partition')
    active={};result=[];jobs=spec['jobs'];blocks=spec['blocks'];previous=None
    for seq,row in enumerate(capture.rows(directory)):
        t,event,family,stage,callback,parent,job,block,worker,size,branch,*_=row
        if event==capture.E['idle_interval']:continue
        if event==capture.E['callback_entry']:
            active[callback]=dict(family=capture.FAMILIES[family],size=size,branch='valid',job=job,block=block,
                costs={},lookups=[],milestones={},start=None,entry_ns=t,hash=hashlib.sha256(),first_row=seq,callback=callback,children=[])
        item=active[callback];item['hash'].update(capture.ROW.pack(*row))
        if job>=0:item['job']=job
        if block>=0:item['block']=block
        if event in (capture.E['send'],capture.E['receive']):item['milestones'][capture.EVENTS[event]]=t
        if event==capture.E['decision']:item['branch']='rejected' if branch else 'valid'
        if event==capture.E['group_end'] and branch:item['branch']='invalid'
        if event==capture.E['stage_entry']:
            item['start']=(t,stage)
            if capture.STAGES[stage]=='block_lookups' and (not item['lookups'] or
                    previous[1]==capture.E['stage_exit'] and previous[4]==callback):item['lookups'].append(0)
        elif event==capture.E['stage_exit']:
            begin,kind=item['start'];name=capture.STAGES[kind];value=t-begin;item['start']=None
            if name=='block_lookups':item['lookups'][-1]+=value
            else:item['costs'][name]=item['costs'].get(name,0)+value
        previous=row
        if event!=capture.E['callback_exit']:continue
        del active[callback]
        # Lookup stages may be suspended/resumed around inline sends: group the
        # pieces by actual lookup markers below, rather than inventing a slope.
        item.update(source_hash=item.pop('hash').hexdigest(),last_row=seq,
            job_id=jobs[item['job']] if item['job']>=0 else None,
            block_id=blocks[item['block']] if item['block']>=0 else None)
        item.pop('start');item.pop('job');item.pop('block')
        item['source']=dict(replicate=context['replicate'],callback=callback,capture_sha256=spec['sha256'])
        if parent>=0:active[parent]['children'].append(item)
        else:result.append(item)
    return spec,result

def flatten(items):
    for row in items:
        yield row
        yield from flatten(row['children'])

def compile_sources(paths,slot):
    if slot not in SLOTS:raise ValueError('unsupported calibration slot')
    contexts=[];families={};tuples={};sources=[];atomic=[]
    for path in paths:
        directory=Path(path);spec,callbacks=callback_bundles(directory);context=spec['context']
        if context['replicate'] not in SLOTS[slot]:raise ValueError('wrong donor slot')
        contexts.append(context);sources.append(dict(replicate=context['replicate'],stage_sha256=spec['sha256'],
            metadata_sha256=capture.sha(directory/'stages.json'),cycles_sha256=capture.sha(directory/'cycles.csv')))
        all_rows=list(flatten(callbacks));sends={r['job_id']:r for r in all_rows if r['family']=='send'}
        completions={r['job_id']:r for r in all_rows if r['family'].startswith('completion_')}
        accepts={r['block_id']:r for r in all_rows if r['family']=='acceptance'}
        for row in all_rows:
            family=row['family']
            if family not in ('arrival','block_arrival','acceptance'):continue
            lower=context['epoch_ns']+round(context['warmup']*1e9);upper=lower+round(context['measurement']*1e9)
            if not lower<=row['entry_ns']<upper:continue
            donor=dict(family=family,size=row['size'] if family!='arrival' else -1,branch=row['branch'],
                costs=row['costs'],lookups=row['lookups'],source=row['source'],source_hash=row['source_hash'])
            # Arrival branch uses captured terminal structural/drop milestones;
            # absent branches later use within-family pooled costs, never service.
            donor['id']=digest(donor);families.setdefault(family,[]).append(donor)
        with (directory/'cycles.csv').open(newline='') as f:
            for row in csv.DictReader(f):
                cls=row['job_class'];identity=row['job_id'];send=sends.get(identity);completion=completions.get(identity)
                if row['backend']!=context['backend']+':'+cls or row['source']!=f'concurrency-cycle-k{context["k"]}-rep{context["replicate"]}':
                    raise ValueError('calibration row backend/k/repetition differs from capture')
                value=dict(job_class=cls,label='valid' if row['operation']=='verify' else row['variant'],
                    occupancy_ns=int(row['occupancy_ns']),primitive_ns=int(row['primitive_ns']),cycle_ns=int(row['duration_ns']),
                    source=dict(replicate=context['replicate'],csv_row_sha256=digest(row)),linked=bool(send and completion),
                    send=send,completion=completion,acceptance=next((r for r in flatten(completion['children'])
                        if r['family']=='acceptance'),None) if completion else None)
                if not 0<value['occupancy_ns']<=value['cycle_ns'] or value['primitive_ns']<0:raise ValueError('invalid occupancy/primitive/cycle row')
                if send and completion:
                    start=send['milestones']['send'];end=completion['milestones']['receive'];epoch=context['epoch_ns']
                    if start-epoch!=int(row['send_ns']) or end-epoch!=int(row['receive_ns']) or end-start!=value['occupancy_ns']:
                        raise ValueError('physical occupancy does not match its own captured send/receive')
                value['id']=digest(value);tuples.setdefault(cls,[]).append(value)
        atomic.append(capture.atomic_groups(directory,True))
    identity={(r['backend'],r['k'],r['host']) for r in contexts}
    if len(identity)!=1 or sorted(r['replicate'] for r in contexts)!=list(SLOTS[slot]):
        raise ValueError('backend/k/host or repetition isolation mismatch')
    backend,k,host=identity.pop()
    return dict(schema=SCHEMA,algorithm=ALGORITHM,draw_version=DRAW_VERSION,slot=slot,
        backend=backend,k=k,host=host,repetitions=list(SLOTS[slot]),sources=sources,families=families,
        tuples=tuples,support=support(families),atomic_groups=atomic,
        overhead=[dict(replicate=r['replicate'],**(read(Path(p)/'stages.json')['append_cost'] or
            dict(is_overhead_estimate=False,reason='NOT RECORDED literal fixture'))) for r,p in zip(contexts,paths)],
        pairing=dict(linked=sum(r['linked'] for values in tuples.values() for r in values),
                     unlinked=sum(not r['linked'] for values in tuples.values() for r in values)),
        mapping='atomic groups charged before final milestone; intermediate real milestones may shift later',
        collection_wait_limitation='sampled occupancy includes collection wait; post-receive work is marginal conditional approximation')

def build(paths,slot,output):
    """Seal calibration evidence and derived table before any simulation."""
    from .replay import seal,audit_file
    output=Path(output)
    if output.exists():raise FileExistsError('cost tables must be new')
    output.mkdir(parents=True);copied=[]
    for source in paths:
        source=Path(source);rep=read(source/'stages.json')['context']['replicate'];target=output/'sources'/str(rep)
        target.mkdir(parents=True)
        for name in ('stages.bin','stages.json','cycles.csv'):shutil.copyfile(source/name,target/name)
        copied.append(target)
    table=compile_sources(copied,slot);write(output/'tables.json',table)
    for file in output.rglob('*'):
        if file.is_file():audit_file(file)
    seal(output,'COST_MANIFEST.json');return verify(output)

def verify(directory,backend=None,k=None,slot=None):
    from .replay import verify_files
    directory=Path(directory);verify_files(directory,'COST_MANIFEST.json');table=read(directory/'tables.json')
    if table.get('schema')!=SCHEMA or table.get('algorithm')!=ALGORITHM:raise ValueError('mixed/unsupported dispatcher version')
    for name,expected in (('backend',backend),('k',k),('slot',slot)):
        if expected is not None and table[name]!=expected:raise ValueError('cost table '+name+' mismatch')
    actual=compile_sources([directory/'sources'/str(rep) for rep in table['repetitions']],table['slot'])
    if actual!=table:raise ValueError('cost table/tuple/support/source integrity mismatch')
    return table

class Sampler:
    def __init__(self,table,run_id,replicate):
        if table.get('schema')!=SCHEMA or table['support']!=support(table['families']):raise ValueError('unsupported empirical table/support')
        self.table,self.run_id,self.replicate=table,run_id,replicate;self.events=[]

    def select(self,family,size,branch,identity,integer=None):
        rows=[r for r in self.table['families'].get(family,[]) if r['size']==size]
        if not rows:raise ValueError('empty family or out-of-support exact size: '+family+'/'+str(size))
        matching=[r for r in rows if r['branch']==branch];fallback=not matching
        index=draw(self.run_id,self.replicate,family,identity) if integer is None else integer
        donor=(matching or rows)[index%len(matching or rows)]
        self.events.append(dict(family=family,size=size,branch=branch,donor_id=donor['id'],
            fallback=fallback,reason='unsupported branch: pooled within exact size/backend/k/slot' if fallback else None,
            stream='dispatcher_cost_'+family,draw=str(index),approximation=None))
        return donor

    def physical(self,cls,label,integer,observe=True):
        rows=[r for r in self.table['tuples'].get(cls,[]) if r['label']==label]
        if not rows:raise ValueError('missing physical service class/label; no valid-service fallback')
        row=rows[integer%len(rows)]
        if observe:self.events.append(dict(family='physical_'+cls,donor_id=row['id'],paired=row['linked'],fallback=False,
            approximation=None if row['linked'] else 'independent named marginals: missing own send/completion link'))
        return row

    def receipt(self):
        return dict(schema=SCHEMA,slot=self.table['slot'],events=self.events,
            fallback_count=sum(r.get('fallback',False) for r in self.events),
            paired_count=sum(r.get('paired',False) for r in self.events),
            unlinked_count=sum(r.get('approximation') is not None for r in self.events))

    def marginal(self,cls,component,identity):
        rows=[r[component] for r in self.table['tuples'].get(cls,[]) if r.get(component)]
        if not rows:raise ValueError('empty unlinked marginal family: '+component+'/'+cls)
        stream='unlinked_'+component+'_'+cls;integer=draw(self.run_id,self.replicate,stream,identity)
        row=rows[integer%len(rows)]
        self.events.append(dict(family=component,identity=identity,donor_id=row['source_hash'],fallback=False,
            approximation='independent named marginal for unlinked '+component,stream='dispatcher_cost_'+stream,draw=str(integer)))
        return row
