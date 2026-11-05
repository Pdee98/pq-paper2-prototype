"""Deviation 6 orchestration; validation remains blocked on author-set caps."""
import json,math,os,statistics,tempfile,time
from pathlib import Path
from . import corpus,public_corpus,replay,runner
from .cycle_calibration import calibrate_backend
from .cycle_protocol import cycle_cells,corpus_group,volume_projection
from src.paper2.workload import generate_workload
from src.paper2.model.engine import _git_state

def group_parameters(cell,rep):
    identity='secondary-regime' if cell.get('role')=='secondary' else corpus_group(cell,rep)
    return dict(runner.parameters(cell['rate'],rep,cell['period']),run_id='paper2-g3-cycle-'+identity)

def secondary_cell(ref):
    rate=1115.433019832252
    return dict(ref,backend='xmss',policy='fifo',role='secondary',rho=.5,rho_cold=None,rate=rate,period=128/rate,
        dispatcher_utilisation=rate*ref['d_dispatch'],g3_input_version=6,B_ref=ref['B_ref_cycle'],B_cold=ref['B_cold_cycle'])

def execute(root):
    if runner.ENGINEERING_CAPS is None:raise RuntimeError('STOP: validation awaits diagnostic v3 and author-set preparation/serialisation caps')
    root=Path(root).resolve()
    if root==runner.ROOT or runner.ROOT in root.parents:raise ValueError('runner output must be outside checkout')
    if runner.platform.machine().lower() not in ('aarch64','arm64') or len(os.sched_getaffinity(0))<4:raise RuntimeError('ARM runner with at least four usable vCPUs required')
    if not (root/'conformance.json').is_file():raise RuntimeError('native conformance required')
    state=dict(deviation=6,status='cycle calibration',cells=[],prototypes=[]);totals={};sizes={};pilots={};refs={};started=time.monotonic()
    runner.save(root/'protocol.json',state)
    try:
        with tempfile.TemporaryDirectory(prefix='paper2-cycle-private-') as td:
            private=Path(td)
            for backend in runner.BACKENDS:
                at=time.perf_counter();data=corpus.build(generate_workload(runner.parameters(2560,0,.05,horizon=.1)),backend,primitive_checks=True)
                cp=corpus.write(data,private/(backend+'-pilot.json'));pilots[backend]=data['presigning']
                runner.account(root,totals,'pilot',time.perf_counter()-at)
                refs[backend]=calibrate_backend(backend,cp,root,totals,min(runner.STAGE_CAPS['calibration']-totals.get('calibration',0),runner.remaining(root)))
                size=public_corpus.write_archive(data,private/(backend+'-size.zip'),full_path=cp);n=len(data['transactions'])
                sizes[backend]={f+'_per_tx':size[f]/n for f in ('compressed_bytes','uncompressed_bytes')};runner.save(root/'compact-sizing.json',sizes)
            planned=cycle_cells({b:refs[b] for b in runner.VALIDATION});secondary=secondary_cell(refs['xmss'][1])
            eligible,excluded=runner.partition_cells(planned);state.update(cells=planned,eligible_cells=eligible,excluded_cells=excluded,secondary_cell=secondary)
            runner.save(root/'dispatcher-guard.json',dict(cells=planned,eligible_cells=eligible,excluded_cells=excluded,secondary=secondary,limit=.5))
            projection=volume_projection(planned,sizes);state['corpus_projection']=projection;runner.save(root/'projection-compact-corpus.json',projection);runner.save(root/'protocol.json',state)
            if not projection['passed']:raise RuntimeError('STOP: projected compact corpus exceeds 2 GB')
            if secondary['dispatcher_utilisation']>.5:raise RuntimeError('STOP: required secondary regime cell fails dispatcher guard')
            planned=planned+[secondary];count=3*len(eligible)+1
            inputs=root/'replay-inputs';index=replay.initialize(inputs,planned,excluded,os.environ.get('GITHUB_SHA') or _git_state()['commit'],os.environ.get('GITHUB_RUN_ID','local'))
            groups={};signing_projection=0
            for c in [*eligible,secondary]:
                for rep in range(1 if c.get('role')=='secondary' else 3):
                    name='secondary-regime' if c.get('role')=='secondary' else corpus_group(c,rep)
                    groups.setdefault(name,dict(cell=c,rep=rep,workload=generate_workload(group_parameters(c,rep))))
            for backend in runner.VALIDATION:
                messages=sum(len(g['workload']['transactions'])+len(g['workload']['blocks']) for g in groups.values() if g['cell']['backend']==backend)
                ledgers=[r for v in pilots[backend].values() for r in v['keys']]
                rate=sum(r['count'] for r in ledgers)/(sum(r['signing_ns'] for r in ledgers)/1e9)
                keytime=statistics.fmean(r['keygen_ns'] for r in ledgers)/1e9
                signing_projection+=1.25*(messages/rate+(math.ceil(messages/512)+2*len(groups))*keytime)/2+messages/refs[backend][2]['B_ref_cycle']
            if signing_projection>runner.STAGE_CAPS['presigning']:raise RuntimeError('STOP: fixed signing projection exceeds cap')
            runner.project(root,'presigning',runner.arm_remaining_projection(signing_projection,count),dict(signing_seconds=signing_projection,runs=count,corpus=projection))
            for name,g in groups.items():
                at=time.perf_counter();data=corpus.build(g.pop('workload'),g['cell']['backend'],processes=2,primitive_checks=True)
                g['path']=corpus.write(data,private/(name+'.json'));runner.account(root,totals,'presigning',time.perf_counter()-at)
            runner.project(root,'prototype',runner.arm_remaining_projection(0,count),dict(runs=count,service='calibration cycles'))
            for cell_id,c in enumerate(planned):
                if c['dispatcher_utilisation']>.5:continue
                for rep in range(1 if c.get('role')=='secondary' else 3):
                    name='secondary-regime' if c.get('role')=='secondary' else corpus_group(c,rep)
                    cp=groups[name]['path'];doc=replay.read(cp);rid='secondary-regime' if c.get('role')=='secondary' else f'cell{cell_id}-r{rep}'
                    cfg=dict(runner.settings(doc['workload'],c,root/'validation'/rid/'prototype'),g3_input_version=6,
                        calibration_cycle_means=c['cycle_means'],diagnostic_instrumentation=False)
                    proto=runner.fresh(runner.prototype_run,(cfg,cp,replay.sha256_file(cp)),runner.remaining(root),progress_path=Path(cfg['output_dir'])/'progress.jsonl',
                        phase_timeouts=dict(runner.ENGINEERING_CAPS,**{'prototype window':110}),partial_dir=root/'timeouts'/rid)
                    row=next(r for r in index['runs'] if r['run_id']==rid)
                    reference=refs[c['backend']][c['k']]
                    row['manifest_sha256']=replay.create_packet(inputs/rid,cfg,cp,proto,reference['held_out_cycle_samples'],c,rep,
                        shared_public='shared-corpora/'+name+'/public-corpus.zip',primary=reference['primary_cycle_samples'])
                    replay.write_index(inputs,index)
                    state.setdefault('arm_corpus_audits',{})[rid]=replay.read(inputs/rid/'info.json')['arm_corpus_audit']
                    state['prototypes'].append(dict(run_id=rid,cell=c,replicate=rep,prototype=proto));state['public_corpus']=public_corpus.audit_upload(inputs)
                    for phase,seconds in proto['phase_seconds'].items():
                        stage='prototype' if phase=='prototype window' else phase;totals[stage]=totals.get(stage,0)+seconds
                        cap=runner.STAGE_CAPS[stage] if stage=='prototype' else count*runner.ENGINEERING_CAPS[stage]
                        if totals[stage]>cap:raise RuntimeError('STOP: fixed '+stage+' stage cap exceeded')
                    runner.save(root/'stage-times.json',dict(elapsed_seconds=totals,caps_seconds=runner.STAGE_CAPS));runner.save(root/'protocol.json',state)
            index['status']=replay.PENDING;replay.write_index(inputs,index);replay.verify(inputs);state['status']=replay.PENDING
    except BaseException as exc:state.update(status='prototype-incomplete: replay pending',failure=str(exc));raise
    finally:
        state['orchestrator_wall_seconds']=time.monotonic()-started;runner.save(root/'protocol.json',state)
        (root/'PROTOCOL_REPORT.md').write_text('# Deviation 6 ARM measurement\n\n'+state['status']+'\n\nNo G3 comparison is made on ARM.\n')
