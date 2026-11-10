"""SYNTHETIC validation-path fixtures and strictly timing-only replay tooling."""
import argparse
import copy
import csv
import json
import os
from pathlib import Path
import tempfile
import time
from unittest.mock import patch
from . import corpus,replay,runner,runtime,artifact_integrity
from ..model.engine import _git_state
from .replay_progress import checkout_receipt

SCENARIOS={'pass':'PASS','band_and_invalid':'FAIL','invalid_invariant':'FAIL',
    'one_invalid':'INCONCLUSIVE','two_invalid':'INCONCLUSIVE',
    'replacement_pass':'PASS','replacement_fail':'FAIL','replacement_invalid':'INCONCLUSIVE',
    'replacement_invalid_invariant':'FAIL','secondary_missing':'PASS','secondary_error':'PASS',
    'secondary_disagree':'PASS','secondary_invariant':'FAIL','two_source':'PASS','part_rerun':'PASS'}


def create(output,scenario):
    if scenario not in SCENARIOS:raise ValueError('unknown synthetic scenario')
    # Existing deterministic fake-worker clock; no native signing or real ARM data.
    from tests.paper2.test_phase5a_deviation5 import Clock
    from tests.paper2._support import config
    requested=Path(output).resolve();output=requested
    split=scenario in ('two_source','part_rerun')
    if split:output=requested.with_name(requested.name+'-unsplit')
    output.parent.mkdir(parents=True,exist_ok=True)
    cells=[dict(backend='sleep',k=k,policy=policy,rho_cold=.5,rate=10,period=1,
                dispatcher_utilisation=.1,g3_input_version=6) for k in (1,2) for policy in ('fifo','block_priority')]
    if split:
        base=cells
        cells=[dict(base[i%4],backend=backend,dispatcher_utilisation=.1 if i<4 else .6)
               for backend in ('xmss','ml_dsa_44') for i in range(8)]
    cells.append(dict(cells[0],role='secondary'))
    index=replay.initialize(output,cells,[dict(cell=c,reason=replay.EXCLUSION) for c in cells if c['dispatcher_utilisation']>.5],_git_state()['commit'],os.environ.get('GITHUB_RUN_ID','0'))
    index.update(purpose='SYNTHETIC validation dry-run; excluded from G3',scenario=scenario)
    if scenario.startswith('replacement_'):
        index['followup_cells']=[0]
        index['runs'].append(dict(run_id='cell0-r3',cell_id=0,replicate=3,manifest_sha256=None))
    with tempfile.TemporaryDirectory(prefix='paper2-synthetic-') as td:
        private=Path(td)
        for run in index['runs']:
            i,rep=run['cell_id'],run['replicate'];rid=run['run_id'];cell=cells[i]
            if cell.get('role')=='secondary' and scenario=='secondary_missing':continue
            bad=(i==0 and ((rep==0 and scenario not in ('pass','secondary_missing','secondary_error','secondary_disagree','secondary_invariant','two_source','part_rerun')) or
                          (rep==1 and scenario=='two_invalid') or (rep==3 and scenario in ('replacement_invalid','replacement_invalid_invariant'))))
            cfg=config(q_max=1000,run_id='SYNTHETIC-g3-'+rid,replicate=rep,k=cell['k'],policy=dict(name=cell['policy']),
                admissions=[dict(tx_id=f't{j}',arrival_t=30) for j in range(240)],
                blocks=[dict(block_id='B',tx_ids=[f't{j}' for j in range(240)])],block_start=31,
                cache=dict(capacity=4096,ttl=100),pool=dict(enabled=True,capacity_bytes=1000000),
                g3_input_version=6,calibration_cycle_means=dict.fromkeys(('admission','block_tx','block_sig'),.1 if bad else .001))
            doc=corpus.build(cfg,'sleep');cp=corpus.write(doc,private/(rid+'.json'))
            cfg=dict(doc['workload'],g3_input_version=6,calibration_cycle_means=cfg['calibration_cycle_means'],output_dir=str(private/rid))
            clock=Clock(duration=1000000)
            def memory(pids=()):return dict(parent_pid=os.getpid(),rss_bytes={str(os.getpid()):100*1024**2},available_bytes=8*1024**3,total_bytes=16*1024**3)
            with clock.patches(),patch('src.paper2.prototype.gc_control.memory_snapshot',side_effect=memory):
                e,m=runtime.run(cfg,cp,stop_t=32,sleep_seconds=.001)
            if (scenario=='invalid_invariant' and i==0 and rep==0) or (scenario=='replacement_invalid_invariant' and i==0 and rep==3) or (scenario=='secondary_invariant' and cell.get('role')=='secondary'):
                manifest=replay.read(m);manifest['blocks']['B']['deadline_t']+=1;replay.save(m,manifest)
            fail_band=i==0 and ((scenario=='band_and_invalid' and rep==1) or (scenario=='replacement_fail' and rep==3))
            samples={}
            for role,reps,duration in [('primary',(0,1),.01 if scenario=='secondary_disagree' and cell.get('role')=='secondary' else .003 if fail_band else .001),('held-out',(2,),.001)]:
                sample=private/(rid+'-'+role+'.csv');samples[role]=sample
                with sample.open('w',newline='') as f:
                    w=csv.writer(f);w.writerow(['backend','operation','variant','duration_ns','primitive_ns','job_class','source'])
                    for slot in reps:
                        for cls in ('admission','block_tx','block_sig'):w.writerow(['sleep:'+cls,'verify','valid',round(duration*1e9),round(duration*1e9),cls,f'concurrency-cycle-k{cell["k"]}-rep{slot}'])
            run['manifest_sha256']=replay.create_packet(output/rid,cfg,cp,dict(events=str(e),manifest=str(m)),samples['held-out'],cell,rep,primary=samples['primary'])
    index['status']=replay.PENDING;replay.write_index(output,index);artifact_integrity.write_checksums(output)
    if split:
        from .split_replay import union,copy_file
        parts=[]
        for label,ids,source in [('7X',list(range(8))+[16],'101'),('7M',list(range(8,16)),'102')]:
            part=requested.with_name(requested.name+'-'+label);part.mkdir()
            selected={i:cells[i] for i in ids}
            idx=dict(index,cells=list(selected.values()),cell_ids=ids,source_run_id=source,
                     excluded_cells=[dict(cell=c,reason=replay.EXCLUSION) for c in selected.values() if c['dispatcher_utilisation']>.5],
                     runs=[r for r in index['runs'] if r['cell_id'] in ids],
                     part_receipt=dict(part=label,attempt=2 if scenario=='part_rerun' and label=='7X' else 1,operational_status='complete'))
            if idx['part_receipt']['attempt']==2:
                idx['part_receipt']['previous_attempt_evidence']=dict(source_run_id=source,attempt=1,
                    operational_status='failed',code_commit=index['code_commit'],preserved=True,purpose='SYNTHETIC infrastructure failure')
            for run in idx['runs']:
                for file in (output/run['run_id']).rglob('*'):
                    if file.is_file():copy_file(file,part/file.relative_to(output))
            replay.write_index(part,idx);artifact_integrity.write_checksums(part);parts.append(part)
        return union(*parts,requested,'101','102')
    return index


def exercise(inputs,output,scenario):
    """Use the ordinary validation replay/check/compare/gather code, never diagnostic mode."""
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    index=replay.verify(inputs)
    source=index['source_run_id'];results=output/'cells';results.mkdir()
    matrix=[replay.matrix_entry(inputs,r['run_id']) for r in index['runs'] if r.get('manifest_sha256')]
    replay.save(output/'prepare-matrix.json',dict(include=matrix))
    for item in matrix:
        rid=item['run_id'];directory=results/rid
        result=replay.execute(inputs,rid,directory,source)
        if scenario=='secondary_error' and rid=='secondary-regime':
            result.pop('primary',None);result.pop('held_out',None)
            result['execution_error']='SYNTHETIC secondary operational error'
            replay.save(directory/'result.json',result);replay.seal(directory,'RESULT_MANIFEST.json')
    replay.gather(inputs,results,output/'gather',source)
    receipt=assert_report(output/'gather',scenario)
    replay.save(output/'assertion.json',receipt)
    return receipt


def assert_report(directory,scenario):
    replay.verify_aggregate(directory)
    report=replay.read(Path(directory)/'G3_STATUS.json')
    if report['verdict']!=SCENARIOS[scenario]:raise AssertionError((scenario,report))
    cell=report['aggregates'][0]
    if scenario=='one_invalid' and report['followup_plan']!=[dict(cell_id=0,replicate=3,reason='exactly one initial INVALID')]:raise AssertionError('follow-up plan')
    if scenario in ('two_invalid','replacement_invalid') and report['followup_plan']:raise AssertionError('unauthorised replacement')
    if any(r['replicate'] in (4,5) for r in report['per_repetition']):raise AssertionError('replicate 4/5 scheduled')
    if scenario in ('invalid_invariant','replacement_invalid_invariant'):
        if not any(r.get('status')=='INVALID' and any(f['check']=='prototype invariant' for f in r.get('failures',[])) for r in report['per_repetition']):raise AssertionError('INVALID invariant fixture not exercised')
    if scenario=='band_and_invalid':
        if 'cell0-r0' not in report['invalid_runs'] or not any(f['check'] in replay.BANDS for f in report['failures']):raise AssertionError('FAIL plus INVALID not exercised')
    if scenario.startswith('replacement_'):
        if not any(r['run_id']=='cell0-r3' for r in report['per_repetition']):raise AssertionError('replacement absent')
        if scenario=='replacement_invalid' and (len(cell['invalid_runs'])!=2 or not cell['final']):raise AssertionError('replacement INVALID not final')
    if scenario.startswith('secondary_'):
        secondary=report['secondary_regime'][0]
        if scenario=='secondary_missing' and secondary['category']!='NOT RECORDED':raise AssertionError('secondary not missing')
        if scenario=='secondary_error' and not any(r['check']=='execution' for r in secondary['diagnostic_errors']):raise AssertionError('secondary error absent')
        if scenario=='secondary_disagree' and secondary['category']!='DISAGREE':raise AssertionError('secondary disagreement absent')
        if scenario=='secondary_invariant' and not any(f['check']=='prototype invariant' for f in report['failures']):raise AssertionError('secondary invariant absent')
    if scenario in ('two_source','part_rerun'):
        if report['source_run_ids']!=['101','102'] or len(report['part_receipts'])!=2:raise AssertionError('two-source proof absent')
        if scenario=='part_rerun' and (report['part_receipts'][0]['attempt']!=2 or not report['part_receipts'][0]['previous_attempt_evidence']['preserved']):raise AssertionError('failed attempt evidence absent')
    return dict(purpose='SYNTHETIC only; excluded from G3',scenario=scenario,expected=SCENARIOS[scenario],actual=report['verdict'],passed=True)


def timing(inputs,output):
    from . import diagnostic
    output=Path(output);receipt=dict(purpose='TIMING ONLY; excluded from G3; no metrics or comparisons',source_run_id='42354911778',replay_checkout=checkout_receipt(),runs={})
    try:
        artifact_integrity.verify_checksums(inputs)
        index,packet=diagnostic.verify(inputs,'42354911778','paper2-g3-diag-v5-xmss-k2')
        receipt.update(source_code_commit=index['code_commit'],packet_sha256=next(r['packet_sha256'] for r in index['runs'] if r['run_id']==packet.name),transactions=replay.read(packet/'info.json')['arm_corpus_audit']['signature_ids_checked'])
        with tempfile.TemporaryDirectory(prefix='paper2-timing-only-') as td:
            for name,sample in [('primary','primary.csv'),('held_out','held-out.csv')]:
                start=time.monotonic();e,_=replay.simulate(packet,packet/sample,Path(td)/name);elapsed=time.monotonic()-start
                with e.open(newline='') as f:count=sum(1 for _ in csv.DictReader(f))
                receipt['runs'][name]=dict(wall_seconds=elapsed,event_rows=count)
        receipt['outputs_discarded']=True;receipt['status']='complete'
    except BaseException as exc:receipt.update(status='failed',error_type=type(exc).__name__);raise
    finally:replay.save(output,receipt)
    return receipt


def main():
    parser=argparse.ArgumentParser();parser.add_argument('command',choices=('create','assert','timing','exercise'))
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--inputs',type=Path);parser.add_argument('--scenario',choices=SCENARIOS)
    a=parser.parse_args()
    if a.command=='create':create(a.output,a.scenario)
    elif a.command=='assert':print(json.dumps(assert_report(a.output,a.scenario)))
    elif a.command=='exercise':print(json.dumps(exercise(a.inputs,a.output,a.scenario)))
    else:timing(a.inputs,a.output)

if __name__=='__main__':main()
