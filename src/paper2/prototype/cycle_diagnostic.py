"""One fresh-seed v3 diagnostic; no validation launch or cap changes."""
import os,tempfile,time,math
from pathlib import Path
from . import corpus,replay,runner,public_corpus
from .cycle_calibration import calibrate_backend
from .cycle_protocol import cold_cycle_loads
from src.paper2.model.engine import _git_state
from src.paper2.model.service_times import sha256_file
from src.paper2.workload import generate_workload

def projection():
    from . import diagnostic as d
    rate=.85*1119.5398934554457
    w=generate_workload(d.diagnostic_parameters(rate,128/rate));n=len(w['transactions'])+len(w['blocks'])
    keys=math.ceil(len(w['transactions'])/512)+math.ceil(len(w['blocks'])/512)
    signing=((n/d.RUN6['signing_rate']+keys*d.RUN6['keygen_seconds'])/2+d.RUN6['keygen_seconds'])*1.0753970376335098
    calibration=135.247078+2*2*3*12+120 # both iterations plus synthetic preparation reserve
    estimate=166.303858+3.473617023+calibration+signing+6.052722314+110+25.103262621+60
    return dict(purpose=d.PURPOSE,run_id=d.RUN_ID,paired_with_run=None,provisional_rate=rate,
        basis='Existing v2 idle-calibration cycle proxy; fresh representative calibration determines actual v3 rate',
        transactions=len(w['transactions']),blocks=len(w['blocks']),messages=n,signing_keys=keys,
        presigning_seconds=signing,calibration_planning_seconds=calibration,projected_seconds_to_exit=estimate,
        projected_compact_bytes=len(w['transactions'])*185.1*1.10,projected_uncompressed_corpus_bytes=len(w['transactions'])*351.4*1.10,
        diagnostic_stage_timeouts_seconds=d.TIMEOUTS,job_timeout_minutes=180,
        caveat='PROVISIONAL estimate, not a measurement; conformance/build/upload variation remains unmeasured; unchanged watchdogs, no validation caps')

def collect(root):
    from . import diagnostic as d
    root=Path(root).resolve();d.preflight()
    if root==runner.ROOT or runner.ROOT in root.parents:raise ValueError('diagnostic output must be outside checkout')
    if not (root/'conformance.json').is_file():raise RuntimeError('native conformance required')
    state=dict(purpose=d.PURPOSE,run_id=d.RUN_ID,status='DIAGNOSTIC: collecting',excluded_from_G3=True,
        code_commit=os.environ.get('GITHUB_SHA') or _git_state()['commit'],source_run_id=os.environ.get('GITHUB_RUN_ID','local'),projection=projection())
    runner.save(root/'protocol.json',state)
    try:
        with tempfile.TemporaryDirectory(prefix='paper2-v3-private-') as td:
            private=Path(td);at=time.perf_counter()
            pilot=d.bounded_presign(d.diagnostic_parameters(2560,.05,.1),1,private/'pilot.json','pilot')
            state['pilot_seconds']=time.perf_counter()-at;at=time.perf_counter()
            refs=calibrate_backend('xmss',pilot['path'],root,timeout=d.TIMEOUTS['calibration'])
            state['calibration_seconds']=time.perf_counter()-at
            ref=refs[1];load=next(r for r in cold_cycle_loads(ref) if r['rho_cold']==.85)
            cell=dict(ref,backend='xmss',policy='fifo',rho=.85,**load,B_cold=ref['B_cold_cycle'],B_ref=ref['B_ref_cycle'],g3_input_version=6)
            state.update(cell=cell,guard_holds=cell['dispatcher_utilisation']<=.5);runner.save(root/'protocol.json',state)
            if not state['guard_holds']:raise RuntimeError('DIAGNOSTIC STOP: dispatcher guard exceeded')
            at=time.perf_counter();receipt=d.bounded_presign(d.diagnostic_parameters(cell['rate'],cell['period']),2,private/'full.json','presigning')
            state['presigning_seconds']=time.perf_counter()-at;cp=Path(receipt['path']);doc=replay.read(cp)
            cfg=dict(runner.settings(doc['workload'],cell,root/'prototype'),g3_input_version=6,
                calibration_cycle_means=ref['cycle_means'],diagnostic_instrumentation=True)
            proto=runner.fresh(runner.prototype_run,(cfg,cp,receipt['sha256']),sum(d.TIMEOUTS[s] for s in ('preparation','prototype window','serialisation')),
                progress_path=root/'prototype/progress.jsonl',phase_timeouts=d.TIMEOUTS,partial_dir=root/'timeout-evidence')
            inputs=root/'replay-inputs';packet=inputs/d.RUN_ID
            digest=replay.create_packet(packet,cfg,cp,proto,ref['cycle_samples'],cell,0)
            index=dict(purpose=d.PURPOSE,run_id=d.RUN_ID,code_commit=state['code_commit'],source_run_id=state['source_run_id'],packet_sha256=digest,excluded_from_G3=True)
            replay.save(inputs/'DIAGNOSTIC_INDEX.json',index);(inputs/'DIAGNOSTIC_INDEX.sha256').write_text(sha256_file(inputs/'DIAGNOSTIC_INDEX.json')+'\n')
            state.update(status='DIAGNOSTIC: prototype recorded; analysis pending replay',prototype=proto,arm_corpus_audit=replay.read(packet/'info.json')['arm_corpus_audit'],public_corpus=public_corpus.audit_upload(inputs))
    except BaseException as exc:state.update(status='DIAGNOSTIC: stopped',failure=str(exc));raise
    finally:runner.save(root/'protocol.json',state)
