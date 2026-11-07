"""Three-cell GC-controlled diagnostic. Never dispatches validation or sets caps."""
import math
import os
from pathlib import Path
import tempfile
import time

from . import corpus, public_corpus, replay, runner
from .cycle_calibration import calibrate_backend
from .cycle_protocol import cold_cycle_loads, cycle_cells, volume_projection
from src.paper2.model.engine import _git_state
from src.paper2.model.service_times import sha256_file
from src.paper2.workload import generate_workload

RUN_ID='paper2-g3-diag-v4'
BACKENDS=('xmss','ml_dsa_44')
CASES=(('xmss',1),('xmss',2),('ml_dsa_44',1))
TIMEOUTS={'pilot':600,'calibration':1800,'presigning':900,'preparation':900,
          'prototype window':110,'serialisation':1200}


def parameters(rate, period, horizon=90, run_id=RUN_ID):
    return dict(runner.parameters(rate,0,period,horizon),run_id=run_id)


def message_counts(p):
    """Count the unchanged generator's arrival stream without building wire metadata."""
    from src.paper2.workload.generator import arrival_times
    from src.paper2.model.service_times import WorkloadStream, derive_seed
    if p['arrivals_invalid']['rate']!=0:raise ValueError('valid-only diagnostic planning required')
    stream=WorkloadStream(derive_seed(p['run_id'],'arrivals',p['replicate']))
    return sum(1 for _ in arrival_times(p['arrivals_valid'],p['horizon'],stream)),math.floor(p['horizon']/p['block_period'])


def projection():
    # Historical diagnostic means are planning inputs only. GC-controlled ARM
    # calibration is deliberately not predicted by subtracting observed pauses.
    from .diagnostic import RUN6
    old_rates={('xmss',1):705.9451539483958,('xmss',2):1299.396289654,
               ('ml_dsa_44',1):.85/(2*.000192+.000192/128)}
    runs=[]
    for backend,k in CASES:
        rate=old_rates[backend,k];nt,nb=message_counts(parameters(rate,128/rate));n=nt+nb
        keys=math.ceil(nt/512)+math.ceil(nb/512)
        signing_rate=RUN6['signing_rate'] if backend=='xmss' else 1689.9791979798963
        keygen=RUN6['keygen_seconds'] if backend=='xmss' else .0023188265
        sign=((n/signing_rate+keys*keygen)/2+keygen)*1.0753970376335098
        runs.append(dict(backend=backend,k=k,provisional_rate=rate,messages=n,signing_keys=keys,
                         presigning_seconds=sign,preparation_reserve_seconds=30,
                         prototype_window_seconds=110,serialisation_reserve_seconds=60))
    calibration=2*514.385040*1.5
    reserves=dict(native_build=165.189647*1.25,conformance=300,pilots=60,self_tests=60,packet_hash_upload=300)
    estimate=sum(reserves.values())+calibration+sum(r['presigning_seconds']+200 for r in runs)
    return dict(purpose='DIAGNOSTIC v4; excluded from G3',run_id=RUN_ID,runs=runs,
                calibration_planning_seconds=calibration,planning_reserves_seconds=reserves,projected_seconds=estimate,
                stage_timeouts_seconds=TIMEOUTS,command_watchdog_minutes=165,job_timeout_minutes=180,
                basis='v3 XMSS cold rates; ML-DSA UNVERIFIED 192 us proxy; run #6 signing rates; '
                      'two v3 calibration totals with 50% margin for GC changes/instrumentation; '
                      'v3 native build with 25% margin; explicit UNVERIFIED conformance/pilot/self-test/upload reserves; '
                      '30/60 s per-run prep/serialisation planning reserves',
                caveat='Planning only, not new measurements. Fresh v4 calibration determines actual rates; '
                       'individual stage maxima are not additive guarantees within the enclosing watchdog. '
                       'No validation preparation/serialisation caps are set.')


def presign(workload,backend,processes,destination):
    doc=corpus.build(generate_workload(workload),backend,processes=processes,primitive_checks=True)
    cp=corpus.write(doc,destination)
    return dict(path=str(cp),sha256=sha256_file(cp),transactions=len(doc['transactions']))


def collect(root, *, run_id=RUN_ID, planning_projection=None):
    from . import diagnostic as d
    d.preflight();root=Path(root).resolve()
    if root==runner.ROOT or runner.ROOT in root.parents:raise ValueError('diagnostic output must be outside checkout')
    if not (root/'conformance.json').is_file():raise RuntimeError('native conformance required')
    host=replay.read(root/'host.json')
    if 'memory' not in host:raise RuntimeError('host total/available memory receipt required')
    purpose='DIAGNOSTIC '+run_id.rsplit('-',1)[-1]
    state=dict(purpose=purpose,run_id=run_id,status='DIAGNOSTIC: collecting',excluded_from_G3=True,
               code_commit=os.environ.get('GITHUB_SHA') or _git_state()['commit'],
               source_run_id=os.environ.get('GITHUB_RUN_ID','local'),projection=projection() if planning_projection is None else planning_projection,
               host_total_memory_bytes=host['memory']['total_bytes'],runs=[],skipped_cells=[])
    runner.save(root/'protocol.json',state);refs={};sizes={};started=time.perf_counter()
    inputs=root/'replay-inputs';inputs.mkdir()
    index=dict(purpose=purpose,run_id=run_id,code_commit=state['code_commit'],
               source_run_id=state['source_run_id'],runs=[],skipped_cells=[],status='DIAGNOSTIC: collecting')
    def index_save():
        replay.save(inputs/'DIAGNOSTIC_INDEX.json',index)
        (inputs/'DIAGNOSTIC_INDEX.sha256').write_bytes((sha256_file(inputs/'DIAGNOSTIC_INDEX.json')+'\n').encode())
    index_save()
    try:
        with tempfile.TemporaryDirectory(prefix=run_id+'-private-') as td:
            private=Path(td)
            for backend in BACKENDS:
                at=time.perf_counter()
                pilot=runner.fresh(presign,(parameters(2560,.05,.1,run_id),backend,1,private/(backend+'-pilot.json')),TIMEOUTS['pilot'])
                state.setdefault('pilot_seconds',{})[backend]=time.perf_counter()-at;at=time.perf_counter()
                refs[backend]=calibrate_backend(backend,pilot['path'],root,timeout=TIMEOUTS['calibration'],
                                               diagnostic=True,seed_tag='-'+run_id)
                state.setdefault('calibration_seconds',{})[backend]=time.perf_counter()-at
                archive=public_corpus.write_archive(replay.read(pilot['path']),private/(backend+'-size.zip'),full_path=pilot['path'])
                sizes[backend]={f+'_per_tx':archive[f]/pilot['transactions'] for f in ('compressed_bytes','uncompressed_bytes')}
                state['compact_sizing']=sizes;runner.save(root/'protocol.json',state)
            planned=cycle_cells(refs);projected=volume_projection(planned,sizes)
            state['full_run_corpus_projection']=projected
            runner.save(root/'projection-compact-corpus.json',projected)
            state['planned_cells']=planned;runner.save(root/'protocol.json',state)
            if not projected['passed']:raise RuntimeError('STOP: projected compact corpus exceeds 2 GB')
            for backend,k in CASES:
                ref=refs[backend][k];load=next(v for v in cold_cycle_loads(ref) if v['rho_cold']==.85)
                cell=dict(ref,backend=backend,policy='fifo',rho=.85,**load,
                          B_cold=ref['B_cold_cycle'],B_ref=ref['B_ref_cycle'],g3_input_version=6)
                rid=f'{run_id}-{backend}-k{k}'
                if cell['dispatcher_utilisation']>.5:
                    row=dict(run_id=rid,cell=cell,reason=replay.EXCLUSION)
                    state['skipped_cells'].append(row);index['skipped_cells'].append(row);index_save();continue
                at=time.perf_counter()
                receipt=runner.fresh(presign,(parameters(cell['rate'],cell['period'],run_id=run_id),backend,2,private/(rid+'.json')),TIMEOUTS['presigning'])
                signing=time.perf_counter()-at;cp=Path(receipt['path']);doc=replay.read(cp)
                config=dict(runner.settings(doc['workload'],cell,root/'prototypes'/rid),g3_input_version=6,
                            calibration_cycle_means=ref['cycle_means'],diagnostic_instrumentation=True)
                proto=runner.fresh(runner.prototype_run,(config,cp,receipt['sha256']),
                    sum(TIMEOUTS[s] for s in ('preparation','prototype window','serialisation')),
                    progress_path=Path(config['output_dir'])/'progress.jsonl',phase_timeouts=TIMEOUTS,
                    partial_dir=root/'timeout-evidence'/rid)
                packet=inputs/rid
                digest=replay.create_packet(packet,config,cp,proto,ref['held_out_cycle_samples'],cell,0,
                                            primary=ref['primary_cycle_samples'])
                index['runs'].append(dict(run_id=rid,packet_sha256=digest,cell=cell))
                state['runs'].append(dict(run_id=rid,cell=cell,presigning_seconds=signing,prototype=proto,
                                          arm_corpus_audit=replay.read(packet/'info.json')['arm_corpus_audit']))
                state['public_corpus']=public_corpus.audit_upload(inputs);index_save();runner.save(root/'protocol.json',state)
            state['status']='DIAGNOSTIC: prototypes recorded; cell stop rules pending replay'
            index['status']=state['status'];index_save()
    except BaseException as exc:
        state.update(status='DIAGNOSTIC: stopped',failure=str(exc));raise
    finally:
        state['elapsed_seconds']=time.perf_counter()-started;runner.save(root/'protocol.json',state)
