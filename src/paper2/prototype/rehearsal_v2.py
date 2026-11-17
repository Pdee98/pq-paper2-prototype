"""DIAGNOSTIC v2 collection/replay plumbing; production remains gated."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import time
from . import replay,transport,artifact_integrity as inventory
from . import production,empirical_replay,dispatcher_tables
from .rehearsal_v2_q7 import evaluate
from .deviation9_budget import replay_projection,stage_volume
from src.paper2.model.service_times import STREAM_NAMES,derive_seed

NAMESPACE='paper2-g3-rehearsal-v2'
CELLS={5:('xmss',2),9:('ml_dsa_44',1)}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()


def identities(namespace):
    """Finite named-stream domains; per-job suffixes remain in sealed workloads."""
    result=[]
    for b,k in CELLS.values():
        result.append((namespace+f'-{b}-k{k}-rho0.85-r0',0,'workload/corpus/service/dispatcher'))
    for b in ('xmss','ml_dsa_44'):
        result.append((namespace+'-pilot-'+b,0,'pilot/corpus/occupancy/dispatcher-probe'))
        for k in (1,2):
            for family in ('backlog','traffic'):
                # Existing calibration traffic is replicate 0; each fresh
                # process repetition reuses that workload, as registered.
                result.extend((namespace+f'-calibration-{family}-{b}-k{k}',rep,'calibration/'+family) for rep in range(3))
    return result


def validation_identities():
    result=[]
    for b in ('xmss','ml_dsa_44'):
        result.extend(('paper2-g3-v1',rep,'run7') for rep in range(4))
        for k in (1,2):
            for rho in (.5,.85):
                for rep in range(4):result.append((f'paper2-g3-cycle-{b}-k{k}-rho{rho}-r{rep}',rep,'run7'))
        result.append(('paper2-cycle-backlog-'+b+'1',0,'calibration'))
        for k in (1,2):
            for family in ('backlog','traffic'):result.append((f'paper2-cycle-{family}-{b}{k}',0,'calibration'))
    result.append(('paper2-g3-cycle-secondary-regime',0,'secondary'))
    return result


def seed_ledger(old=None,*,attempt=1,attempt_1_run_id=''):
    if isinstance(attempt,bool) or attempt not in (1,2) or attempt==2 and not attempt_1_run_id:
        raise ValueError('invalid v2 ledger attempt identity')
    old=validation_identities() if old is None else old
    old_seeds={derive_seed(i,s,r) for i,r,_ in old for s in STREAM_NAMES}
    entries=[]
    for identity,rep,purpose in identities(NAMESPACE):
        for stream in STREAM_NAMES:
            seed=derive_seed(identity,stream,rep)
            if seed in old_seeds:raise ValueError('run #7 seed-ledger overlap')
            entries.append(dict(identity=identity,replicate=rep,stream=stream,seed=str(seed),purpose=purpose))
        # Dispatcher hash streams use this exact run identity, a distinct domain
        # tag and per-event suffix; corpus identity is workload identity, not a
        # claim to seed native signing-key setup.
        for stream in ('corpus-identity','dispatcher-cost-identity'):
            entries.append(dict(identity=identity,replicate=rep,stream=stream,
                identity_sha256=digest([identity,rep,stream]),purpose=purpose))
    return dict(namespace=NAMESPACE,schema='paper2-rehearsal-seed-ledger-v1',entries=entries,
        attempt=attempt,attempt_1_run_id=attempt_1_run_id,
        run7_ledger_sha256=digest(sorted(map(str,old_seeds))),overlap_count=0,
        dispatcher_domain=dispatcher_tables.DRAW_VERSION,
        native_key_generation='not seeded; no signing secrets in ledger',
        suffix_contract='per-job identities in sealed workload; dispatcher draw domain separated; fresh-process calibration replicas 0,1,2')


def write_ledger(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    attempt=int(os.environ.get('ATTEMPT','1'));previous=os.environ.get('PREVIOUS_RUN','')
    if attempt==2 or (root/'attempt-authorization').exists():
        from .rehearsal_v2_attempts import load
        authorization=load(root,attempt);previous=authorization['attempt_1_run_id']
    value=seed_ledger(attempt=attempt,attempt_1_run_id=previous);replay.save(root/'SEED_LEDGER.json',value)
    (root/'SEED_LEDGER.sha256').write_text(replay.sha256_file(root/'SEED_LEDGER.json')+'\n')
    return value


def verify_ledger(root):
    root=Path(root)
    if replay.sha256_file(root/'SEED_LEDGER.json')!=(root/'SEED_LEDGER.sha256').read_text().strip():raise ValueError('seed ledger seal mismatch')
    value=replay.read(root/'SEED_LEDGER.json')
    if value!=seed_ledger(attempt=value.get('attempt'),attempt_1_run_id=value.get('attempt_1_run_id','')):raise ValueError('seed ledger identity mismatch')
    if any(not e['identity'].startswith(NAMESPACE+'-') for e in value['entries']):raise ValueError('missing namespace')
    return value


def qualify_projection(proj,rows,groups,root):
    """Fixed planning proxies; exact counts are generated before bulk signing."""
    if {r['cell_id'] for r in rows}!={5,9}:raise ValueError('both rehearsal cells must pass planned guard')
    verify_ledger(root)
    stage=stage_volume(rows,3*1024**3,24.9584584585*112*(2+1/128))
    # Account for preallocated stage mmap plus bounded observation timer storage.
    from .stage_capture import capacity_bound,ROW,HEADER
    from src.paper2.workload import generate_workload
    extents=[]
    for row in rows:
        w=generate_workload(production.parameters(row['cell'],0,NAMESPACE));a=capacity_bound(w)
        extents.append(HEADER.size+a['rows']*ROW.size+8*(4*a['rows']+280*60*1000))
    extra=stage['added_peak_bytes']+max(extents)
    io=dict(proj['transport']);io['peak_runner_bytes']+=extra
    io['disk_threshold_bytes']=math.ceil(1.5*io['peak_runner_bytes'])
    io['compressed_upload_bytes']+=stage['stage_compressed_projection_bytes']
    proj=dict(proj,transport=io,stage_evidence=stage,mmap_and_timer_extent_bytes=extents,
        replay=[dict(cell_id=r['cell_id'],**replay_projection(r['transactions'],('legacy','explicit'))) for r in rows])
    # The plan's report-only 60 min engineering allowance remains a projection,
    # not a new cap or a claim to measured ARM capture speed.
    proj['expected_seconds']+=3600;proj['conservative_seconds']+=3600
    proj['passed']=proj['conservative_seconds']<=proj['gate_seconds']
    return proj


def volume_receipt(prototype,upload,control):
    from .stage_capture import rows,E,ROW,HEADER
    prototype=Path(prototype);control=Path(control)
    kinds={'event':0,'idle':0};sends=0
    for row in rows(prototype):
        kinds['idle' if row[1]==E['idle_interval'] else 'event']+=1
        sends+=row[1]==E['send']
    stage=replay.read(prototype/'stages.json');doc=replay.read(Path(upload)/'TRANSPORT.json')
    raw=sum(f['bytes'] for f in doc['files'])
    encoded=sum(f['bytes'] for f in doc['objects'].values())
    disk=dict(monotonic_ns=time.monotonic_ns(),free_bytes=shutil.disk_usage(control).free)
    trajectory=control/'disk-trajectory.jsonl'
    with trajectory.open('a') as f:f.write(json.dumps(disk)+'\n')
    copies=sum(p.stat().st_size for p in (control/'dispatcher-costs').rglob('*') if p.is_file())
    return dict(namespace=NAMESPACE,report_only=True,physical_sends=sends,rows=kinds,
        rows_per_send={k:v/sends if sends else None for k,v in kinds.items()},
        bytes_per_send={k:v*ROW.size/sends if sends else None for k,v in kinds.items()},
        stage_bytes=stage['bytes'],mmap_extent_bytes=HEADER.size+stage['capacity']*ROW.size,
        timer_capacity_bytes=8*(4*stage['capacity']+280*60*1000),capture_overhead=stage['append_cost'],
        sealed_raw_bytes=raw,encoded_object_bytes=encoded,gzip_ratio=raw/encoded if encoded else None,
        table_copy_bytes=copies,disk=disk,atomic_groups=replay.read(prototype/'atomic-groups.json'))


def fetch_current(destination):
    """Use immutable artifact IDs/digests; source job already completed in this run."""
    from . import remote_authorization as remote
    dest=Path(destination);dest.mkdir(parents=True,exist_ok=False)
    rid=os.environ['GITHUB_RUN_ID'];available=remote.artifacts(rid)
    ctl=remote.download(remote.exact(available,'paper2-g3-control-'+rid),dest/'control-encoded')
    inventory.verify_checksums(ctl);bootstrap=replay.read(ctl/'CONTROL.json')
    known={}
    for item in bootstrap['packets']:
        selected=[a for a in available if str(a['id'])==str(item['id'])]
        if len(selected)!=1 or selected[0]['digest']!=item['digest']:raise ValueError('packet upload receipt mismatch')
        known[str(item['id'])]=remote.download(selected[0],dest/('packet-'+str(item['id'])))
    control=dest/'control';transport.verify(ctl,known,control)
    part=replay.read(control/'PART.json')
    if part['purpose']!=NAMESPACE or part['code_commit']!=os.environ['GITHUB_SHA'] or part['operational_status']!='complete':raise ValueError('v2 source provenance mismatch')
    if {r['cell_id'] for r in part['completed']}!={5,9} or len(part['completed'])!=2:raise ValueError('incomplete v2 cohort')
    if verify_ledger(control)['attempt']!=part['attempt']:raise ValueError('source attempt differs from ledger')
    for row in part['completed']:
        source=known[str(row['artifact']['id'])]
        if replay.sha256_file(source/'TRANSPORT.json')!=row['transport_sha256']:raise ValueError('packet binding mismatch')
        target=dest/row['run_id'];transport.verify(source,known,target)
        if replay.sha256_file(target/'REPLAY_MANIFEST.json')!=row['manifest_sha256']:raise ValueError('raw packet seal mismatch')
        if replay.read(target/'info.json').get('attempt')!=part['attempt']:raise ValueError('packet attempt differs from source')
        if replay.read(target/'config.json')['run_id']!=production.parameters(row['cell'],0,NAMESPACE)['run_id']:
            raise ValueError('workload/service/dispatcher namespace mismatch')
    return part


def matrix(destination):
    part=fetch_current(destination);rows=[]
    for row in part['completed']:
        rows.append(dict(run_id=row['run_id'],cell_id=row['cell_id'],attempt=part['attempt'],
                         timeout_minutes=replay_projection(row['transactions'],('legacy','explicit'))['timeout_minutes']))
    with open(os.environ['GITHUB_OUTPUT'],'a') as f:f.write('matrix='+json.dumps(dict(include=rows),separators=(',',':'))+'\n')
    return rows


def run(destination,run_id,output):
    part=fetch_current(destination);row=next(r for r in part['completed'] if r['run_id']==run_id)
    b,k=CELLS[row['cell_id']];control=Path(destination)/'control'
    inputs={slot:control/'dispatcher-costs'/f'{b}-k{k}'/slot for slot in dispatcher_tables.SLOTS}
    identity=dict(run_id=run_id,cell_id=row['cell_id'],replicate=0,source_run_id=part['source_run_id'],
                  code_commit=part['code_commit'],seed_ledger_sha256=replay.sha256_file(control/'SEED_LEDGER.json'),
                  attempt=part['attempt'],attempt_1_run_id=verify_ledger(control)['attempt_1_run_id'])
    from .production_replay import diagnostic_context,result_capsule
    with diagnostic_context(True):
        value=empirical_replay.execute(Path(destination)/run_id,inputs,output,purpose='rehearsal-v2',identity=identity)
    # Apply Dev8 exactly (the older diagnostic dip-stop reader is never called).
    from .measurement_conditions import apply
    apply(value['prototype'],Path(destination)/run_id,(30,90))
    if row['cell']['dispatcher_utilisation']>.5:value['prototype']['validity']['passed']=False
    value['namespace']=NAMESPACE
    value['reader_source_sha256']=replay.sha256_file(Path(__file__).with_name('rehearsal_v2_q7.py'))
    replay.save(Path(output)/'result.json',value);replay.seal(output,'RESULT_MANIFEST.json')
    result_capsule(output,Path(output).parent/'capsule','paper2-v2-evidence-'+os.environ['GITHUB_RUN_ID']+'-'+run_id)
    transport.pack(output,Path(output).parent/'evidence')
    return value


def gather(results,output):
    from .input_trust import reject
    reject(results);output=Path(output);output.mkdir(parents=True,exist_ok=False)
    records=[];commit=os.environ.get('GITHUB_SHA')
    for path in Path(results).rglob('result.json'):
        replay.verify_files(path.parent,'RESULT_MANIFEST.json');original=path.parent/'ORIGINAL_RESULT_MANIFEST.json'
        if replay.sha256_file(original)!=(path.parent/'ORIGINAL_RESULT_MANIFEST.json.sha256').read_text().strip():raise ValueError('source result seal mismatch')
        seal=replay.read(original);value=replay.read(path)
        entry=next(r for r in seal['files'] if r['path']=='result.json')
        if entry['sha256']!=replay.sha256_file(path):raise ValueError('source result content mismatch')
        provenance=seal['provenance']
        if (value['namespace']!=NAMESPACE or value['code_commit']!=commit or
            provenance['source_code_commit']!=commit or provenance['replay_code_commit']!=commit or not provenance['replay_tree_clean']):raise ValueError('same-commit clean v2 replay required')
        records.append(value);shutil.copytree(path.parent,output/'cells'/value['run_id'])
    attempts={r['attempt'] for r in records}
    if len(attempts)>1 or any(a not in (1,2) for a in attempts):raise ValueError('mixed or invalid v2 attempt identities')
    result=evaluate(records);result['code_commit']=commit
    result['attempt']=next(iter(attempts)) if attempts else int(os.environ.get('ATTEMPT','1'))
    predecessors={r.get('attempt_1_run_id','') for r in records}
    if len(predecessors)>1:raise ValueError('mixed v2 attempt predecessors')
    result['attempt_1_run_id']=next(iter(predecessors)) if predecessors else os.environ.get('PREVIOUS_RUN','')
    result['reader_source_sha256']=replay.sha256_file(Path(__file__).with_name('rehearsal_v2_q7.py'))
    replay.save(output/'result.json',result);replay.seal(output,'RESULT_MANIFEST.json')
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('ledger','matrix','run','gather','disk-monitor','fetch-results'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--run-id')
    a=p.parse_args()
    if a.command=='ledger':write_ledger(a.root)
    elif a.command=='matrix':matrix(a.root)
    elif a.command=='run':run(a.root,a.run_id,a.output)
    elif a.command=='gather':gather(a.root,a.output)
    elif a.command=='fetch-results':
        from . import remote_authorization as remote
        a.root.mkdir(parents=True,exist_ok=False)
        for row in remote.artifacts(os.environ['GITHUB_RUN_ID']):
            if row['name'].startswith('paper2-v2-result-'+os.environ['GITHUB_RUN_ID']+'-'):
                remote.download(row,a.root/str(row['id']))
    else:
        path=a.root/'disk-trajectory-periodic.jsonl';lowest=None
        with path.open('a',buffering=1) as stream:
            while not (a.root.parent/'DISK_MONITOR_STOP').exists() and not (a.root.parent/'WATCHDOG_STOP').exists():
                free=shutil.disk_usage(a.root).free;lowest=free if lowest is None else min(lowest,free)
                stream.write(json.dumps(dict(monotonic_ns=time.monotonic_ns(),free_bytes=free,minimum_free_bytes=lowest))+'\n')
                time.sleep(1)

if __name__=='__main__':main()
