"""Split validation mechanics, rehearsed behind an unconditional production gate.

Calibration, measurements and samples always originate on this job's host.
Only the explicitly DIAGNOSTIC rehearsal is executable in this bundle.
"""
import argparse
import json
import math
import os
from pathlib import Path
import shutil
import time
from . import runner, replay, corpus, public_corpus, transport, validation_caps
from .cycle_runner import group_parameters, secondary_cell
from .cycle_protocol import cycle_cells, corpus_group
from .cycle_calibration import calibrate_backend
from .artifact_integrity import write_checksums
from src.paper2.workload import generate_workload
from src.paper2.model.engine import _git_state
from .work_budget import require as require_budget

REHEARSAL = 'paper2-g3-rehearsal-v1'
PRODUCTION_ENABLED = False
PARTS = {'7X': 'xmss', '7M': 'ml_dsa_44'}


def authorize(part, attempt, mode='initial', previous=None, aggregate=None, selected=None):
    """Authorization is checked again at prepare, not inferred from UI choices."""
    if part not in PARTS or attempt not in (1, 2): raise ValueError('invalid part or operational attempt')
    if mode not in ('initial', 'followup'): raise ValueError('invalid execution mode')
    if attempt == 2:
        if not previous or any(previous.get(k) != v for k, v in
                (('part', part), ('attempt', 1), ('mode',mode), ('operational_status', 'failed'), ('preserved', True))):
            raise ValueError('operational re-run requires preserved failed first attempt')
    elif previous is not None: raise ValueError('first attempt cannot replace another attempt')
    if previous and mode=='followup' and set(previous.get('selected_cells',[]))!=set(selected or []):
        raise ValueError('operational re-run cannot change requested follow-up cells')
    if mode == 'initial':
        if selected or aggregate: raise ValueError('initial execution cannot select cells')
        return None
    if not aggregate:
        raise ValueError('follow-up requires sealed aggregate')
    allowed = {a['cell_id'] for a in aggregate['aggregates'] if a['verdict'] == 'INCONCLUSIVE'
               and a['followup_eligible'] and a['initial_invalid_count'] == 1}
    requested = set(selected or [])
    if not requested or requested - allowed: raise ValueError('D1 follow-up cell not eligible')
    if any((i < 8) != (part == '7X') or i == 16 for i in requested):
        raise ValueError('follow-up cells must belong to selected part')
    return sorted(requested)


def parameters(cell, rep, purpose):
    p = group_parameters(cell, rep)
    # Validation identities remain exactly the established group_parameters.
    # Rehearsal has an explicitly separate seed namespace and never counts as G3.
    if purpose == REHEARSAL:
        p['run_id'] = REHEARSAL+'-'+corpus_group(cell, rep)
    return p


def plan(refs, part, purpose='validation', selected=None):
    all_cells = cycle_cells({b:refs[b] for b in ('xmss','ml_dsa_44')})
    cells = {i:c for i,c in enumerate(all_cells)}
    if purpose == REHEARSAL:
        cells = {i:cells[i] for i in (5, 9)}
    else:
        cells = {i:c for i,c in cells.items() if c['backend'] == PARTS[part]}
        if part == '7X': cells[16] = secondary_cell(refs['xmss'][1])
    rows, groups = [], {}
    for i,c in cells.items():
        if c['dispatcher_utilisation'] > .5:
            if c.get('role') == 'secondary' or selected and i in selected:
                raise RuntimeError('required secondary/follow-up cell fails dispatcher guard')
            continue
        if selected is not None and i not in selected: continue
        reps = [3] if selected is not None else [0] if purpose == REHEARSAL or c.get('role') == 'secondary' else range(3)
        for rep in reps:
            name = 'secondary-regime' if c.get('role') == 'secondary' else corpus_group(c,rep)
            if name not in groups:
                w = generate_workload(parameters(c,rep,purpose))
                groups[name] = dict(cell=c,replicate=rep,transactions=len(w['transactions']),
                                    messages=len(w['transactions'])+len(w['blocks']))
            rid = 'secondary-regime' if c.get('role') == 'secondary' else f'cell{i}-r{rep}'
            rows.append(dict(run_id=rid,cell_id=i,replicate=rep,group=name,cell=c,
                             transactions=groups[name]['transactions']))
    # Run both policies against one signed group before releasing its full corpus.
    rows.sort(key=lambda r:(r['group'],r['cell_id']))
    return cells,rows,groups


def projection(rows,groups,backends):
    from .transport_budget import project
    signing = {b:validation_caps.presigning(b,sum(g['messages'] for g in groups.values() if g['cell']['backend']==b)) for b in backends}
    caps = [validation_caps.for_transactions(r['transactions']) for r in rows]
    io = project(rows,groups,backends)
    cal_expected = {'xmss':573.606470739*1.1,'ml_dsa_44':931.585159858*1.1}
    common = 212.82298767625+300+60+60+600  # disclosed v5/native and UNVERIFIED reserves
    expected = common+sum(cal_expected[b]+signing[b]['projected_seconds'] for b in backends)
    expected += sum(110+(70.7+208.4)*r['transactions']/1e6 for r in rows)
    conservative = common+sum(validation_caps.CALIBRATION[b]+signing[b]['cap_seconds'] for b in backends)+sum(sum(c.values()) for c in caps)
    return dict(signing=signing,transport=io,expected_seconds=expected,conservative_seconds=conservative,
                gate_seconds=238*60,passed=conservative<=238*60,
                reserves='600 s hashing/upload, 300 s conformance, 60 s pilots, 60 s self-tests: UNVERIFIED; native v5 x1.25')


def prepare(root,part,attempt=1,purpose='validation',mode='initial',previous=None,aggregate=None,selected=None):
    root = Path(root).resolve()
    if purpose != REHEARSAL and not PRODUCTION_ENABLED: raise RuntimeError(validation_caps.BLOCK_MESSAGE)
    if purpose == REHEARSAL:
        if attempt!=1 or mode!='initial' or previous or aggregate or selected: raise ValueError('rehearsal is a single diagnostic attempt')
        backends=['xmss','ml_dsa_44']
    else:
        authorize(part,attempt,mode,previous,aggregate,selected);backends=[PARTS[part]]
    if root==runner.ROOT or runner.ROOT in root.parents: raise ValueError('output must be outside checkout')
    if runner.platform.machine().lower() not in ('arm64','aarch64') or len(os.sched_getaffinity(0))<4:
        raise RuntimeError('four-vCPU ARM runner required')
    if not (root/'conformance.json').is_file(): raise ValueError('native conformance receipt required')
    code = os.environ.get('GITHUB_SHA') or _git_state()['commit']
    if previous and previous.get('code_commit')!=code: raise ValueError('attempt code commit differs')
    if aggregate and aggregate.get('code_commit')!=code: raise ValueError('follow-up code commit differs')
    private=root.parent/'private';private.mkdir(exist_ok=True)
    refs={};cal_times={};pilot_seconds=0.
    for b in backends:
        pilot_parameters=runner.parameters(2560,0,.05,horizon=.1)
        if purpose==REHEARSAL:pilot_parameters['run_id']=REHEARSAL+'-pilot-'+b
        cp=private/(b+'-pilot.json');pilot_start=time.perf_counter()
        cap=runner.STAGE_CAPS['pilot']-pilot_seconds
        require_budget(root,cap)
        runner.fresh(build_pilot,(pilot_parameters,b,cp),cap)
        pilot_seconds+=time.perf_counter()-pilot_start
        replay.save(root/'pilot-times.json',dict(seconds=pilot_seconds,cap_seconds=runner.STAGE_CAPS['pilot']))
        if pilot_seconds>runner.STAGE_CAPS['pilot']:raise TimeoutError('unchanged pilot stage cap exceeded')
        at=time.perf_counter()
        # Per-backend caps replace the historical shared account() cap.
        require_budget(root,validation_caps.CALIBRATION[b])
        fresh=calibrate_backend(b,cp,root,None,validation_caps.CALIBRATION[b],False,REHEARSAL if purpose==REHEARSAL else '')
        refs[b]={int(k):v for k,v in fresh.items()};cal_times[b]=time.perf_counter()-at
        if cal_times[b]>validation_caps.CALIBRATION[b]: raise TimeoutError('per-backend calibration cap')
    # cycle_cells requires both backend keys; irrelevant backend is a placeholder
    # only for assigning unchanged global IDs, never used as a calibration.
    filled=dict(refs)
    if len(filled)==1:
        other=next(b for b in PARTS.values() if b not in filled)
        filled[other]=next(iter(refs.values()))
    cells,rows,groups=plan(filled,part,purpose,selected)
    proj=projection(rows,groups,backends);replay.save(root/'projection.json',proj)
    if not proj['passed']: raise RuntimeError('conservative projection exceeds 238 minutes; no reduction permitted')
    disk=transport.disk_guard(root,proj['transport']['peak_runner_bytes'])
    replay.save(root/'disk-pre-presigning.json',disk)
    state=dict(purpose=purpose,run_id=REHEARSAL if purpose==REHEARSAL else 'paper2-g3-v1',part=part,attempt=attempt,mode=mode,previous_attempt_evidence=previous,
               code_commit=code,source_run_id=os.environ.get('GITHUB_RUN_ID','local'),cells=cells,rows=rows,groups=groups,
               projection=proj,refs=refs,calibration_seconds=cal_times,signing_seconds={},completed=[],known_objects={},
               uploads=[],operational_status='collecting',followup_authorization=aggregate)
    save_state(root,state)
    return state


def save_state(root,state):
    replay.save(Path(root)/'production-state.json',state)
    replay.save(Path(root)/'protocol.json',state)


def load(root): return replay.read(Path(root)/'production-state.json')


def run_slot(root,slot):
    root=Path(root);state=load(root);rows=state['rows']
    if slot>=len(rows): return False
    row=rows[slot]
    if slot!=len(state['completed']): raise ValueError('each prior sealed packet must be acknowledged first')
    b=row['cell']['backend'];private=root.parent/'private';cp=private/(row['group']+'.json')
    if not cp.exists():
        # Disk is rechecked before each group's bulk signing, not just before the first.
        transport.disk_guard(root,state['projection']['transport']['peak_runner_bytes'])
        left=state['projection']['signing'][b]['cap_seconds']-state['signing_seconds'].get(b,0)
        at=time.perf_counter()
        # Top-level callable is required by Windows spawn and fresh-process watchdogs.
        require_budget(root,left)
        runner.fresh(build_group,(parameters(row['cell'],row['replicate'],state['purpose']),b,cp),left)
        state['signing_seconds'][b]=state['signing_seconds'].get(b,0)+time.perf_counter()-at
        if state['signing_seconds'][b]>state['projection']['signing'][b]['cap_seconds']: raise TimeoutError('presigning cap exceeded')
    doc=replay.read(cp)
    if len(doc['transactions'])!=row['transactions'] or doc['backend']!=b:
        raise ValueError('audited group identity/count differs from exact planned count')
    rid=row['run_id'];base=root.parent/'working'/rid
    cfg=dict(runner.settings(doc['workload'],row['cell'],base/'prototype'),g3_input_version=6,
             calibration_cycle_means=row['cell']['cycle_means'],diagnostic_instrumentation=False)
    caps=validation_caps.for_transactions(len(doc['transactions']))
    require_budget(root,sum(caps.values()))
    proto=runner.fresh(runner.prototype_run,(cfg,cp,replay.sha256_file(cp)),sum(caps.values()),
          progress_path=base/'prototype/progress.jsonl',phase_timeouts=caps,partial_dir=root/'timeouts'/rid)
    packet=root.parent/'packet'/rid;ref=state['refs'][b][str(row['cell']['k'])]
    seal=replay.create_packet(packet,cfg,cp,proto,ref['held_out_cycle_samples'],row['cell'],row['replicate'],primary=ref['primary_cycle_samples'])
    public_corpus.audit_upload(packet)
    info=replay.read(packet/'info.json')
    state.setdefault('compact_groups',{})[row['group']]=info['public_corpus']
    for field in ('compressed_bytes','uncompressed_bytes'):
        if sum(r[field] for r in state['compact_groups'].values())>2_000_000_000:
            raise RuntimeError('STOP: cumulative compact corpus exceeds 2 GB')
    upload=root.parent/'upload'/str(slot)
    transport.pack(packet,upload,state['known_objects'])
    state['pending']=dict(slot=slot,row=row,manifest_sha256=seal,packet=str(packet),upload=str(upload),base=str(base),
                          arm_audit=replay.read(packet/'info.json')['arm_corpus_audit'],info=replay.read(packet/'info.json'),phase_seconds=proto['phase_seconds'],drain_complete=proto['drain_complete'])
    state.setdefault('arm_corpus_audits',{})[rid]=state['pending']['arm_audit']
    save_state(root,state)
    return True


def build_pilot(parameters,backend,path):
    doc=corpus.build(generate_workload(parameters),backend,primitive_checks=True)
    corpus.write(doc,path)
    return dict(sha256=replay.sha256_file(path))


def build_group(parameters,backend,path):
    doc=corpus.build(generate_workload(parameters),backend,processes=2,primitive_checks=True)
    corpus.write(doc,path)
    return dict(sha256=replay.sha256_file(path),messages=len(doc['transactions'])+len(doc['blocks']))


def acknowledge(root,downloaded,artifact):
    root=Path(root);state=load(root);p=state['pending']
    known_roots={str(u['artifact']['id']):Path(u['downloaded']) for u in state['uploads']}
    # Keep verified canonical objects locally for subsequent acknowledgements;
    # they are uploaded exactly once and referenced by immutable artifact id.
    receipt=transport.acknowledge(p['packet'],p['upload'],downloaded,artifact,known_roots)
    doc=replay.read(Path(downloaded)/'TRANSPORT.json')
    for key,d in doc['objects'].items():
        if d['artifact'] is None: state['known_objects'][key]=str(artifact['id'])
    state['uploads'].append(dict(artifact=artifact,downloaded=str(downloaded),receipt=receipt))
    state['completed'].append(dict(p['row'],manifest_sha256=p['manifest_sha256'],transport_sha256=receipt['transport_sha256'],
                                   artifact=artifact,arm_corpus_audit=p['arm_audit'],info=p['info'],phase_seconds=p['phase_seconds'],drain_complete=p['drain_complete']))
    # Original measurement files duplicate packet bytes; verify their content
    # hash is present among reconstructed entries before removing each copy.
    raw_hashes={r['sha256'] for r in doc['files']}
    for file in Path(p['base']).rglob('*'):
        if file.is_file():
            if replay.sha256_file(file) not in raw_hashes: raise ValueError('measurement evidence absent from packet; retained on disk')
            file.unlink()
    state.pop('pending');save_state(root,state)
    group=p['row']['group']
    if not any(r['group']==group for r in state['rows'][len(state['completed']):]):
        cp=root.parent/'private'/(group+'.json')
        cp.unlink()
    # Upload staging is an identical local copy of verified download; retain
    # canonical download, remove only explicitly inventory-covered staging files.
    for file in (Path(p['upload'])).rglob('*'):
        if file.is_file(): file.unlink()
    return receipt


def finalize(root):
    root=Path(root);state=load(root)
    if len(state['completed'])!=len(state['rows']) or state.get('pending'): raise ValueError('operationally incomplete part')
    if runner.remaining(root)<=0: raise TimeoutError('unchanged 280-minute work budget exceeded')
    state['operational_status']='complete';state['status']=replay.PENDING
    save_state(root,state)
    replay.save(root/'PART.json',dict(schema='paper2-part-transport-v1',**state))
    # Local paths are working hints, not canonical transport. Raw/private files
    # are outside this upload root. Canonical payload is only in per-run artifacts.
    write_checksums(root)
    return state


def seal_control(root):
    root=Path(root)
    state=load(root) if (root/'production-state.json').is_file() else {}
    destination=root.parent/'control-upload'
    transport.pack(root,destination,state.get('known_objects',{}))
    failure=replay.read(root/'OPERATIONAL_FAILURE.json') if (root/'OPERATIONAL_FAILURE.json').is_file() else None
    replay.save(destination/'CONTROL.json',dict(schema='paper2-control-reference-v1',
        source_run_id=os.environ.get('GITHUB_RUN_ID'),code_commit=os.environ.get('GITHUB_SHA'),
        packets=[u['artifact'] for u in state.get('uploads',[])],failure=failure,
        part_sha256=replay.sha256_file(root/'PART.json') if (root/'PART.json').is_file() else None))
    write_checksums(destination)
    return destination


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('prepare','run','ack','finalize','record-disk','failed','seal-control','budget'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--part',choices=tuple(PARTS),default='7X')
    p.add_argument('--attempt',type=int,default=1);p.add_argument('--purpose',default='validation')
    p.add_argument('--mode',choices=('initial','followup'),default='initial');p.add_argument('--previous',type=Path)
    p.add_argument('--aggregate',type=Path);p.add_argument('--cells',default='');p.add_argument('--slot',type=int)
    p.add_argument('--downloaded',type=Path);p.add_argument('--artifact-id');p.add_argument('--artifact-digest');p.add_argument('--uploaded-zip',type=Path)
    a=p.parse_args()
    if a.command=='prepare':
        aggregate=None
        if a.aggregate:
            replay.verify_aggregate(a.aggregate);aggregate=replay.read(a.aggregate/'G3_REPORT.json')
        previous=replay.read(a.previous) if a.previous else None
        if a.previous:
            from .input_trust import reject
            reject(a.previous.parent)
        prepare(a.root,a.part,a.attempt,a.purpose,a.mode,previous,aggregate,[int(i) for i in a.cells.split(',') if i] or None)
    elif a.command=='run':
        exists=run_slot(a.root,a.slot)
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('present='+str(exists).lower()+'\n')
    elif a.command=='ack':
        transport.verify_uploaded_zip(a.uploaded_zip,a.artifact_digest)
        acknowledge(a.root,a.downloaded,dict(id=a.artifact_id,digest=a.artifact_digest))
        a.uploaded_zip.unlink()
    elif a.command=='record-disk':
        a.root.mkdir(parents=True,exist_ok=True)
        replay.save(a.root/'disk-start.json',dict(free_bytes=shutil.disk_usage(a.root).free,monotonic_ns=time.monotonic_ns()))
    elif a.command=='budget':
        remaining=runner.remaining(a.root);print(json.dumps(dict(phase='bulk transport complete',remaining_seconds=remaining,work_limit_seconds=280*60)),flush=True)
        if remaining<=0:raise SystemExit('unchanged 280-minute budget exceeded; operationally failed part')
    elif a.command=='seal-control':seal_control(a.root)
    elif a.command=='failed':
        a.root.mkdir(parents=True,exist_ok=True)
        if (a.root/'production-state.json').is_file():
            state=load(a.root)
            pending=state.get('pending')
            if pending and Path(pending['packet']).is_dir():
                transport.pack(Path(pending['packet']),a.root/'partial-sealed-packet')
        replay.save(a.root/'OPERATIONAL_FAILURE.json',dict(part=a.part,attempt=a.attempt,mode=a.mode,selected_cells=[int(i) for i in a.cells.split(',') if i],operational_status='failed',preserved=True,code_commit=os.environ['GITHUB_SHA'],source_run_id=os.environ['GITHUB_RUN_ID']))
        write_checksums(a.root)
    else:finalize(a.root)


if __name__=='__main__':main()
