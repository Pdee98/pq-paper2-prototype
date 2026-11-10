"""Canonical artifact restoration and sealed union of split validation attempts."""
import argparse
from contextlib import contextmanager
import csv
import json
import os
from pathlib import Path
import shutil
from . import replay, production, transport, g3_decision, artifact_integrity
from .replay_budget import timeout_minutes


@contextmanager
def diagnostic_context(enabled):
    token=replay.DIAGNOSTIC_REHEARSAL.set(enabled)
    try: yield
    finally: replay.DIAGNOSTIC_REHEARSAL.reset(token)


def controls(downloads,rehearsal=False):
    from .input_trust import reject
    reject(downloads)
    found=[]
    for p in Path(downloads).rglob('PART.json'):
        artifact_integrity.verify_checksums(p.parent)
        doc=replay.read(p)
        proof=p.parent/'CONTROL_PROOF.json'
        if proof.is_file():
            evidence=replay.read(proof);original=replay.safe_file(downloads,evidence['control_transport'])
            if replay.sha256_file(original/'TRANSPORT.json')!=evidence['transport_sha256'] or replay.sha256_file(p)!=evidence['part_sha256']:
                raise ValueError('derived control metadata provenance mismatch')
            if transport.read_file(original,'PART.json')!=p.read_bytes():raise ValueError('derived PART differs from canonical content')
        if doc.get('operational_status')!='complete': raise ValueError('incomplete operational part')
        if (doc['purpose']==production.REHEARSAL)!=rehearsal: raise ValueError('DIAGNOSTIC/G3 source mixing')
        found.append(doc)
    if not found or len({d['code_commit'] for d in found})!=1: raise ValueError('missing or different bundle commits')
    if rehearsal:
        if len(found)!=1 or {int(i) for i in found[0]['cells']}!={5,9}: raise ValueError('incorrect rehearsal cohort')
    else:
        initial=[d for d in found if d['mode']=='initial']
        if len(initial)!=2 or {d['part'] for d in initial}!={'7X','7M'}: raise ValueError('both completed parts required')
        for d in found:
            selected=[r['cell_id'] for r in d['rows']] if d['mode']=='followup' else None
            production.authorize(d['part'],d['attempt'],d['mode'],d['previous_attempt_evidence'],d['followup_authorization'],selected)
            if d['mode']=='followup' and any(r['replicate']!=3 for r in d['rows']): raise ValueError('replicate 3 only')
    found.sort(key=lambda d:(d['mode']!='initial',d['part']))
    return found


def catalogue(downloads,rehearsal=False):
    parts=controls(downloads,rehearsal)
    originals=[p for p in parts if p['mode']=='initial']
    cells={int(i):c for p in originals for i,c in p['cells'].items()}
    runs=[];known={};docs={}
    for p in parts:
        for row in p['completed']:
            aid=str(row['artifact']['id'])
            candidate=Path(downloads)/('packet-'+aid)
            present=(candidate/'TRANSPORT.json').is_file()
            if present:
                if replay.sha256_file(candidate/'TRANSPORT.json')!=row['transport_sha256']:
                    raise ValueError('canonical packet transport hash mismatch')
                artifact_integrity.verify_checksums(candidate)
                known[aid]=candidate
            docs[row['run_id']]=(p,row,candidate if present else None)
            if p['mode']=='followup':
                original=cells[row['cell_id']]
                if any(row['cell'].get(k)!=original.get(k) for k in ('backend','k','policy','rho_cold','role')):
                    raise ValueError('follow-up changed nominal cell identity')
            runs.append(dict(run_id=row['run_id'],cell_id=row['cell_id'],replicate=row['replicate'],
                             cell=row['cell'],manifest_sha256=row['manifest_sha256'],source_run_id=p['source_run_id']))
    if len({r['run_id'] for r in runs})!=len(runs): raise ValueError('duplicate source repetition')
    index=dict(schema=replay.SCHEMA,code_commit=parts[0]['code_commit'],source_run_id=parts[0]['source_run_id'],
        source_run_ids=[p['source_run_id'] for p in parts],cells=[cells[i] for i in sorted(cells)],cell_ids=sorted(cells),
        runs=runs,excluded_cells=[dict(cell=c,reason=replay.EXCLUSION) for i,c in sorted(cells.items()) if c['dispatcher_utilisation']>.5],
        status=replay.PENDING,followup_cells=[r['cell_id'] for r in runs if r['replicate']==3],
        part_receipts=[{k:p[k] for k in ('part','attempt','mode','operational_status','source_run_id')} for p in parts])
    if rehearsal:index['purpose']='DIAGNOSTIC rehearsal; excluded from G3'
    # Dependency archives may hold only objects needed by the selected packet.
    for candidate in Path(downloads).glob('packet-*'):
        if candidate.is_dir():known[candidate.name.removeprefix('packet-')]=candidate
    return index,docs,known


def restore(downloads,output,run_id,rehearsal=False):
    index,docs,known=catalogue(downloads,rehearsal)
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    replay.write_index(output,index)
    _,row,path=docs[run_id]
    if path is None:raise ValueError('selected canonical packet not downloaded')
    transport.verify(path,known,output/run_id)
    if replay.sha256_file(output/run_id/'REPLAY_MANIFEST.json')!=row['manifest_sha256']:
        raise ValueError('restored packet seal differs')
    replay.verify_files(output/run_id,'REPLAY_MANIFEST.json')
    for path in (output/run_id).rglob('*'):
        if path.is_file():replay.audit_file(path)
    return index


def prepare(downloads,rehearsal=False):
    index,docs,known=catalogue(downloads,rehearsal)
    budget=replay.read(Path(__file__).with_name('replay-budget.json'))
    matrix=[]
    for rid,(_,row,path) in docs.items():
        if path is not None:artifact_integrity.verify_checksums(path)
        n=row['transactions'];seconds=budget['fixed_seconds']+budget['seconds_per_transaction']*n
        matrix.append(dict(run_id=rid,timeout_minutes=timeout_minutes(seconds)))
    with open(os.environ['GITHUB_OUTPUT'],'a') as f:
        f.write('matrix='+json.dumps(dict(include=matrix),separators=(',',':'))+'\n')
        f.write('code_commit='+index['code_commit']+'\n')
    return matrix


def result_capsule(result,output,artifact_name):
    """Small sealed verdict plus hashes binding the complete canonical result.

    Full result bytes are uploaded once as a compressed transport artifact;
    gather embeds the original seal and result JSON, referencing that artifact.
    """
    result=Path(result);output=Path(output)
    manifest=replay.verify_files(result,'RESULT_MANIFEST.json')
    output.mkdir(parents=True,exist_ok=False)
    for name in ('result.json','replay-progress.jsonl','RESULT_MANIFEST.json','RESULT_MANIFEST.json.sha256'):
        shutil.copyfile(result/name,output/('ORIGINAL_'+name if name.startswith('RESULT_MANIFEST') else name))
    rules=result/'REHEARSAL_STOP_RULES.json'
    if rules.is_file():shutil.copyfile(rules,output/rules.name)
    replay.save(output/'EVIDENCE_REFERENCE.json',dict(artifact=artifact_name,
                  original_seal_sha256=replay.sha256_file(result/'RESULT_MANIFEST.json'),original_manifest=manifest))
    replay.seal(output,'RESULT_MANIFEST.json')


def rehearsal_stop_rules(packet,prototype):
    """Existing Deviation 7 diagnostic stop predicates, no new threshold."""
    from .measurement_conditions import from_packet
    packet=Path(packet);conditions=from_packet(packet)
    diagnostic=conditions['cache_bin_diagnostic'];drops=diagnostic['sub_50_seconds']
    dispatcher=conditions['observed_dispatcher_load']['busy_fraction']
    checks=dict(drained=conditions['drain']['passed'],
        calibration_dispatcher_guard=replay.read(packet/'info.json')['cell']['dispatcher_utilisation']<=.5,
        observed_dispatcher_guard=dispatcher<=.5,
        count_aware_cache_memory=prototype.get('validity',{}).get('passed',False),
        no_sub_50_measurement_bin=not drops,prototype_invariants=not prototype.get('violations'))
    return dict(purpose='DIAGNOSTIC rehearsal; excluded from G3',checks=checks,passed=all(checks.values()),
                measurement_dispatcher_busy_fraction=dispatcher,sub_50_seconds=drops,
                one_second_bins=diagnostic['one_second_bins'])


def gather(downloads,results,output,rehearsal=False):
    index,docs,known=catalogue(downloads,rehearsal);records=[];paths=[]
    for path in Path(results).rglob('result.json'):
        replay.verify_files(path.parent,'RESULT_MANIFEST.json')
        original=path.parent/'ORIGINAL_RESULT_MANIFEST.json'
        if replay.sha256_file(original)!=(path.parent/'ORIGINAL_RESULT_MANIFEST.json.sha256').read_text().strip():
            raise ValueError('original result seal mismatch')
        seal=replay.read(original);row=next((r for r in seal['files'] if r['path']=='result.json'),None)
        if row is None or row['sha256']!=replay.sha256_file(path): raise ValueError('result not bound to original seal')
        result=replay.read(path);rid=result['run_id']
        if rid not in docs:raise ValueError('unknown result')
        part,source,_=docs[rid]
        if result.get('seeds')!=source['info']['seeds']:raise ValueError('result seed mismatch')
        if seal['provenance']['source_code_commit']!=index['code_commit'] or seal['provenance']['replay_code_commit']!=index['code_commit'] or not seal['provenance']['replay_tree_clean']:
            raise ValueError('same-commit clean replay receipt required')
        records.append(result);paths.append(path)
    # D1-D3 remains the single evaluator; diagnostic cohort never counts as G3.
    report=g3_decision.gather_records(index,records)
    if rehearsal:
        expected={r['run_id'] for r in index['runs']}
        passed=not index['excluded_cells'] and len(records)==len(expected) and {r['run_id'] for r in records}==expected
        for r in records:
            passed &= bool(r.get('prototype',{}).get('validity',{}).get('passed')) and not r.get('execution_error')
            passed &= all(c in r and not r[c].get('violations') and r[c].get('metrics',{}).get('complete',False) for c in ('prototype','primary','held_out'))
        for path in paths:
            rules=path.parent/'REHEARSAL_STOP_RULES.json'
            original=replay.read(path.parent/'ORIGINAL_RESULT_MANIFEST.json')
            expected=next((r['sha256'] for r in original['files'] if r['path']==rules.name),None)
            if not rules.is_file() or expected!=replay.sha256_file(rules):passed=False
            else:passed &= replay.read(rules)['passed']
        report=dict(purpose='DIAGNOSTIC rehearsal; excluded from G3',passed=bool(passed),
                    next_action='AUTHOR REVIEW' if passed else 'STOP',comparisons=report)
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    for path in paths: shutil.copytree(path.parent,output/'cells'/replay.read(path)['run_id'])
    replay.save(output/'G3_REPORT.json',report)
    replay.save(output/'INPUT_INDEX.json',index)
    replay.seal_aggregate(output,index['code_commit']);replay.verify_aggregate(output)
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('prepare','run','gather'))
    p.add_argument('--downloads',type=Path,required=True);p.add_argument('--output',type=Path)
    p.add_argument('--run-id');p.add_argument('--results',type=Path);p.add_argument('--rehearsal',action='store_true')
    a=p.parse_args()
    with diagnostic_context(a.rehearsal):
        if a.command=='prepare':prepare(a.downloads,a.rehearsal)
        elif a.command=='run':
            restored=a.output.parent/(a.run_id+'-restored')
            restore(a.downloads,restored,a.run_id,a.rehearsal)
            result=replay.execute(restored,a.run_id,a.output)
            if a.rehearsal:
                replay.save(a.output/'REHEARSAL_STOP_RULES.json',rehearsal_stop_rules(restored/a.run_id,result.get('prototype',{})))
                replay.seal(a.output,'RESULT_MANIFEST.json')
            result_capsule(a.output,a.output.parent/'capsule','paper2-g3-evidence-'+os.environ['GITHUB_RUN_ID']+'-'+a.run_id)
            transport.pack(a.output,a.output.parent/'evidence')
        else:gather(a.downloads,a.results,a.output,a.rehearsal)


if __name__=='__main__':main()
