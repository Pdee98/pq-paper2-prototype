"""Read-only GitHub evidence acquisition by immutable workflow/artifact IDs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from . import replay, transport, production, artifact_integrity


def api(path,output=None):
    if output is None:
        return json.loads(subprocess.run(['gh','api',path],check=True,capture_output=True).stdout)
    with Path(output).open('xb') as stream:
        subprocess.run(['gh','api',path],check=True,stdout=stream)


def run_info(run_id):
    if not re.fullmatch(r'[0-9]+',str(run_id)): raise ValueError('numeric source run ID required')
    repo=os.environ['GITHUB_REPOSITORY']
    value=api(f'repos/{repo}/actions/runs/{run_id}')
    if str(value['id'])!=str(run_id) or value['repository']['full_name']!=repo:
        raise ValueError('source run repository/identity mismatch')
    return value


def artifacts(run_id):
    repo=os.environ['GITHUB_REPOSITORY'];found=[];page=1
    while True:
        rows=api(f'repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}')['artifacts']
        found.extend(rows)
        if len(rows)<100:return found
        page+=1


def download(row,destination):
    from .input_trust import reject
    reject(destination,row.get('name',''))
    destination=Path(destination)
    if destination.exists(): raise FileExistsError('artifact acquisition directory must be new')
    destination.mkdir(parents=True)
    if row.get('expired') or not row.get('digest'):raise ValueError('expired/unsealed remote artifact')
    with tempfile.TemporaryDirectory(prefix='paper2-download-',dir=destination.parent) as td:
        archive=Path(td)/'artifact.zip'
        api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/{row['id']}/zip",archive)
        transport.verify_uploaded_zip(archive,row['digest'])
        with zipfile.ZipFile(archive) as z:
            seen=set()
            for info in z.infolist():
                if info.is_dir():continue
                if info.filename in seen:raise ValueError('duplicate ZIP member')
                seen.add(info.filename)
                if (info.external_attr>>16)&0o170000==0o120000:raise ValueError('ZIP symlink rejected')
                path=replay.safe_file(destination,info.filename);path.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as source,path.open('xb') as target:
                    import shutil
                    shutil.copyfileobj(source,target,1024*1024)
    reject(destination)
    return destination


def exact(rows,name):
    found=[r for r in rows if r['name']==name]
    if len(found)!=1:raise ValueError('missing/ambiguous remote artifact: '+name)
    return found[0]


def authorize(root,part,attempt,mode,previous_run,aggregate_run,cells):
    root=Path(root)/'authorization';root.mkdir(parents=True,exist_ok=False)
    current=run_info(os.environ['GITHUB_RUN_ID'])
    if current.get('run_attempt',1)!=1:
        raise ValueError('use the explicit operational attempt input, not GitHub re-run jobs')
    # Server-side run names bind the explicitly selected part/mode/attempt.
    # A workflow concurrency group serializes this check for a part/cohort.
    marker=f'Paper2 G3 {part}/{mode}/attempt-{attempt} '
    if not current['display_title'].startswith(marker):raise ValueError('unexpected execution identity')
    page=1
    while True:
        rows=api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/workflows/{current['workflow_id']}/runs?event=workflow_dispatch&head_sha={os.environ['GITHUB_SHA']}&per_page=100&page={page}")['workflow_runs']
        for other in rows:
            if int(other['id'])>=int(current['id']):continue
            if other['display_title'].startswith(marker):
                raise ValueError('this part/cohort operational attempt has already been used')
        if len(rows)<100:break
        page+=1
    previous=None;aggregate=None
    if previous_run:
        info=run_info(previous_run)
        if info.get('status')!='completed' or info.get('conclusion') not in ('failure','timed_out','cancelled','startup_failure'):
            raise ValueError('operational re-run requires completed failed attempt')
        expected_prefix=f'Paper2 G3 {part}/{mode}/attempt-1 '
        if not info['display_title'].startswith(expected_prefix) or info.get('run_attempt',1)!=1:
            raise ValueError('prior execution is not this part/cohort first attempt')
        if mode=='followup' and ('aggregate-'+aggregate_run+' ') not in info['display_title']:
            raise ValueError('operational re-run changed the follow-up cohort authorization')
        # Upload/infrastructure failure can prevent a control artifact. Preserve
        # authenticated run logs and inventory of whatever artifacts survived;
        # never fabricate missing calibration or measurement evidence.
        logs=root/'failed-attempt-logs.zip'
        api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{previous_run}/logs",logs)
        available=artifacts(previous_run)
        replay.save(root/'failed-attempt-artifacts.json',available)
        previous=dict(part=part,attempt=1,mode=mode,selected_cells=cells,operational_status='failed',
            preserved=True,code_commit=info['head_sha'],source_run_id=previous_run,
            logs_sha256=replay.sha256_file(logs),available_artifacts=[dict(id=r['id'],name=r['name'],digest=r.get('digest'),expired=r.get('expired')) for r in available],
            evidence_scope='Authenticated GitHub run logs retained locally and existing artifact references; absent control/calibration data is NOT RECORDED')
        control_rows=[r for r in available if r['name']=='paper2-g3-control-'+previous_run and not r.get('expired')]
        if control_rows:
            path=download(exact(available,'paper2-g3-control-'+previous_run),root/'failed-attempt')
            artifact_integrity.verify_checksums(path)
            control=replay.read(path/'CONTROL.json')
            if control['failure'] is not None:
                recorded=control['failure']
                row=next(r for r in replay.read(path/'TRANSPORT.json')['files'] if r['path']=='OPERATIONAL_FAILURE.json')
                if transport.digest(transport.canonical(recorded))!=row['sha256']:
                    raise ValueError('failed-attempt receipt not bound to transport inventory')
                if any(recorded.get(k)!=previous[k] for k in ('part','attempt','mode','code_commit')):
                    raise ValueError('failed-attempt receipt identity mismatch')
        if previous.get('code_commit')!=os.environ['GITHUB_SHA'] or info['head_sha']!=os.environ['GITHUB_SHA']:
            raise ValueError('failed attempt bundle differs')
        replay.save(root/'previous.json',previous)
    if aggregate_run:
        info=run_info(aggregate_run)
        if info['head_sha']!=os.environ['GITHUB_SHA']: raise ValueError('follow-up replay code differs')
        path=download(exact(artifacts(aggregate_run),'paper2-g3-report-'+aggregate_run),root/'aggregate')
        replay.verify_aggregate(path);aggregate=replay.read(path/'G3_REPORT.json')
    production.authorize(part,attempt,mode,previous,aggregate,cells or None)


def fetch(output,run_id=None):
    root=Path(output);root.mkdir(parents=True,exist_ok=False)
    rehearsal=os.environ.get('REHEARSAL')=='true'
    ids=[os.environ.get(k,'') for k in ('SOURCE_7X','SOURCE_7M','FOLLOWUP_7X','FOLLOWUP_7M')]
    if not ids[0] or not rehearsal and not ids[1] or rehearsal and any(ids[1:]):
        raise ValueError('both validation parts, or exactly one DIAGNOSTIC rehearsal source, required')
    selected=[i for i in ids if i]
    if len(selected)!=len(set(selected)): raise ValueError('duplicate source run IDs')
    for rid in selected:
        info=run_info(rid)
        if info['conclusion']!='success': raise ValueError('operationally failed part excluded from G3')
        rows=artifacts(rid)
        uploaded_control=download(exact(rows,'paper2-g3-control-'+rid),root/('control-transport-'+rid))
        artifact_integrity.verify_checksums(uploaded_control)
        bootstrap=replay.read(uploaded_control/'CONTROL.json')
        if bootstrap['source_run_id']!=rid or bootstrap['code_commit']!=info['head_sha']:
            raise ValueError('control bootstrap differs from GitHub receipt')
        by_id={str(r['id']):r for r in rows}
        # PART contains counts/provenance only, no per-transaction objects. Its
        # independently bound raw digest is checked without decoding calibration.
        raw=transport.read_file(uploaded_control,'PART.json')
        control=root/('control-'+rid);control.mkdir()
        (control/'PART.json').write_bytes(raw)
        part=json.loads(raw)
        if replay.sha256_file(control/'PART.json')!=bootstrap['part_sha256']:
            raise ValueError('control part checksum differs')
        if part['source_run_id']!=rid or part['code_commit']!=info['head_sha']:raise ValueError('source provenance differs from GitHub receipt')
        replay.save(control/'CONTROL_PROOF.json',dict(control_transport=uploaded_control.relative_to(root).as_posix(),
            transport_sha256=replay.sha256_file(uploaded_control/'TRANSPORT.json'),part_sha256=bootstrap['part_sha256']))
        artifact_integrity.write_checksums(control)
        for artifact in bootstrap['packets']:
            aid=str(artifact['id']);row=by_id[aid]
            if row.get('expired') or row['digest'].removeprefix('sha256:')!=artifact['digest'].removeprefix('sha256:'):
                raise ValueError('missing/expired or changed canonical artifact')
        if run_id:
            target=next((r for r in part['completed'] if r['run_id']==run_id),None)
            if target is not None:
                aid=str(target['artifact']['id'])
                target_root=download(by_id[aid],root/('packet-'+aid))
                artifact_integrity.verify_checksums(target_root)
                if replay.sha256_file(target_root/'TRANSPORT.json')!=target['transport_sha256']:
                    raise ValueError('packet transport descriptor differs')
                dependencies={str(d['artifact']) for d in replay.read(target_root/'TRANSPORT.json')['objects'].values() if d['artifact'] is not None}
                for dependency in dependencies:
                    if dependency not in {str(a['id']) for a in bootstrap['packets']}:raise ValueError('canonical object outside source part')
                    dep=download(by_id[dependency],root/('packet-'+dependency))
                    artifact_integrity.verify_checksums(dep)
        replay.save(root/('REMOTE_RUN-'+rid+'.json'),dict(run_id=rid,head_sha=info['head_sha'],conclusion=info['conclusion']))
    return root


def main():
    import sys
    if len(sys.argv)>1 and sys.argv[1]=='fetch':
        p=argparse.ArgumentParser();p.add_argument('command');p.add_argument('--output',type=Path,required=True);p.add_argument('--run-id')
        a=p.parse_args();fetch(a.output,a.run_id);return
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--part',required=True)
    p.add_argument('--attempt',type=int,required=True);p.add_argument('--mode',required=True)
    p.add_argument('--previous-run',default='');p.add_argument('--aggregate-run',default='');p.add_argument('--cells',default='')
    a=p.parse_args();authorize(a.root,a.part,a.attempt,a.mode,a.previous_run,a.aggregate_run,[int(i) for i in a.cells.split(',') if i])


if __name__=='__main__':main()
