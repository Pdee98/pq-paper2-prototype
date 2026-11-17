"""Two-attempt DIAGNOSTIC authorisation from sealed repository evidence."""
import argparse
import json
import os
from pathlib import Path
from . import replay,remote_authorization as remote

NAMESPACE='paper2-g3-rehearsal-v2'
PREFIX='Paper2 DIAGNOSTIC rehearsal v2 attempt-'


def validate(attempt,previous_run,previous=None):
    if isinstance(attempt,bool) or attempt not in (1,2):raise ValueError('only attempts 1 and 2 are permitted')
    if attempt==1:
        if previous_run:raise ValueError('attempt 1 cannot name a predecessor')
    elif (not previous_run or not previous or previous.get('namespace')!=NAMESPACE or
          previous.get('attempt')!=1 or str(previous.get('source_run_id'))!=str(previous_run) or
          previous.get('retryable') is not True or previous.get('status') not in ('failure','INVALID')):
        raise ValueError('attempt 2 requires sealed failure/INVALID evidence from attempt 1')
    return attempt


def sealed_download(run_id,name,destination):
    directory=remote.download(remote.exact(remote.artifacts(run_id),name),destination)
    replay.verify_files(directory,'RESULT_MANIFEST.json')
    return replay.read(directory/'result.json')


def authorize(root,attempt,previous_run=''):
    validate(attempt,previous_run,dict(namespace=NAMESPACE,attempt=1,source_run_id=previous_run,retryable=True,status='failure') if previous_run else None)
    root=Path(root);rid=os.environ['GITHUB_RUN_ID'];code=os.environ['GITHUB_SHA'];repo=os.environ['GITHUB_REPOSITORY']
    current=remote.run_info(rid)
    if current.get('run_attempt',1)!=1:raise ValueError('use explicit attempt 2; GitHub rerun jobs is not authorised')
    if not current['display_title'].startswith(PREFIX+str(attempt)+' '):raise ValueError('workflow attempt identity mismatch')
    # One execution per attempt and bundle. This prevents redispatching attempt
    # 1 or 2 to obtain an unregistered third measurement opportunity.
    page=1
    while True:
        runs=remote.api(f"repos/{repo}/actions/workflows/{current['workflow_id']}/runs?event=workflow_dispatch&head_sha={code}&per_page=100&page={page}")['workflow_runs']
        if any(int(r['id'])<int(rid) and r['display_title'].startswith(PREFIX+str(attempt)+' ') for r in runs):
            raise ValueError('this v2 attempt was already used; a third attempt is forbidden')
        if len(runs)<100:break
        page+=1
    prior=None
    if attempt==2:
        info=remote.run_info(previous_run)
        if info['head_sha']!=code or info.get('status')!='completed' or info.get('run_attempt',1)!=1 or not info['display_title'].startswith(PREFIX+'1 '):
            raise ValueError('predecessor is not completed attempt 1 of this bundle')
        prior=sealed_download(previous_run,'paper2-v2-attempt-outcome-'+previous_run,root/'prior-attempt')
        if prior.get('repository')!=repo or prior.get('code_commit')!=code:raise ValueError('prior attempt repository/commit mismatch')
        validate(attempt,previous_run,prior)
    value=dict(namespace=NAMESPACE,attempt=attempt,attempt_1_run_id=previous_run,source_run_id=rid,
        code_commit=code,repository=repo,prior_outcome=prior,accepted=True,
        design='same workload namespace; fresh host calibration; no prior samples reused')
    output=root/'attempt-authorization';output.mkdir(parents=True,exist_ok=False)
    replay.save(output/'result.json',value);replay.seal(output,'RESULT_MANIFEST.json')
    return value


def load(root,attempt):
    directory=Path(root)/'attempt-authorization';replay.verify_files(directory,'RESULT_MANIFEST.json')
    value=replay.read(directory/'result.json')
    if value.get('attempt')!=attempt or value.get('namespace')!=NAMESPACE or value.get('accepted') is not True:
        raise ValueError('missing or wrong accepted attempt identity')
    validate(attempt,value.get('attempt_1_run_id',''),value.get('prior_outcome'))
    return value


def outcome(root,attempt,previous_run,job_results):
    root=Path(root);root.mkdir(parents=True,exist_ok=False)
    job_results={name:(value['result'] if isinstance(value,dict) else value) for name,value in job_results.items()}
    rid=os.environ['GITHUB_RUN_ID'];repo=os.environ['GITHUB_REPOSITORY'];code=os.environ['GITHUB_SHA']
    auth=sealed_download(rid,'paper2-v2-attempt-authorization-'+rid,root/'accepted')
    if auth.get('attempt')!=attempt or auth.get('source_run_id')!=rid or auth.get('repository')!=repo or auth.get('code_commit')!=code:
        raise ValueError('accepted attempt receipt differs from current execution')
    # Authenticated job results are supplied by the workflow needs context, not
    # inferred from raw UNVERIFIED evidence. Q7, when present, is hash-verified.
    if set(job_results)!={'g3','prepare-replay','replay','q7'}:raise ValueError('incomplete authenticated job outcome context')
    status='failure' if any(v!='success' for v in job_results.values()) else 'complete'
    q7=None
    rows=[r for r in remote.artifacts(rid) if r['name']=='paper2-v2-q7-'+rid]
    if rows:
        q7=sealed_download(rid,'paper2-v2-q7-'+rid,root/'q7')
        from . import rehearsal_v2_q7
        if (q7.get('namespace')!=NAMESPACE or q7.get('attempt')!=attempt or q7.get('code_commit')!=code or
                q7.get('reader_source_sha256')!=replay.sha256_file(Path(rehearsal_v2_q7.__file__))):
            raise ValueError('wrong Q7 attempt/source/reader')
        if q7['verdict']=='INVALID':status='INVALID'
    elif status=='complete':raise ValueError('missing Q7 evidence in completed execution')
    # The workflow context is authoritative but keep its corresponding API job
    # receipt too; a later authoriser can inspect the bound failure evidence.
    jobs=remote.api(f'repos/{repo}/actions/runs/{rid}/jobs?per_page=100')
    value=dict(namespace=NAMESPACE,attempt=attempt,attempt_1_run_id=previous_run,
        source_run_id=rid,repository=repo,code_commit=code,status=status,
        retryable=attempt==1 and status in ('failure','INVALID'),job_results=job_results,
        jobs=jobs,q7_verdict=q7['verdict'] if q7 else None,
        accepted_receipt_sha256=replay.sha256_file(root/'accepted/RESULT_MANIFEST.json'))
    # Nested original evidence stays covered; this small receipt is distinct
    # from raw failed-attempt outputs, which remain non-consumable.
    replay.save(root/'result.json',value);replay.seal(root,'RESULT_MANIFEST.json')
    return value


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('authorize','outcome'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--attempt',type=int,required=True)
    p.add_argument('--previous-run',default='')
    a=p.parse_args()
    if a.command=='authorize':authorize(a.root,a.attempt,a.previous_run)
    else:outcome(a.root,a.attempt,a.previous_run,json.loads(os.environ['V2_JOB_RESULTS']))

if __name__=='__main__':main()
