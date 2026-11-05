"""Author-approved count-aware stationarity and cache-cohort validity."""
import csv,json,statistics
from pathlib import Path
from .cycle_protocol import CLASSES

def from_records(records,waiting_after,config,blocks,window=(30,90),drain_end=105):
    """Cycles end at the next same-worker send while eligible work waited.

    Starvation counts physical jobs enqueued in the measurement window and
    completed by drain_end. Cache-hit logical checks are not physical jobs.
    """
    left,right=window;expected=config['calibration_cycle_means']
    physical=sorted((j for j in records if 'send_ns' in j),key=lambda j:(j['worker_id'],j['send_ns']))
    samples={c:[] for c in CLASSES};enqueued={c:0 for c in CLASSES};completed={c:0 for c in CLASSES}
    censored={c:0 for c in CLASSES};successors=set()
    for previous,following in zip(physical,physical[1:]):
        if (previous['worker_id']==following['worker_id'] and left<=previous['start_t']<right and
            waiting_after.get(previous['job_id'],False) and previous.get('end_t') is not None and
            previous['end_t']<=drain_end and following['start_t']<=drain_end):
            samples[previous['job_class']].append((following['send_ns']-previous['send_ns'])/1e9)
            successors.add(previous['job_id'])
    for j in records:
        c=j['job_class'];t=j.get('enqueue_t')
        if t is not None and left<=t<right:
            enqueued[c]+=1
            if j.get('end_t') is not None and j['end_t']<=drain_end:completed[c]+=1
        if ('send_ns' in j and left<=j['start_t']<right and j['job_id'] not in successors and
            (j.get('end_t') is None or waiting_after.get(j['job_id'],False))):censored[c]+=1
    checks={}
    for c in CLASSES:
        n=len(samples[c]);mean=statistics.fmean(samples[c]) if n else None
        error=abs(mean-expected[c])/expected[c] if mean is not None else None
        status=('TESTED-PASS' if error<=.10 else 'TESTED-FAIL') if n>=100 else 'LOW-COUNT' if n else 'NOT OBSERVED'
        starved=enqueued[c]>0 and completed[c]==0
        passed=status!='TESTED-FAIL' and not starved and (c!='admission' or n>=100)
        checks[c]=dict(n=n,count=n,mean=mean,calibration_mean=expected[c],relative_error=error,status=status,
            tested=n>=100,enqueued_in_window=enqueued[c],completed_by_drain=completed[c],censored=censored[c],starved=starved,passed=passed)
    cohort=[j['status']=='cache_hit' for j in records if j['job_class']=='block_tx' and left<=blocks[j['block_id']]['arrival_t']<right]
    hit=sum(cohort)/len(cohort) if cohort else None
    passed=all(r['passed'] for r in checks.values()) and hit is not None and hit>=.90
    return dict(scheme='cycle-calibration-v6',window=list(window),drain_end=drain_end,class_checks=checks,
        measurement_block_tx_hit_rate=hit,hit_limit=.90,stationarity_limit=.10,minimum_count=100,
        passed=passed,status='VALID' if passed else 'INVALID',
        retired_guards=['idle-while-waiting <=5%','p99 dispatch gap <=1ms'])

def from_logs(events,jobs,config,manifest,window=(30,90)):
    with Path(jobs).open(newline='') as f:records=[json.loads(row['record']) for row in csv.DictReader(f)]
    waiting={}
    with Path(events).open(newline='') as f:
        for row in csv.DictReader(f):
            if row['event']=='end':waiting[row['job_id']]=int(row['q_admission'])+int(row['q_block'])>0
    return from_records(records,waiting,config,json.loads(Path(manifest).read_bytes())['blocks'],window)
