"""Synthetic scale gate; no prototype, signing, calibration or real G3 input."""
import cProfile
import gc
import io
import json
import math
from pathlib import Path
import pstats
import random
import shutil
import time
from .invariants import check
from src.paper2.model import run_model

SEED=91320261113
FULL_COUNT=117292
RATE=1115.433019832252


def configuration(n):
    rng=random.Random(SEED);cost_rng=random.Random(SEED+1);t=0;arrivals=[];transactions={};blocks=[];times=[]
    for i in range(n):
        t+=rng.expovariate(RATE);identity=f'q:{i}'
        transactions[identity]=dict(tx_id=identity,sender='account',receiver='sink',nonce=i,
            amount=0,fee_rate=0,size_bytes=249,timestamp=0,sig_label='valid')
        arrivals.append(dict(tx_id=identity,arrival_t=t))
        if (i+1)%128==0 or i+1==n:
            first=i-i%128
            blocks.append(dict(block_id=f'b:{len(blocks)}',tx_ids=[f'q:{j}' for j in range(first,i+1)]))
            times.append(t+.005)
    names=('arrival_pre','arrival_tail','block_build','block_lookup','block_tail','send_pre','send_tail',
           'complete_admission','complete_block_tx','complete_block_sig','complete_tail','accept','accept_tail')
    return dict(run_id='paper2-model-qualification-scale-v1',replicate=0,k=2,q_max=1000000,
        genesis=dict(balances=dict(account=1,sink=0),next_nonces=dict(account=0,sink=0)),
        transactions=transactions,admissions=arrivals,blocks=blocks,block_times=times,block_period=128/RATE,
        deadline=1,policy=dict(name='block_priority'),coalesce_inflight=False,
        cache=dict(capacity=None,ttl=120),pool=dict(enabled=True,capacity_bytes=None),
        service=dict(mode='constant',seconds=dict(admission=.0004486,block_tx=.0004486,block_sig=.002)),
        dispatcher=dict(schema='paper2-dispatcher-literal-v1',mode='explicit',
                        costs={name:cost_rng.choice([1e-6,2e-6,3e-6]) for name in names}))


def scale(work,receipts,count=FULL_COUNT,smoke=False):
    work=Path(work);receipts=Path(receipts);work.mkdir(parents=True,exist_ok=True);receipts.mkdir(parents=True,exist_ok=True)
    if not smoke and count!=FULL_COUNT:raise ValueError('qualification scale count is fixed')
    result=dict(label='LOCAL-SMOKE' if smoke else 'SYNTHETIC MODEL QUALIFICATION',seed=SEED,
        stage_cost_seed=SEED+1,offered_rate=RATE,block_size=128,k=2,policy='block_priority',cases=[],status='running')
    def save():(receipts/'scale.json').write_text(json.dumps(result,indent=2))
    save()
    for fraction in (.1,.25,.5,1):
        n=math.ceil(count*fraction);directory=work/f'scale-{n}';begin=time.perf_counter();cpu=time.process_time()
        e,m=run_model(dict(configuration(n),output_dir=str(directory)))
        simulation=dict(wall_seconds=time.perf_counter()-begin,cpu_seconds=time.process_time()-cpu)
        gc.collect()
        profile=cProfile.Profile();begin=time.perf_counter();cpu=time.process_time();profile.enable()
        violations=check(e,e.parent/'jobs.csv',m);profile.disable()
        elapsed=time.perf_counter()-begin;check_cpu=time.process_time()-cpu
        output=io.StringIO()
        for order in ('cumulative','tottime'):pstats.Stats(profile,stream=output).sort_stats(order).print_stats(25)
        (receipts/f'profile-{n}.txt').write_text(output.getvalue())
        data=json.loads(m.read_text());row=dict(fraction=fraction,transactions=n,events=data['event_count'],jobs=data['job_records']['count'],
            simulation=simulation,checker=dict(wall_seconds=elapsed,cpu_seconds=check_cpu,rows_per_second=data['event_count']/elapsed),
            violation_count=len(violations),violations=violations[:20])
        result['cases'].append(row);save();print(json.dumps(row),flush=True)
        if violations:
            result['status']='failed: invariant violations';save();raise RuntimeError('scale invariant gate failed')
        if directory.resolve().parent!=work.resolve():raise ValueError('scratch removal outside work directory')
        shutil.rmtree(directory);gc.collect()
    result['status']='smoke passed' if smoke else 'passed';save();return result
