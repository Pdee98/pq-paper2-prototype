"""Prepared remote-only scale receipt for numeric capture/table construction.

Synthetic fixed stages; no prototype, ARM, native calibration or G3 data.
"""
import csv,hashlib,json,time
from pathlib import Path
from src.paper2.prototype import stage_capture as c,dispatcher_tables as t

def generate(directory,count,rep):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=False)
    jobs=['synthetic:'+str(i) for i in range(count)]
    recorder=c.Recorder(directory,28*count+8192,dict(window='representative-cycle',calibration_only=True,
        backend='synthetic',k=2,host='qualification-synthetic',replicate=rep,epoch_ns=0,warmup=0,
        measurement=count+100),jobs,['synthetic-block'])
    b=c.Boundaries(recorder);scale=1000000;now=0
    sample=(directory/'cycles.csv').open('x',newline='')
    writer=csv.writer(sample);writer.writerow(('backend','operation','variant','job_id','job_class','source','duration_ns','occupancy_ns','primitive_ns','send_ns','receive_ns'))
    try:
        # Common exact-size support, without a fabricated fitted coefficient.
        b.begin(now,c.F['block_arrival'],c.S['block_build'],block=0,size=2)
        now+=scale;b.change(now,c.S['block_lookups']);now+=scale;b.change(now,c.S['block_lookups'])
        now+=scale;b.change(now,c.S['block_tail']);b.end(now)
        b.begin(now,c.F['acceptance'],c.S['block_accept'],block=0,size=2);now+=scale;b.end(now)
        for i in range(count):
            cls=('admission','block_tx','block_sig')[i%3]
            b.begin(now,c.F['arrival'],c.S['arrival_pre'],job=i);now+=scale;b.end(now)
            b.begin(now,c.F['send'],c.S['send_pre'],job=i,worker=i%2)
            now+=scale;sent=now;b.record(now,c.E['send']);b.change(now,c.S['send_tail']);b.record(now,c.E['pipe_return']);b.end(now)
            now+=2*scale;received=now;b.begin(now,c.F['completion_'+cls],c.S['complete_'+cls],job=i,worker=i%2)
            b.record(now,c.E['receive']);now+=scale;b.end(now)
            writer.writerow(('synthetic:'+cls,'verify','valid',jobs[i],cls,f'concurrency-cycle-k2-rep{rep}',4*scale,2*scale,scale,sent,received))
    finally:sample.close();recorder.finish(True)
    return directory

def scale(work,receipts,count=117292,smoke=False):
    work=Path(work);receipts=Path(receipts);rows=[]
    for fraction in ((1.,) if smoke else (.1,.25,.5,1.)):
        n=max(3,round(count*fraction));root=work/str(n);root.mkdir(parents=True)
        begin=time.perf_counter();paths=[generate(root/str(rep),n,rep) for rep in range(3)]
        generation=time.perf_counter()-begin;at=time.perf_counter()
        audits=[c.audit(p) for p in paths]
        if not all(a['passed'] for a in audits):raise RuntimeError('capture partition scale gate failed')
        auditing=time.perf_counter()-at;at=time.perf_counter()
        for slot,reps in t.SLOTS.items():t.build([paths[r] for r in reps],slot,root/slot)
        tables=time.perf_counter()-at
        row=dict(transactions=n,fraction=fraction,generation_seconds=generation,audit_seconds=auditing,table_seconds=tables,
            numeric_rows=sum(a['rows'] for a in audits),violations=0)
        rows.append(row);print(json.dumps(row),flush=True)
    value=dict(purpose='SYNTHETIC capture/table scale only; excluded from G3',seed='literal-v1: no random draw',rows=rows,
        memory_and_cpu_receipt='qualification monitor step.json and time-v.txt',full_size_confirmation=not smoke)
    (receipts/'capture-scale.json').write_text(json.dumps(value,indent=2));return value
