"""Backlogged fixed-real-corpus workers through the Deviation 4 dispatcher.

Logical state/arrival/block traffic is synthetic. Every physical verification
uses the presigned pilot's genuine bytes. Synthetic signatures are never sent
to a worker or exported. All preparation/CSV work is outside the timed window.
"""
import csv,hashlib,heapq,json,math,statistics,tempfile,time
from pathlib import Path
from . import corpus
from .runtime import PreDeviation5Model,BufferedEventWriter
from .analysis import distribution
from .cycle_protocol import CLASSES
from src.paper2.workload import generate_workload
from src.paper2.model.service_times import sha256_file

class SyntheticSigner:
    dimensions=(64,32);serial=0
    def __init__(self,backend):
        type(self).serial+=1;self.signature_size,n=type(self).dimensions
        self.public_key=hashlib.shake_256(str(type(self).serial).encode()).digest(n)
    def sign(self,payload):return bytes(self.signature_size)
    def close(self):pass

def traffic_workload(rate,duration,run_id,prefix):
    from .runner import parameters
    w=generate_workload(dict(parameters(rate,0,128/rate,horizon=duration),run_id=run_id))
    names={t:prefix+t for t in w['transactions']}
    w['transactions']={names[t]:dict(tx,tx_id=names[t]) for t,tx in w['transactions'].items()}
    for a in w['admissions']:a.update(tx_id=names[a['tx_id']])
    for b in w['blocks']:b.update(block_id=prefix+b['block_id'],tx_ids=[names[t] for t in b['tx_ids']])
    return w

class CalibrationModel(PreDeviation5Model):
    def __init__(self,config,path,pilot):
        super().__init__(config,path,validated_sha256=sha256_file(path))
        self.fixed={c:[] for c in CLASSES};self.last={};self.samples=[];self.unbacklogged=0;self.sent=0
        for c in ('admission','block_tx'):self.fixed[c]=[corpus.signed_parts(e) for e in list(pilot['transactions'].values())[:128]]
        self.fixed['block_sig']=[corpus.signed_parts(next(iter(pilot['blocks'].values())))];self.indices={c:0 for c in CLASSES}
        self.prefilling=True;self.epoch=time.monotonic_ns();keep=[]
        # Process the initial source in its original chronological order while
        # withholding dispatch. Live traffic retains its own fixed timestamps.
        while self.events:
            event=heapq.heappop(self.events);self.scheduled_t=event[0];self.t=0
            callback,args=event[3:]
            identity=args[1]['tx_id'] if callback.__name__=='_admission' else args[1]['block_id']
            if identity.startswith('backlog:'):callback(*args)
            else:keep.append(event)
        self.events=keep;heapq.heapify(self.events);self.prefilling=False;self.t=0
        self.block_snapshots={bid:(bid,b['arrival_t'],b['accept_t'],b['deadline_t'],b['reject_t'],b['reject_reason'],b['reject_reasons'])
                              for bid,b in self.blocks.items()}
        self.event_writer=BufferedEventWriter(None,self.event_capacity,self.serialize_event)

    def worker_publics(self):return {p[2] for values in self.fixed.values() for p in values}
    def _log(self,*args,**kwargs):
        if getattr(self,'prefilling',False):return
        super()._log(*args,**kwargs)
    def _dispatcher(self,cost,callback,*args):
        if self.prefilling:callback(*args)
        else:super()._dispatcher(cost,callback,*args)
    def _dispatch(self):
        if not self.prefilling:super()._dispatch()
    def _receive(self,worker):
        previous=self.pool.running[worker];self.last[worker]=(previous,bool(self.pool.waiting))
        super()._receive(worker)
        if previous.outcome!='valid':raise ValueError('fixed calibration corpus verification failed')
    def _start(self,job,worker):
        values=self.fixed[job.job_class];n=self.indices[job.job_class];self.indices[job.job_class]+=1
        payload,signature,public=values[n%len(values)]
        job.send_ns=time.monotonic_ns();prior=self.last.pop(worker,None)
        if prior:
            previous,waiting=prior
            if waiting:self.samples.append(dict(backend=self.corpus['backend']+':'+previous.job_class,operation='verify',variant='valid',
                duration_ns=job.send_ns-previous.send_ns,occupancy_ns=previous.occupancy_ns,primitive_ns=previous.primitive_ns,
                job_class=previous.job_class,source=f'concurrency-cycle-k{self.pool.k}-rep{self.config["replicate"]}',worker_id=worker,
                send_ns=previous.send_ns-self.epoch,next_send_ns=job.send_ns-self.epoch,receive_ns=previous.receive_ns-self.epoch))
            else:self.unbacklogged+=1
        self.workers.pipes[worker].send(('verify',job.job_id,payload,signature,public));self.ipc_ns+=time.monotonic_ns()-job.send_ns
        job.dispatch_to_start_ns=job.send_ns-self.dispatch_ns[job.job_id];job.dispatch_decision_ns=self.dispatch_ns[job.job_id]
        job.scheduled_service_unknown=True;self.t=(job.send_ns-self.epoch)/1e9;self.sent+=1
        from src.paper2.model.engine import Model
        Model._start(self,job,worker)

def calibrate_cycle(corpus_path,k,output,replicate,traffic_rate,throughput,warmup=2,measurement=10,diagnostic=False,seed_tag=''):
    if traffic_rate<=0 or warmup<0 or measurement<=0:raise ValueError('positive cycle calibration rate/window required')
    output=Path(output);output.mkdir(parents=True,exist_ok=False);pilot=json.loads(Path(corpus_path).read_bytes());duration=warmup+measurement
    with tempfile.TemporaryDirectory(prefix='paper2-cycle-synthetic-') as td:
        rate=max(256/duration,throughput)
        backlog=traffic_workload(rate,duration,'paper2-cycle-backlog-'+pilot['backend']+str(k)+seed_tag,'backlog:')
        live=traffic_workload(traffic_rate,duration,'paper2-cycle-traffic-'+pilot['backend']+str(k)+seed_tag,'traffic:')
        def times(w):return [w['block_start']+i*w['block_period'] for i in range(len(w['blocks']))]
        ordered=sorted(zip(times(backlog)+times(live),backlog['blocks']+live['blocks']),key=lambda pair:pair[0])
        w=dict(live,transactions={**backlog['transactions'],**live['transactions']},admissions=backlog['admissions']+live['admissions'],
            blocks=[b for t,b in ordered],block_times=[t for t,b in ordered])
        e=next(iter(pilot['transactions'].values()));SyntheticSigner.dimensions=(len(bytes.fromhex(e['signature_hex'])),len(bytes.fromhex(e['public_key_hex'])))
        dummy=corpus.build(w,pilot['backend'],signer_factory=SyntheticSigner);path=corpus.write(dummy,Path(td)/'synthetic.json')
        cfg=dict(dummy['workload'],replicate=replicate,k=k,policy=dict(name='fifo'),coalesce_inflight=False,
            q_max=len(w['admissions'])+1,cache=dict(capacity=4096,ttl=2*128/traffic_rate,erase_on_inclusion=False),
            pool=dict(enabled=True,capacity_bytes=16*1024*1024))
        from .gc_control import WindowGC
        from .pause_attribution import PauseRecorder, labelled
        from .progress import Progress
        from .runtime import CycleRealtimeModel
        from types import MethodType
        model=CalibrationModel(cfg,path,pilot);model.stop_t=duration
        model.pause_monitor=PauseRecorder(output,detailed=diagnostic);model.detailed=diagnostic
        model.gc_window=WindowGC(output,model.pause_monitor);model.progress=Progress(output)
        if diagnostic:
            model._handle=MethodType(CycleRealtimeModel._handle,model)
            for name,label in dict(_decide_block='block_state',_receive='receive_result',_dispatch='select_dispatch',
                                   _view='policy_view',_start='send_start',_admit_state='admission_state',
                                   _insert_cache='cache_insert_evidence',_lookup='cache_lookup_ttl',
                                   _admit_ready='admission_structural',_block_ready='block_structural',_new_job='job_preparation').items():
                setattr(model,name,MethodType(labelled(label)(getattr(model,name).__func__),model))
        complete=False
        try:model.run();complete=True
        finally:
            model.gc_window.leave(partial=not complete)
            model.pause_monitor.finish(partial=not complete);model.progress.close()
        if diagnostic:
            from .serialisation import write_json
            with (output/'events.csv').open('x',newline='') as stream:
                writer=csv.writer(stream);writer.writerow(model.event_fields)
                for i in range(model.event_writer.count):writer.writerow(model.serialize_event(model.event_writer.records[i]))
            with (output/'jobs.csv').open('x',newline='') as stream:
                writer=csv.writer(stream);writer.writerow(('job_id','record'))
                for j in model.jobs.values():writer.writerow((j.job_id,json.dumps(vars(j),separators=(',',':'))))
            write_json(output/'dispatcher_spans.json',model.spans)
        selected=[r for r in model.samples if warmup*1e9<=r['send_ns']<(warmup+measurement)*1e9]
        if model.unbacklogged:raise ValueError('cycle calibration source was not backlogged')
        if any(not any(r['job_class']==c for r in selected) for c in CLASSES):raise ValueError('missing cycle calibration class')
        with (output/'cycles.csv').open('x',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=tuple(selected[0]));writer.writeheader();writer.writerows(selected)
        stats={c:distribution([r['duration_ns']/1e9 for r in selected if r['job_class']==c]) for c in CLASSES}
        for c in CLASSES:
            values=sorted(r['duration_ns']/1e9 for r in selected if r['job_class']==c);stats[c]['p99']=values[math.ceil(.99*len(values))-1]
        result=dict(backend=pilot['backend'],k=k,replicate=replicate,traffic_rate=traffic_rate,warmup=warmup,measurement=measurement,
            epoch_ns=model.epoch,seed_tag=seed_tag,diagnostic_instrumentation=diagnostic,
            gc_control=dict(version=7,state='gc_state.json',progress='progress.jsonl'),
            means={c:stats[c]['mean'] for c in CLASSES},statistics=stats,samples=str(output/'cycles.csv'),
            synthetic_live_arrivals=len(live['admissions']),synthetic_live_blocks=len(live['blocks']),initial_backlog_jobs=model.sent+len(model.pool.waiting),
            physical_sends=model.sent,unbacklogged_successors=model.unbacklogged,unfinished_at_boundary=len(model.pool.running),
            design='Deviation 4 completion/dispatch path; fixed real verification bytes; FIFO initial synthetic backlog plus timed synthetic traffic; calibration-only enlarged queue cap',
            csv_sha256=sha256_file(output/'cycles.csv'))
    (output/'calibration.json').write_text(json.dumps(result,indent=2));return result


def calibrate_backend(backend,path,root,stage_times=None,timeout=1200,diagnostic=False,seed_tag=''):
    """Old diagnostics retained; exactly one representative-traffic replacement."""
    from . import runner
    from .calibration import calibrate_once
    from .analysis import references
    from .cycle_protocol import cold_cycle_reference,cold_cycle_loads
    root=Path(root);old=[];begin=time.perf_counter()
    def invoke(function,args):
        budget=timeout-(time.perf_counter()-begin)
        if budget<=0:raise TimeoutError('cycle calibration stage watchdog')
        at=time.perf_counter();r=runner.fresh(function,args,budget,progress_path=Path(args[2])/'progress.jsonl',
            partial_dir=root/'calibration-timeouts'/Path(args[2]).name)
        if stage_times is not None:runner.account(root,stage_times,'calibration',time.perf_counter()-at)
        return r
    for k in (1,2,3):
        for rep in range(3):old.append(invoke(calibrate_once,(path,k,root/'calibration'/f'{backend}-k{k}-r{rep}',rep,2,10,diagnostic)))
    throughput={k:statistics.fmean(r['throughput'] for r in old if r['k']==k) for k in (1,2,3)}
    occupancy={}
    for k in (1,2,3):
        occupancy[k]=root/'calibration'/f'{backend}-k{k}-occupancy.csv'
        runner.merge_samples([r['samples'] for r in old if r['k']==k],occupancy[k])
    with occupancy[1].open(newline='') as f:rows=list(csv.DictReader(f))
    means={c:statistics.fmean(int(r['duration_ns'])/1e9 for r in rows if r['job_class']==c) for c in CLASSES}
    prior=references(means,throughput,max(r['dispatcher_per_tx'] for r in old));refs={};windows=[]
    for k in (1,2):
        d=max(r['dispatcher_per_tx'] for r in old if r['k']==k);rate=.8*prior[k]['B_cold']
        def window(iteration,rate):
            runner.save(root/'calibration'/f'{backend}-k{k}-cycle-i{iteration}-DESIGN.json',
                dict(backend=backend,k=k,traffic_rate=rate,old_B_cold=prior[k]['B_cold'],iteration=iteration,
                     seed_tag=seed_tag,diagnostic_instrumentation=diagnostic,
                     design='fixed before this window; FIFO backlog plus actual synthetic arrival/block handlers'))
            result=[invoke(calibrate_cycle,(path,k,root/'calibration'/f'{backend}-k{k}-cycle-i{iteration}-r{rep}',rep,rate,throughput[k],2,10,diagnostic,seed_tag)) for rep in range(3)]
            target=root/'calibration'/f'{backend}-k{k}-cycle-i{iteration}.csv';runner.merge_samples([r['samples'] for r in result],target)
            with target.open(newline='') as f:data=list(csv.DictReader(f))
            m={c:statistics.fmean(int(r['duration_ns'])/1e9 for r in data if r['job_class']==c) for c in CLASSES}
            from .calibration_split import split_samples
            slots=split_samples([r['samples'] for r in result],target.with_suffix(''))
            ref=cold_cycle_reference(k,m,d,throughput[k]/throughput[1]);ref.update(cycle_samples=str(target),occupancy_samples=str(occupancy[k]),calibration_traffic_rate=rate,**slots)
            windows.append(dict(backend=backend,k=k,iteration=iteration,rate=rate,reference=ref,repetitions=result));return ref
        ref=window(0,rate)
        ratios=[max(r['rate']/rate,rate/r['rate']) for r in cold_cycle_loads(ref)]
        if max(ratios)>2:ref=window(1,.8*ref['B_cold_cycle'])
        refs[k]=ref
    runner.save(root/'calibration'/f'{backend}-cycle-session.json',dict(old=old,windows=windows,references=refs,iteration_rule='any planned rho rate differs >2x; at most one replacement'))
    return refs
