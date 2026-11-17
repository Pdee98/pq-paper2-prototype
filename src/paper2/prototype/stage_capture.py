"""Bounded numeric stage evidence, independent of optional diagnostic tracing.

Partition tolerance is ONE NANOSECOND per outer callback, fixed before collection.
Times are raw monotonic nanoseconds. No residual is fitted or subtracted.
"""
import hashlib,json,mmap,os,struct,time
from pathlib import Path

SCHEMA='paper2-stage-capture-v1'
TOLERANCE_NS=1
IDLE_SPIN_LIMIT=4096  # Fixed engineering fault guard, independent of row capacity.
FIELDS=('time_ns','event','family','stage','callback','parent','job','block','worker','size','branch','q_admission','q_block','pool_bytes')
ROW=struct.Struct('<14q');HEADER=struct.Struct('<8sQQ')
MAGIC=b'P2STAGE1'
EVENTS=('callback_entry','callback_exit','stage_entry','stage_exit','release','enqueue','send','pipe_return','receive','cache','pool','decision','bind','proof','group_end','lookup','idle_interval')
FAMILIES=('arrival','block_arrival','completion_admission','completion_block_tx','completion_block_sig','send','acceptance','loop','poll')
STAGES=('arrival_pre','arrival_tail','block_build','block_lookups','block_tail','complete_admission','complete_block_tx','complete_block_sig','complete_tail','send_pre','send_tail','block_accept','block_accept_tail','loop','poll')
E={name:i for i,name in enumerate(EVENTS)};F={name:i for i,name in enumerate(FAMILIES)};S={name:i for i,name in enumerate(STAGES)}
# Observation-only record; existing event rows retain every field and enum ID.
IDLE_FIELDS=dict(time_ns='end_ns',job='start_ns',block='poll_ns',worker='loop_ns',
                 size='poll_iterations',branch='empty_iterations',q_admission='between_observations_ns')


def capacity_bound(config):
    """Event-derived bound; idle duration never appears in the allocation."""
    a=len(config.get('admissions',()));b=len(config.get('blocks',()))
    t=sum(len(block['tx_ids']) for block in config.get('blocks',()));j=a+t+b
    events=a+b+t+j;idle=a+b+j+1
    return dict(admissions=a,blocks=b,block_tx_slots=t,jobs=j,event_units=events,
                max_rows_per_event=64,merged_idle_bound=idle,fixed_margin=8192,
                rows=64*events+idle+8192)

class CaptureOverflow(RuntimeError):pass

class CaptureTimings:
    """Bounded durable observation samples; open count survives process timeout."""
    def __init__(self,directory,capacity):
        self.file=(Path(directory)/'capture-timings.bin').open('x+b');self.capacity=capacity;self.count=0
        self.file.truncate(16+8*capacity);self.map=mmap.mmap(self.file.fileno(),0)
        struct.pack_into('<QQ',self.map,0,0,capacity)
    def __len__(self):return self.count
    def append(self,value):
        struct.pack_into('<Q',self.map,16+8*self.count,value);self.count+=1
        struct.pack_into('<Q',self.map,0,self.count)
    def __iter__(self):
        for i in range(self.count):yield struct.unpack_from('<Q',self.map,16+8*i)[0]
    def close(self):
        self.map.flush();self.map.close();self.file.truncate(16+8*self.count);self.file.close()

def timed_capture(function):
    """Outer capture operations only; nested calls are counted once."""
    from functools import wraps
    @wraps(function)
    def measured(self,*args,**kwargs):
        recorder=getattr(self,'recorder',self)
        if not getattr(recorder,'in_place',False):return function(self,*args,**kwargs)
        outer=recorder.timing_depth==0;recorder.timing_depth+=1
        start=time.monotonic_ns() if outer else 0
        try:return function(self,*args,**kwargs)
        finally:
            recorder.timing_depth-=1
            if outer:
                elapsed=time.monotonic_ns()-start
                if len(recorder.timings)>=recorder.timing_limit:
                    recorder.overflow=True;recorder.preserve('INVALID: capture timer overflow')
                    raise CaptureOverflow('INVALID: capture timer capacity; evidence preserved')
                recorder.timings.append(elapsed)
    return measured

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

class Recorder:
    """Append-only records; count commits after a complete numeric row.

    Preallocation and string catalogs precede the measured window. Existing
    entries are never edited. A killed process leaves a recoverable count/header.
    """
    def __init__(self,directory,capacity,metadata,jobs=(),blocks=(),cost=None):
        if isinstance(capacity,bool) or not isinstance(capacity,int) or capacity<1:raise ValueError('positive capture capacity required')
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.path=self.directory/'stages.bin';self.file=self.path.open('x+b')
        self.capacity=capacity;self.count=0;self.closed=False;self.overflow=False
        self.file.truncate(HEADER.size+capacity*ROW.size);self.map=mmap.mmap(self.file.fileno(),0)
        HEADER.pack_into(self.map,0,MAGIC,0,capacity)
        self.jobs=tuple(jobs);self.blocks=tuple(blocks)
        self.job_ids={name:i for i,name in enumerate(self.jobs)};self.block_ids={name:i for i,name in enumerate(self.blocks)}
        self.metadata=dict(metadata);self.cost=cost;self.receipt=None
        if os.environ.get('PAPER2_CAPTURE_TIMERS')=='1':
            self.metadata['capture_namespace']='paper2-g3-rehearsal-v2'
        from array import array
        self.in_place=os.environ.get('PAPER2_CAPTURE_TIMERS')=='1';self.timing_depth=0
        self.timing_limit=4*capacity+280*60*1000
        self.timings=CaptureTimings(self.directory,self.timing_limit) if self.in_place else array('Q')
        self.timer_overhead=[]
        if self.in_place:
            for _ in range(1000):
                a=time.monotonic_ns();self.timer_overhead.append(time.monotonic_ns()-a)
        self.idle=[-1,0,0,0,0,0];self.last_idle_poll=None;self.zero_progress_polls=0
        self._metadata('OPEN')

    def _metadata(self,status,**extra):
        value=dict(schema=SCHEMA,status=status,fields=FIELDS,events=EVENTS,families=FAMILIES,stages=STAGES,
            partition_tolerance_ns=TOLERANCE_NS,capacity=self.capacity,count=self.count,
            jobs=self.jobs,blocks=self.blocks,context=self.metadata,append_cost=self.cost,
            idle_interval_fields=IDLE_FIELDS,idle_spin_guard=dict(limit=IDLE_SPIN_LIMIT,
                condition='equal-time poll comparisons without root callback progress',
                consecutive_no_progress=self.zero_progress_polls),**extra)
        pending=self.directory/'stages-metadata.pending'
        pending.write_text(json.dumps(value,separators=(',',':')),encoding='utf-8')
        os.replace(pending,self.directory/'stages.json')
        return value

    @timed_capture
    def append(self,t,event,family,stage=-1,callback=-1,parent=-1,job=-1,block=-1,worker=-1,size=-1,branch=0,qa=0,qb=0,pool=0):
        if self.closed:raise RuntimeError('capture is closed')
        if self.count==self.capacity:
            self.overflow=True;self.preserve('INVALID: capture overflow')
            raise CaptureOverflow('INVALID: stage capture overflow; evidence preserved')
        ROW.pack_into(self.map,HEADER.size+self.count*ROW.size,t,event,family,stage,callback,parent,job,block,worker,size,branch,qa,qb,pool)
        self.count+=1;struct.pack_into('<Q',self.map,8,self.count)

    @timed_capture
    def idle_interval(self,start,end,family):
        """Coalesce between root callbacks, keeping poll/wait work disjoint."""
        if family not in ('loop','poll') or end<start:raise ValueError('invalid idle interval')
        v=self.idle
        if v[0]<0:v[0]=start
        elif start<v[1]:raise ValueError('overlapping idle observations')
        v[1]=end;v[2 if family=='poll' else 3]+=end-start;v[4 if family=='poll' else 5]+=1
        if family=='poll':
            self.zero_progress_polls=self.zero_progress_polls+1 if end==self.last_idle_poll else 0
            self.last_idle_poll=end
            if self.zero_progress_polls>=IDLE_SPIN_LIMIT:
                self.flush_idle();self.overflow=True;self.preserve('INVALID: non-advancing idle spin')
                raise CaptureOverflow('INVALID: non-advancing idle spin; evidence preserved')

    def flush_idle(self):
        v=self.idle
        if v[0]<0:return
        start,end,poll,loop,polls,loops=v;v[:]=[-1,0,0,0,0,0]
        self.append(end,E['idle_interval'],F['loop'],job=start,block=poll,worker=loop,
                    size=polls,branch=loops,qa=end-start-poll-loop)

    def preserve(self,status='INVALID: partial capture'):
        self.flush_idle()
        if not self.closed:self.map.flush();self.file.flush();os.fsync(self.file.fileno())
        return self._metadata(status,overflow=self.overflow)

    def finish(self,complete,busy_ns=0):
        if self.closed:return self.receipt
        self.flush_idle()
        self.map.flush();self.map.close();self.file.truncate(HEADER.size+self.count*ROW.size);self.file.flush();os.fsync(self.file.fileno());self.file.close();self.closed=True
        if self.in_place:
            import math,statistics
            def summary(values):
                v=sorted(values);n=len(v)
                return dict(count=n,mean_ns=statistics.fmean(v) if n else None,p50_ns=statistics.median(v) if n else None,
                    p95_ns=v[math.ceil(.95*n)-1] if n else None,p99_ns=v[math.ceil(.99*n)-1] if n else None,
                    max_ns=max(v) if n else None,total_ns=sum(v))
            self.cost=dict(summary(self.timings),in_place=True,report_only=True,is_overhead_estimate=any(self.timings),
                scope='outer capture boundary/record/idle operations; nested calls counted once',
                dispatcher_share=sum(self.timings)/busy_ns if busy_ns else None,timer_overhead=summary(self.timer_overhead),
                count_bound=self.timing_limit,overhead_subtracted=False,no_uninstrumented_comparator=True)
            self.timings.close()
        mean=self.cost.get('mean_ns') if self.cost and self.cost.get('is_overhead_estimate',True) else None
        overhead=self.cost['total_ns'] if self.in_place else self.count*mean if mean is not None else None
        self.receipt=self._metadata('COMPLETE' if complete and not self.overflow else 'INVALID: partial capture',
            overflow=self.overflow,sha256=sha(self.path),bytes=self.path.stat().st_size,
            estimated_overhead_ns=overhead,
            dispatcher_busy_ns=busy_ns,estimated_overhead_share=overhead/busy_ns if overhead is not None and busy_ns>0 else None,
            overhead_subtracted=False)
        return self.receipt

def rows(directory,allow_partial=False):
    directory=Path(directory);spec=json.loads((directory/'stages.json').read_text());path=directory/'stages.bin'
    if spec.get('schema')!=SCHEMA or (spec['status']!='COMPLETE' and not allow_partial):raise ValueError('incomplete or unsupported stage capture')
    if spec.get('sha256') and sha(path)!=spec['sha256']:raise ValueError('stage capture hash mismatch')
    with path.open('rb') as f:
        magic,count,capacity=HEADER.unpack(f.read(HEADER.size))
        open_prefix=allow_partial and spec['status']=='OPEN' and count>=spec['count']
        if magic!=MAGIC or count>capacity or (count!=spec['count'] and not open_prefix):raise ValueError('invalid stage capture header')
        if path.stat().st_size<HEADER.size+count*ROW.size:raise ValueError('truncated stage capture')
        for _ in range(count):
            raw=f.read(ROW.size)
            if len(raw)!=ROW.size:raise ValueError('truncated stage capture row')
            yield ROW.unpack(raw)

def audit(directory,allow_partial=False):
    """Independent interval sums; incomplete stages are errors, not filled gaps."""
    active={};stages={};children={};totals={};errors=[];count=0;last=-1;stack=[];residuals=[]
    idle_count=idle_ns=poll_ns=loop_ns=between_ns=0
    for r in rows(directory,allow_partial):
        t,event,family,kind,callback,parent,*_=r;count+=1
        if event==E['idle_interval']:
            start,poll,loop,polls,loops,between=r[6:12]
            if active or stages or start<last or t<start:errors.append('idle/callback overlap or endpoint')
            if min(poll,loop,polls,loops,between)<0 or poll+loop+between!=t-start:errors.append('idle partition')
            if callback!=-1 or parent!=-1 or kind!=-1:errors.append('idle exclusive ownership')
            idle_count+=1;idle_ns+=t-start;poll_ns+=poll;loop_ns+=loop;between_ns+=between
            last=t;continue
        if t<last:errors.append('nonmonotone capture time')
        last=t
        if event==E['callback_entry']:
            if callback in active:errors.append('duplicate callback')
            if parent>=0 and parent not in active:errors.append('missing callback parent')
            if parent!=(stack[-1] if stack else -1):errors.append('callback nesting/overlap')
            if parent in stages:errors.append('nested child overlaps parent exclusive work')
            active[callback]=(t,parent);totals[callback]=0;children[callback]=0
            stack.append(callback)
        elif event==E['stage_entry']:
            if callback not in active or callback in stages or not stack or callback!=stack[-1]:errors.append('stage ownership')
            stages[callback]=(t,kind)
        elif event==E['stage_exit']:
            begin=stages.pop(callback,None)
            if begin is None or begin[1]!=kind or t<begin[0]:errors.append('stage endpoint')
            else:totals[callback]+=t-begin[0]
        elif event==E['callback_exit']:
            begin=active.pop(callback,None)
            if begin is None:errors.append('callback endpoint');continue
            duration=t-begin[0];residual=duration-totals[callback]-children[callback]
            residuals.append(residual)
            if not stack or stack.pop()!=callback:errors.append('callback exit nesting')
            if callback in stages or duration<0 or abs(residual)>TOLERANCE_NS:errors.append('callback partition')
            if begin[1]>=0:children[begin[1]]+=duration
    if active or stages:errors.append('unfinished callback/stage')
    return dict(passed=not errors,errors=errors,rows=count,tolerance_ns=TOLERANCE_NS,
        exclusive_ns=sum(totals.values()),nested_ns=sum(children.values()),
        idle_intervals=idle_count,idle_ns=idle_ns,poll_ns=poll_ns,loop_ns=loop_ns,between_observations_ns=between_ns,
        residual_ns=sum(residuals),max_absolute_residual_ns=max(map(abs,residuals),default=0),
        unexplained_residuals_are_not_fitted=True)


class Boundaries:
    """Fixed-depth numeric stack. Parent exclusive work pauses during children.

    Capture timestamps are observation endpoints, never scheduler inputs.
    A parent resumes its previous stage after a nested send/acceptance.
    """
    def __init__(self,recorder,context=None):
        self.recorder=recorder;self.context=context;self.depth=0;self.serial=0
        self.busy_ns=0;self.root_start=0
        self.ids=[-1]*8;self.families=[-1]*8;self.stages=[-1]*8
        self.jobs=[-1]*8;self.blocks=[-1]*8;self.workers=[-1]*8;self.sizes=[-1]*8

    @timed_capture
    def record(self,t,event,job=-1,block=-1,worker=-1,branch=0):
        if not self.depth:return
        i=self.depth-1;qa=qb=pool=0
        if self.context is not None:
            qa,qb,_=self.context.pool.counts();pool=self.context.tx_pool.bytes
        self.recorder.append(t,event,self.families[i],self.stages[i],self.ids[i],self.ids[i-1] if i else -1,
            job if job>=0 else self.jobs[i],block if block>=0 else self.blocks[i],
            worker if worker>=0 else self.workers[i],self.sizes[i],branch,qa,qb,pool)

    @timed_capture
    def begin(self,t,family,stage,job=-1,block=-1,worker=-1,size=-1):
        if self.depth==len(self.ids):
            self.recorder.overflow=True;self.recorder.preserve('INVALID: capture nesting overflow')
            raise CaptureOverflow('INVALID: capture nesting capacity exceeded')
        if not self.depth:
            self.recorder.flush_idle();self.root_start=t
            self.recorder.last_idle_poll=None;self.recorder.zero_progress_polls=0
        if self.depth:self.record(t,E['stage_exit'])
        i=self.depth;self.ids[i]=self.serial;self.serial+=1
        self.families[i]=family;self.stages[i]=stage;self.jobs[i]=job;self.blocks[i]=block
        self.workers[i]=worker;self.sizes[i]=size;self.depth+=1
        self.record(t,E['callback_entry']);self.record(t,E['stage_entry'])

    @timed_capture
    def change(self,t,stage):
        if not self.depth:return
        self.record(t,E['stage_exit']);self.stages[self.depth-1]=stage;self.record(t,E['stage_entry'])

    @timed_capture
    def end(self,t):
        self.record(t,E['stage_exit']);self.record(t,E['callback_exit']);self.depth-=1
        if self.depth:self.record(t,E['stage_entry'])
        elif self.families[0] not in (F['loop'],F['poll']):self.busy_ns+=t-self.root_start


def catalogs(config):
    jobs=['admission:'+str(i) for i in range(len(config.get('admissions',())))]
    blocks=[]
    for i,b in enumerate(config.get('blocks',())):
        blocks.append(b['block_id']);jobs.extend('block:'+str(i)+':tx:'+str(j) for j in range(len(b['tx_ids'])))
        jobs.append('block:'+str(i)+':sig')
    return jobs,blocks


class CapturedDispatcher:
    """Observation-only hooks shared by representative calibration and runs.

    No queue, clock, policy, GC, service draw or completion transition is changed.
    The historical PreDeviation5Model remains callable without these hooks.
    """
    stage_capture=None

    def capture_open(self,directory,window='prototype'):
        if self.config.get('stage_capture',True) is False:return
        window=self.config.get('stage_capture_window',window)
        jobs,blocks=catalogs(self.config)
        # Fixed before entry. Overflow fails instead of silently losing evidence.
        allocation=capacity_bound(self.config)
        capacity=self.config.get('stage_capture_capacity',allocation['rows'])
        import platform
        cost=None if os.environ.get('PAPER2_CAPTURE_TIMERS')=='1' else measure_cost(directory)
        self.stage_capture=Recorder(directory,capacity,dict(window=window,backend=self.corpus['backend'],
            k=self.pool.k,replicate=self.config.get('replicate',0),host=platform.node(),
            calibration_only=window!='prototype',atomic_group_mapping='final-milestone-v1',
            capacity_formula=allocation,capacity_override=self.config.get('stage_capture_capacity')),jobs,blocks,cost)
        self.stage_boundaries=Boundaries(self.stage_capture,self)

    def capture_close(self,complete):
        capture=self.stage_capture
        if capture is None:return
        capture.metadata['epoch_ns']=self.epoch
        busy=sum(s['end_ns']-s['start_ns'] for s in self.spans)
        receipt=capture.finish(complete,busy)
        if complete:
            value=audit(capture.directory)
            (capture.directory/'stage-partition.json').write_text(json.dumps(value,indent=2))
            (capture.directory/'atomic-groups.json').write_text(json.dumps(atomic_groups(capture.directory),indent=2))
            if not value['passed']:raise ValueError('INVALID: stage partition audit failed: '+str(value['errors'][:5]))
        return receipt

    def _handle(self,callback,*args):
        if self.stage_capture is None:return self._captured_handle_body(callback,*args)
        b=self.stage_boundaries;name=callback.__name__;job=None;block='';size=-1
        if name=='_receive':
            job=self.pool.running[args[0]];family=F['completion_'+job.job_class];stage=S['poll']
        elif name=='_admission':job_id='admission:'+str(args[0]);family=F['arrival'];stage=S['arrival_pre']
        elif name=='_block':block=args[1]['block_id'];size=len(args[2]);family=F['block_arrival'];stage=S['block_build']
        else:family=F['loop'];stage=S['loop']
        jid=self.stage_capture.job_ids[job.job_id] if job else (self.stage_capture.job_ids[job_id] if name=='_admission' else -1)
        bid=self.stage_capture.block_ids.get(job.block_id if job else block,-1)
        if job and job.block_id:size=len(self.block_transactions[job.block_id])
        begin=time.monotonic_ns();b.begin(begin,family,stage,jid,bid,args[0] if name=='_receive' else -1,size)
        b.record(begin,E['release'])
        try:return self._captured_handle_body(callback,*args)
        finally:b.end(time.monotonic_ns())

    def _captured_handle_body(self,callback,*args):
        return super()._handle(callback,*args)

    def _view(self):
        if self.stage_capture is not None and self.stage_boundaries.depth:
            self.stage_boundaries.begin(time.monotonic_ns(),F['send'],S['send_pre'])
        return super()._view()

    def _dispatch(self):
        depth=self.stage_boundaries.depth if self.stage_capture is not None else 0
        if depth and self.stage_boundaries.families[depth-1] in (F['completion_admission'],F['completion_block_tx'],F['completion_block_sig']):
            now=time.monotonic_ns();self.stage_boundaries.record(now,E['group_end']);self.stage_boundaries.change(now,S['complete_tail'])
        try:return super()._dispatch()
        finally:
            if self.stage_capture is not None:
                while self.stage_boundaries.depth>depth:self.stage_boundaries.end(time.monotonic_ns())

    def _start(self,job,worker):
        b=self.stage_boundaries if self.stage_capture is not None else None
        if b and b.depth and b.families[b.depth-1]==F['send']:
            i=b.depth-1;b.jobs[i]=self.stage_capture.job_ids[job.job_id];b.blocks[i]=self.stage_capture.block_ids.get(job.block_id,-1);b.workers[i]=worker
            b.record(time.monotonic_ns(),E['bind'])
        try:return super()._start(job,worker)
        finally:
            if b and b.depth and b.families[b.depth-1]==F['send']:b.end(time.monotonic_ns())

    def capture_send(self,job,worker,t):
        if self.stage_capture is not None:
            b=self.stage_boundaries;b.record(t,E['send'],self.stage_capture.job_ids[job.job_id],worker=worker);b.change(t,S['send_tail'])

    def capture_pipe_return(self,t):
        if self.stage_capture is not None:self.stage_boundaries.record(t,E['pipe_return'])

    def _lookup(self,cache,job,negative=False):
        b=self.stage_boundaries if self.stage_capture is not None else None
        is_block=b and b.depth and b.families[b.depth-1]==F['block_arrival']
        if is_block:b.change(time.monotonic_ns(),S['block_lookups'])
        result=super()._lookup(cache,job,negative)
        if is_block:b.record(time.monotonic_ns(),E['lookup'],self.stage_capture.job_ids[job.job_id],branch=int(result is not None))
        return result

    def _block_ready(self,*args):
        try:return super()._block_ready(*args)
        finally:
            if self.stage_capture is not None and self.stage_boundaries.depth:
                self.stage_boundaries.record(time.monotonic_ns(),E['group_end'])
                self.stage_boundaries.change(time.monotonic_ns(),S['block_tail'])

    def _insert_cache(self,job,valid):
        if self.stage_capture is not None:self.stage_boundaries.record(time.monotonic_ns(),E['proof'],self.stage_capture.job_ids[job.job_id])
        return super()._insert_cache(job,valid)

    def _decide_block(self,bid):
        b=self.stage_boundaries if self.stage_capture is not None else None
        if b:
            now=time.monotonic_ns();b.record(now,E['group_end']);b.begin(now,F['acceptance'],S['block_accept'],
                block=self.stage_capture.block_ids[bid],size=len(self.block_transactions[bid]))
        try:return super()._decide_block(bid)
        finally:
            if b:b.end(time.monotonic_ns())

    def _admit_state(self,job):
        result=super()._admit_state(job)
        if self.stage_capture is not None and self.stage_boundaries.depth:
            b=self.stage_boundaries
            if b.families[b.depth-1]==F['arrival']:b.change(time.monotonic_ns(),S['arrival_tail'])
        return result

    def _log(self,event,job=None,block_id='',**extra):
        # Use original event timestamps; no extra observation clock drives Model.
        super()._log(event,job,block_id,**extra)
        if self.stage_capture is None or not self.stage_boundaries.depth:return
        b=self.stage_boundaries;now=round(self.t*1e9)+self.epoch
        jid=self.stage_capture.job_ids[job.job_id] if job else -1
        bid=self.stage_capture.block_ids.get(job.block_id if job else block_id,-1)
        if event=='end':b.record(now,E['receive'],jid,bid,job.worker_id);b.change(now,S['complete_'+job.job_class])
        elif event=='enqueue':
            b.record(now,E['enqueue'],jid,bid)
            if b.families[b.depth-1]==F['arrival']:b.change(now,S['arrival_tail'])
        elif event in ('cache_hit','cache_miss','cache_insert','cache_evict'):b.record(now,E['cache'],jid,bid)
        elif event.startswith('pool_'):b.record(now,E['pool'],jid,bid)
        elif event=='struct_reject':b.record(now,E['group_end'],jid,bid,branch=1)
        elif event in ('block_accept','block_reject'):
            b.record(now,E['decision'],jid,bid,branch=int(event=='block_reject'));b.change(now,S['block_accept_tail'])

    def capture_interval(self,start,end,family):
        if self.stage_capture is not None:
            self.stage_capture.idle_interval(start,end,family)

def measure_cost(directory,n=2000):
    """Dedicated report-only append benchmark, before GC/window entry."""
    import statistics
    path=Path(directory)/'stage-cost-probe';r=Recorder(path,n,dict(purpose='overhead-probe'));values=[]
    try:
        for i in range(n):
            start=time.monotonic_ns();r.append(start,E['release'],F['loop']);values.append(time.monotonic_ns()-start)
    finally:r.finish(False)
    ordered=sorted(values)
    return dict(count=n,mean_ns=statistics.fmean(values),p50_ns=statistics.median(values),p95_ns=ordered[(95*n-1)//100],
        p99_ns=ordered[(99*n-1)//100],max_ns=max(values),host_load='NOT CONTROLLED',report_only=True,
        is_overhead_estimate=any(values),
        clock_note='non-advancing/fake-clock benchmark is not an overhead estimate' if not any(values) else 'local measurement; target ARM overhead measured in Phase F')


def atomic_groups(directory,include_samples=False):
    """Report-only spreads; no threshold and no influence on model/rules.

    Completion proof/cache/pool group ends at its explicit group_end marker.
    The final tx/sig pair is identified from the captured job catalog, not from
    temporal proximity. Inline sends are counted from nested send milestones.
    """
    import math,statistics
    spec=json.loads((Path(directory)/'stages.json').read_text());jobs=spec['jobs']
    active={};samples={};inline={}
    for r in rows(directory):
        t,event,family,stage,callback,parent,job,*_=r
        if event==E['idle_interval']:continue
        if event==E['callback_entry']:active[callback]=[family,[],[],[],[]]
        data=active.get(callback)
        if data is None:raise ValueError('milestone outside callback')
        if event==E['enqueue']:data[1].append((t,job))
        if event in (E['proof'],E['cache'],E['pool']):data[2].append(t)
        if event==E['group_end']:data[3].append(t)
        if event==E['send']:
            for ancestor in active.values():ancestor[4].append(t)
        if event!=E['callback_exit']:continue
        del active[callback];name=None;start=end=None
        if family==F['block_arrival'] and len(data[1])>=2:
            a,b=data[1][-2:]
            if a[1]<len(jobs) and b[1]<len(jobs) and ':tx:' in jobs[a[1]] and jobs[b[1]].endswith(':sig'):
                name='final_block_tx_block_sig_enqueue';start,end=a[0],b[0]
        elif family in (F['completion_admission'],F['completion_block_tx'],F['completion_block_sig']) and data[2] and data[3]:
            name=FAMILIES[family]+'_publication';start=data[2][0];end=data[3][0]
        if name is not None:
            if end<start:raise ValueError('negative atomic group spread')
            samples.setdefault(name,[]).append(end-start)
            inline[name]=inline.get(name,0)+sum(start<s<end for s in data[4])
    result={}
    for name,values in samples.items():
        v=sorted(values);n=len(v)
        result[name]=dict(count=n,mean_ns=statistics.fmean(v),p50_ns=statistics.median(v),
            p95_ns=v[math.ceil(.95*n)-1],max_ns=v[-1],inline_sends=inline[name])
        if include_samples:result[name]['samples_ns']=v
    return dict(schema='paper2-atomic-group-report-v1',context=spec['context'],groups=result,
        mapping='exclusive cost before final milestone; intermediate milestones may shift later',
        report_only=True,threshold=None,affects_rules=False)
