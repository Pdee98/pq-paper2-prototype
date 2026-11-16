"""Independent literal-dispatcher evidence replay. No model/state/policy imports.

Checks exclusive work against input costs, then replays resource ownership and
publication dependencies in event sequence order. Busy labels alone are not proof.
"""
import collections
import hashlib
import json
import math
import heapq
from bisect import bisect_right
from pathlib import Path
import tempfile
import itertools
from .streaming import RowStates


class Delta:
    """A block-local overlay; committing touches only that block's accounts."""
    def __init__(self,base):self.base=base;self.changed={}
    def get(self,key,default=None):return self.changed.get(key,self.base.get(key,default))
    def __setitem__(self,key,value):self.changed[key]=value
    def setdefault(self,key,value):
        if key not in self.changed and key not in self.base:self.changed[key]=value
        return self.get(key)


def close(a, b):
    return a is not None and b is not None and math.isclose(a,b,rel_tol=0,abs_tol=1e-12)


class Replay:
    def __init__(self, rows, records, data):
        self.rows, self.jobs, self.data = rows, {j['job_id']:j for j in records}, data
        self.cfg = data['config']
        self.errors, self.proof_times = [], {}
        self.unavailable,self.owners=RowStates(self.cfg.get('k',1)),RowStates()
        self.block_specs={b['block_id']:b for b in self.cfg.get('blocks',[])}
        self.block_positions={b['block_id']:i for i,b in enumerate(self.cfg.get('blocks',[]))}
        self.tx_by_id={j['tx_id']:j['tx'] for j in records if j.get('tx')}
        self._obstruction_index=None
        self.leaves, self.h0 = [], []
        self.partition_valid = True

    def bad(self, code, message, **context):
        self.errors.append(dict(code='dispatcher_'+code,message=message,**context))

    def cost(self, s, ordinal):
        spec=self.cfg['dispatcher'];kind=s['kind'];bid=s['block_id'];jid=s['job_id']
        defaults=spec.get('costs',{})
        if kind.startswith('block_'):
            name=kind[6:]
            profile=spec.get('blocks',{}).get(bid,{})
            if name=='lookups':
                return profile['lookups'][ordinal] if 'lookups' in profile else defaults.get('block_lookup',0)
            return profile.get(name,defaults.get({'build':'block_build','tail':'block_tail'}.get(name,name),0))
        return spec.get('jobs',{}).get(jid,{}).get(kind,defaults.get(kind,0))

    def inspect_partition(self, evidence):
        callbacks=evidence['callbacks'];stages=evidence['stages']
        self.callbacks={c['id']:c for c in callbacks};self.stages={s['id']:s for s in stages}
        if len(self.callbacks)!=len(callbacks) or len(self.stages)!=len(stages):
            self.bad('partition','duplicate callback/stage identity')
        last=0
        for c in callbacks:
            a,b=c['start_t'],c['end_t']
            if not all(isinstance(v,(int,float)) and math.isfinite(v) for v in (a,b)) or a<last or b<a:
                self.bad('ownership','overlapping or negative callback',callback_id=c['id'])
            last=b
        by_parent=collections.defaultdict(list)
        for s in stages:by_parent[s['callback_id']].append(s)
        for parent,group in by_parent.items():
            c=self.callbacks.get(parent)
            if c is None:
                self.bad('partition','orphan stage',callback_id=parent);continue
            cursor=c['start_t'];lookup=0
            for s in group:
                a,b,d=s['start_t'],s['end_t'],s['duration']
                if not all(isinstance(v,(int,float)) and math.isfinite(v) and v>=0 for v in (a,b,d)):
                    self.bad('partition','negative/nonfinite stage',stage_id=s['id']);continue
                if not close(a,cursor) or not close(b-a,d) or b>c['end_t']+1e-12 or s['family']!=c['family']:
                    self.bad('partition','exclusive child gap/overlap/double count',stage_id=s['id'])
                cursor=b
                try:expected=self.cost(s,lookup)
                except (KeyError,IndexError):expected=None
                if not close(d,expected):self.bad('cost','stage cost differs from literal input',stage_id=s['id'])
                lookup+=s['kind']=='block_lookups'
                if d:self.leaves.append((a,b,s['id']))
            if not close(cursor,c['end_t']):self.bad('partition','parent has unaccounted work',callback_id=parent)
            kinds=[s['kind'] for s in group]
            # Remove only complete nested pairs; malformed sends cannot hide in
            # an outer parent span or be counted as extra dispatcher cores.
            reduced=[];i=0
            while i<len(kinds):
                if kinds[i] in ('send_pre','block_accept'):
                    tail='send_tail' if kinds[i]=='send_pre' else 'block_accept_tail'
                    if i+1>=len(kinds) or kinds[i+1]!=tail:
                        self.bad('causality','nested stage pair mismatch',callback_id=parent);i+=1
                    else:i+=2
                else:reduced.append(kinds[i]);i+=1
            family=c['family']
            if family=='arrival':expected=['arrival_pre','arrival_tail']
            elif family=='block_arrival':
                block=self.data['blocks'][c['identity']]
                n=0 if block['structurally_rejected'] else len(self.block_specs[c['identity']]['tx_ids'])
                expected=['block_build']+['block_lookups']*n+['block_tail']
            elif family.startswith('completion_'):expected=['complete_'+family[11:],'complete_tail']
            elif family.startswith('fixture_') and family in self.data.get('dispatcher',{}).get('fixture_callbacks',[]):expected=[]
            else:expected=None
            if reduced!=expected:self.bad('causality','callback stage grammar mismatch',callback_id=parent)
        for identity in set(self.callbacks)-set(by_parent):
            c=self.callbacks[identity]
            if c['family'] not in self.data.get('dispatcher',{}).get('fixture_callbacks',[]) or c['end_t']!=c['start_t']:
                self.bad('partition','callback missing every stage')
        self.leaves.sort()
        for x,y in zip(self.leaves,self.leaves[1:]):
            if x[1]>y[0]+1e-12:self.bad('ownership','two exclusive stages overlap')
        self.partition_valid=not self.errors
        self.leaf_starts=[x[0] for x in self.leaves]

    def covered(self,a,b):
        if not self.partition_valid or b<=a:return b==a
        i=bisect_right(self.leaf_starts,a)-1
        return i>=0 and self.leaves[i][0]<=a and self.leaves[i][1]>=b-1e-12

    def obstruction(self,a,b,records,k):
        """Validated control time with a physically idle eligible block worker.

        This excludes overlap with all eligible workers' physical service, so
        the H0 residual/service term and dispatcher obstruction are disjoint.
        """
        ka=self.cfg.get('policy',{}).get('k_a',self.cfg.get('k_a',0)) or 0
        eligible=range(ka,k) if self.cfg.get('policy',{}).get('name')=='static_split' else range(k)
        if not self.partition_valid:return 0
        if self._obstruction_index is None:
            points=collections.defaultdict(lambda:[0,0])
            for j in records:
                if j['start_t'] is not None and j['worker_id'] in eligible:
                    points[j['start_t']][0]+=1;points[j['end_t']][0]-=1
            for x,y,_ in self.leaves:points[x][1]+=1;points[y][1]-=1
            times=sorted(points);area=[];slopes=[];running=control=0;total=0.0;previous=times[0] if times else 0
            for t in times:
                total+=(t-previous)*int(control>0 and running<len(eligible));area.append(total)
                running+=points[t][0];control+=points[t][1]
                slopes.append(int(control>0 and running<len(eligible)));previous=t
            self._obstruction_index=times,area,slopes
        times,area,slopes=self._obstruction_index
        def cumulative(t):
            i=bisect_right(times,t)-1
            return 0 if i<0 else area[i]+(t-times[i])*slopes[i]
        return cumulative(b)-cumulative(a)

    def run(self,evidence):
        self.inspect_partition(evidence)
        jobs=self.jobs;cfg=self.cfg
        owner=stage=None
        reserved={};pending={};running={};selected={};published={};cache={}
        callbacks_seen=collections.Counter();stage_seen=collections.Counter();completion=collections.Counter()
        checked=collections.defaultdict(set);triggers={};decisions={};last_complete=None
        stage_milestones={};cache_hits=set();state_checked=set();enqueue_seen=set()
        balances=dict(cfg['genesis']['balances']);nonces=dict(cfg['genesis']['next_nonces']);pool={}
        accepted_ids=set();nonce_pool=collections.defaultdict(set);tx_pool=collections.defaultdict(set)
        def remove_pool(key):
            tx=pool.pop(key,None)
            if tx:
                nonce_pool[tx['sender'],tx['nonce']].discard(key);tx_pool[tx['tx_id']].discard(key)
        def insert_pool(key,tx):
            remove_pool(key);pool[key]=tx
            nonce_pool[tx['sender'],tx['nonce']].add(key);tx_pool[tx['tx_id']].add(key)
        admission_receipts=[]
        send_order={r['job_id']:i for i,r in enumerate(self.rows) if r['event']=='start'}
        completions={c['identity']:c for c in self.callbacks.values() if c['family'].startswith('completion_')}
        release_order=sorted((c for c in self.callbacks.values() if not c['family'].startswith('completion_')),
                             key=lambda c:(c['release_t'],c['id']))
        release_cursor=0;ready=[]
        expected_checks=collections.defaultdict(set);source_checks=collections.defaultdict(list)
        for j in jobs.values():
            if j['block_id'] and not j['admission_origin']:
                expected_checks[j['block_id']].add(j['job_id'])
                source=j['proof_job_id'] if j['status']=='coalesced' else j['job_id']
                source_checks[j['block_id'],source].append(j['job_id'])
        initial=self.data.get('dispatcher',{}).get('prepared_jobs',{})
        # Prepared resource fixtures must explicitly declare absent enqueue rows;
        # ordinary production traces have no such exception.
        for jid,t in initial.items():
            if jid not in jobs or not close(jobs[jid]['enqueue_t'],t):self.bad('prepared','invalid prepared enqueue',job_id=jid)
        for i,row in enumerate(self.rows):
            t=float(row['t']);ev=row['event'];jid=row['job_id'];bid=row['block_id']
            while release_cursor<len(release_order) and release_order[release_cursor]['release_t']<=t:
                c=release_order[release_cursor];release_cursor+=1
                comp=c['family'].startswith('completion_')
                heapq.heappush(ready,(0 if comp else 2,c['release_t'],send_order.get(c['identity'],-1) if comp else c['id'],c['id']))
            if ev.startswith('dispatcher_'):
                r=json.loads(row['detail']);kind=r['event']
                if ev!='dispatcher_'+kind or not close(r['t'],t):self.bad('mirror','control detail disagrees with event',row=i)
                if kind=='callback_start':
                    c=self.callbacks.get(r['id'])
                    if owner is not None or c is None or not close(c['start_t'],t):self.bad('ownership','invalid callback start',row=i)
                    owner=r['id'];callbacks_seen[owner,'start']+=1
                    if not ready or heapq.heappop(ready)[-1]!=owner:self.bad('priority','callback bypassed released work',row=i)
                    if c:
                        family=c['family'];identity=c['identity'];release=c['release_t']
                        if family=='arrival':release=cfg['admissions'][int(identity.split(':')[1])]['arrival_t']
                        elif family=='block_arrival':
                            ix=self.block_positions[identity]
                            release=cfg['block_times'][ix] if cfg.get('block_times') is not None else cfg.get('block_start',0)+ix*cfg.get('block_period',1)
                        elif family.startswith('completion_'):
                            j=jobs.get(identity,{})
                            release=j.get('end_t')
                            if identity not in pending.values() or family!='completion_'+j.get('job_class',''):
                                self.bad('completion','completion family/worker dependency mismatch',row=i)
                        elif not family.startswith('fixture_'):self.bad('causality','unknown callback family',row=i)
                        if not close(release,c['release_t']) or t<release:self.bad('release','callback release mismatch',row=i)
                elif kind=='callback_end':
                    if owner!=r['id'] or stage is not None:self.bad('ownership','invalid callback end',row=i)
                    if not close(self.callbacks[r['id']]['end_t'],t):self.bad('mirror','callback endpoint mismatch',row=i)
                    callbacks_seen[r['id'],'end']+=1;owner=None
                elif kind in ('stage_start','stage_end'):
                    s=self.stages.get(r['id'])
                    if s is None or owner!=s['callback_id']:self.bad('causality','stage outside owner',row=i)
                    else:
                        for key in ('callback_id','kind','job_id','block_id','duration','family','start_t'):
                            if r[key]!=s[key]:self.bad('mirror','stage log differs from dispatcher file',row=i,field=key)
                        if kind=='stage_start':
                            if stage is not None or not close(s['start_t'],t):self.bad('ownership','overlapping stage starts',row=i)
                            stage=s['id']
                        else:
                            if stage!=s['id'] or not close(s['end_t'],t):self.bad('causality','stage ends without ownership',row=i)
                            stage=None;stage_milestones[s['kind'],s['job_id'],s['block_id']]=t
                            if s['kind'].startswith('complete_') and s['kind']!='complete_tail':
                                self.proof_times[s['job_id']]=t;last_complete=s['job_id']
                    stage_seen[r['id'],kind]+=1
                elif kind=='reserve':
                    w=r['worker_id'];j=r['job_id']
                    if not 0<=w<cfg['k'] or w in running or w in pending or w in reserved or j not in selected:
                        self.bad('reservation','reservation collision or missing selection',row=i)
                    reserved[w]=j
                elif kind=='receive_pending':
                    if pending.get(r['worker_id'])!=r['job_id']:self.bad('completion','receive without physical end',row=i)
                elif kind=='completion_commit':
                    w=r['worker_id'];j=r['job_id'];completion[j]+=1
                    if pending.get(w)!=j or j not in self.proof_times:self.bad('completion','commit without required completion stage',row=i)
                    pending.pop(w,None)
                elif kind=='block_check_complete':
                    b=r['block_id'];j=r['job_id'];source=r['source_job_id']
                    logical=[j] if r['via']=='cache' else source_checks[b,source]
                    if len(logical)!=1 or logical[0] in checked[b] or logical[0] not in expected_checks[b]:
                        self.bad('decrement','logical block check decremented twice or wrong source',row=i)
                    else:
                        lj=jobs[logical[0]]
                        if r['via']=='cache':
                            if logical[0] not in cache_hits or source not in published or published[source]>t:
                                self.bad('proof','cache decrement lacks completed proof',row=i)
                        elif source!=last_complete or source not in self.proof_times:
                            self.bad('decrement','decrement outside its completion milestone',row=i)
                        checked[b].add(logical[0])
                    if r['remaining']!=len(expected_checks[b]-checked[b]):self.bad('decrement','remaining count mismatch',row=i)
                elif kind=='acceptance_trigger':
                    b=r['block_id'];j=r['job_id']
                    if b in triggers or checked[b]!=expected_checks[b] or j!=last_complete or r['job_class']!=jobs[j]['job_class']:
                        self.bad('acceptance','premature/duplicate/wrong-class acceptance trigger',row=i)
                    triggers[b]=j
                elif kind=='admission_state_commit':
                    j=r['job_id'];tx=jobs[j]['tx'];key=jobs[j]['cache_key']
                    reason=('already_included' if tx['tx_id'] in accepted_ids else
                            'stale_nonce' if tx['nonce']<nonces.get(tx['sender'],0) else
                            'pool_nonce_duplicate' if nonce_pool[tx['sender'],tx['nonce']]-{key} else
                            'insufficient_balance' if balances.get(tx['sender'],0)<tx['amount']+tx['fee_rate']*tx['size_bytes'] else None)
                    cache_path=j in cache_hits and close(stage_milestones.get(('arrival_pre',j,'')),t)
                    if (not cache_path and not close(self.proof_times.get(j),t)) or r['reason']!=reason or r['passed']!=(reason is None):
                        self.bad('state','admission state transition differs from replay',row=i)
                    admission_receipts.append(dict(job_id=j,key=key,t=t,passed=r['passed'],reason=r['reason']))
                if sorted(reserved)!=r['reserved_workers'] or sorted(pending)!=r['completion_pending_workers']:
                    self.bad('reservation','logged control-worker snapshot differs from replay',row=i)
            elif ev=='dispatch' and row['chosen_job_id']:
                selected[row['chosen_job_id']]=t
            elif ev=='enqueue':enqueue_seen.add(jid)
            elif ev=='start':
                w=int(row['worker_id'])
                prepared=jid in initial and jid not in selected
                if w in running or w in pending or (reserved.get(w)!=jid and not prepared):self.bad('prefetch','start before worker control release/reservation',row=i)
                if not prepared and not close(stage_milestones.get(('send_pre',jid,'')),t) and not close(stage_milestones.get(('send_pre',jid,jobs[jid]['block_id'])),t):
                    self.bad('causality','start outside send milestone',row=i)
                if jid not in enqueue_seen and not prepared:self.bad('causality','start before enqueue',row=i)
                reserved.pop(w,None);selected.pop(jid,None);running[w]=jid
            elif ev=='end':
                w=int(row['worker_id'])
                if running.get(w)!=jid:self.bad('prefetch','receive without running owner',row=i)
                running.pop(w,None);pending[w]=jid
                # Equal timestamps do not imply that a future end has happened.
                # Source receive must already exist in event-sequence order.
                if jid in completions:
                    c=completions[jid]
                    heapq.heappush(ready,(0,c['release_t'],send_order[jid],c['id']))
            elif ev=='cache_insert':
                if not close(self.proof_times.get(jid),t):self.bad('publication','cache published before completion milestone',row=i)
                if row['detail']=='positive':
                    if jobs[jid]['outcome']!='valid':self.bad('proof','invalid result published positively',row=i)
                    published[jid]=t;cache[row['cache_key']]=t
            elif ev=='cache_evict' and row['detail'].startswith('positive:'):cache.pop(row['cache_key'],None)
            elif ev=='cache_hit':
                key=row['cache_key'];ttl=cfg.get('cache',{}).get('ttl')
                if key not in cache or (ttl is not None and t>=cache[key]+ttl):self.bad('publication','hit before publication/after TTL',row=i)
                cache_hits.add(jid)
            elif ev=='pool_insert':
                from_cache=jid in cache_hits and close(stage_milestones.get(('arrival_pre',jid,'')),t)
                if not from_cache and not close(self.proof_times.get(jid),t):self.bad('publication','pool published before completion milestone',row=i)
                insert_pool(row['cache_key'],jobs[jid]['tx'])
            elif ev=='pool_evict':remove_pool(row['cache_key'])
            elif ev=='state_check':
                if bid not in triggers or not close(stage_milestones.get(('block_accept','',bid)),t):self.bad('state','state checks outside acceptance milestone',row=i)
                state_checked.add(bid)
            elif ev in ('block_accept','block_reject'):
                structural=self.data['blocks'][bid]['structurally_rejected']
                if bid in decisions:self.bad('acceptance','duplicate block decision',row=i)
                if not structural and (bid not in triggers or bid not in state_checked or checked[bid]!=expected_checks[bid]
                                       or not close(stage_milestones.get(('block_accept','',bid)),t)):
                    self.bad('acceptance','decision before required checks',row=i)
                if not structural:
                    tx_by_id=self.tx_by_id;spec=self.block_specs[bid]
                    trial_b=Delta(balances);trial_n=Delta(nonces);checks=[]
                    for tx_id in spec['tx_ids']:
                        tx=tx_by_id[tx_id];s=tx['sender'];r=tx['receiver'];debit=tx['amount']+tx['fee_rate']*tx['size_bytes']
                        reason='nonce' if tx['nonce']!=trial_n.get(s,0) else 'insufficient_balance' if trial_b.get(s,0)<debit else None
                        checks.append(dict(tx_id=tx_id,passed=reason is None,reason=reason))
                        if reason is None:
                            trial_b[s]=trial_b.get(s,0)-debit;trial_b[r]=trial_b.get(r,0)+tx['amount']
                            trial_n[s]=tx['nonce']+1;trial_n.setdefault(r,0)
                    invalid=any(jobs[jobs[j]['proof_job_id']]['outcome']!='valid' if jobs[j]['status']=='coalesced' else jobs[j]['outcome']!='valid'
                        for j in expected_checks[bid] if jobs[j]['status']!='cache_hit')
                    reasons=(['invalid_signature'] if invalid else [])+(['state'] if any(not c['passed'] for c in checks) else [])
                    b=self.data['blocks'][bid]
                    if b['state_checks']!=checks or b['reject_reasons']!=';'.join(reasons) or (ev=='block_accept')!= (not reasons):
                        self.bad('state','block decision/checks differ from atomic ledger replay',row=i)
                    if ev=='block_accept':
                        balances.update(trial_b.changed);nonces.update(trial_n.changed)
                        for tx_id in spec['tx_ids']:
                            for key in tuple(tx_pool[tx_id]):remove_pool(key)
                if self.data['blocks'][bid]['valid']:accepted_ids.update(self.block_specs[bid]['tx_ids'])
                decisions[bid]=t
            self.unavailable[i]=frozenset(reserved)|frozenset(pending)
            self.owners[i]=owner
            if i+1<len(self.rows) and float(self.rows[i+1]['t'])!=t:
                next_t=float(self.rows[i+1]['t'])
                if owner is None and ready:self.bad('work_conservation','dispatcher idle with released callback',t=t)
                if owner is not None and not self.covered(t,next_t):self.bad('partition','active callback not explained by exclusive cost',t=t)
        for c in self.callbacks:
            if callbacks_seen[c,'start']!=1 or callbacks_seen[c,'end']!=1:self.bad('single_callback','callback start/end not unique',callback_id=c)
        for s in self.stages:
            if stage_seen[s,'stage_start']!=1 or stage_seen[s,'stage_end']!=1:self.bad('partition','stage start/end not unique',stage_id=s)
        for j in jobs.values():
            if j['start_t'] is not None and completion[j['job_id']]!=1:self.bad('completion','physical completion not exactly once',job_id=j['job_id'])
        for proof in self.data['verification_history']:
            j=jobs.get(proof['job_id'])
            if j is None or j['outcome']!='valid' or not close(self.proof_times.get(j['job_id']),proof['t']):
                self.bad('proof','proof history outside successful completion',job_id=proof['job_id'])
        if admission_receipts!=self.data['admission_checks']:self.bad('state','admission receipt/event mismatch')
        if owner is not None or stage is not None or pending or reserved or running or selected:self.bad('unfinished','unfinished control work')


def inspect(rows,records,data,manifest):
    replay=Replay(rows,records,data)
    try:
        from src.paper2.artifact_stream import read_arrays
        spec=data['dispatcher']['evidence'];path=Path(manifest).parent/spec['path'];digest=hashlib.sha256()
        with path.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=spec['sha256']:replay.bad('digest','dispatcher evidence digest mismatch')
        with tempfile.TemporaryDirectory(prefix='dispatcher-read-') as temp:
            evidence=read_arrays(path,temp)
            try:
                if evidence['schema']!='paper2-dispatcher-literal-v1':replay.bad('schema','unsupported dispatcher schema')
                controls=(json.loads(r['detail']) for r in rows if r['event'].startswith('dispatcher_'))
                sentinel=object()
                if any(a!=b for a,b in itertools.zip_longest(controls,evidence['transitions'],fillvalue=sentinel)):
                    replay.bad('mirror','dispatcher event/file transitions differ')
                replay.run(evidence)
            finally:
                for value in evidence.values():
                    if hasattr(value,'close'):value.close()
    except (KeyError,ValueError,TypeError,IndexError,OSError) as exc:
        replay.bad('evidence','malformed dispatcher evidence: '+str(exc))
    return replay
