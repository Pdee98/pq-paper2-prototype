"""Deviation-5 validity from queue counters and physical start/end evidence.

This guard is separate from G3 agreement and from the invariant checker.
No model, worker, policy or queue state is consulted.
"""

import csv
import heapq
import math
from pathlib import Path

IDLE_LIMIT=.05
GAP_LIMIT_NS=1_000_000


class Validity:
    def __init__(self,k,mode="shared",k_a=None,window=(30,90)):
        self.k,self.mode,self.k_a=k,mode,k_a
        self.left,self.right=window
        if k<1 or self.right<=self.left:raise ValueError("positive workers/window required")
        self.previous=0.;self.qa=self.qb=self.busy=0;self.running={}
        self.idle=0.;self.low=[];self.high=[];self.n=0;self.pending={}

    def _free_eligible(self):
        if self.mode=="shared":return self.k-self.busy if self.qa+self.qb>0 else 0
        free_a=sum(w not in self.running for w in range(self.k_a))
        free_b=sum(w not in self.running for w in range(self.k_a,self.k))
        return (free_a if self.qa else 0)+(free_b if self.qb else 0)

    def _waiting_for(self,worker):
        return self.qa+self.qb>0 if self.mode=="shared" else (self.qa>0 if worker<self.k_a else self.qb>0)

    def _gap(self,value):
        if value<0:raise ValueError("negative dispatch gap")
        self.n+=1
        if not self.low or value<=-self.low[0]:heapq.heappush(self.low,-value)
        else:heapq.heappush(self.high,value)
        target=math.ceil(.99*self.n)
        while len(self.low)>target:heapq.heappush(self.high,-heapq.heappop(self.low))
        while len(self.low)<target:heapq.heappush(self.low,-heapq.heappop(self.high))

    def observe(self,t,event,qa,qb,busy,worker=None,send_ns=None,receive_ns=None):
        if t<self.previous:raise ValueError("nonmonotone validity evidence")
        duration=max(0,min(t,self.right)-max(self.previous,self.left))
        self.idle+=duration*self._free_eligible()
        self.previous=t;self.qa,self.qb,self.busy=qa,qb,busy
        if event=="start":
            prior=self.pending.pop(worker,None)
            if prior is not None:self._gap(send_ns-prior)
            self.running[worker]=True
        elif event=="end":
            self.running.pop(worker,None)
            if self.left<=t<self.right and self._waiting_for(worker):self.pending[worker]=receive_ns

    def report(self,now,final=False):
        idle=self.idle+max(0,min(now,self.right)-max(self.previous,self.left))*self._free_eligible()
        worker_time=self.k*(self.right-self.left)
        share=idle/worker_time;p99=-self.low[0] if self.low else None
        censored=len(self.pending) if final else 0
        passed=(share<=IDLE_LIMIT and (p99<=GAP_LIMIT_NS if p99 is not None else idle==0) and not censored)
        return dict(window=[self.left,self.right],worker_time_seconds=worker_time,
            idle_while_waiting_worker_seconds=idle,idle_fraction=share,idle_limit=IDLE_LIMIT,
            dispatch_gap_count=self.n,p99_dispatch_gap_ns=p99,gap_limit_ns=GAP_LIMIT_NS,
            pending_gap_count=len(self.pending),censored_gaps=censored,final=final,
            passed=passed,status=("VALID" if passed else "INVALID") if final else "PROVISIONAL")


def from_events(path,config,window=(30,90)):
    v=Validity(config["k"],config.get("pool_mode","shared"),config.get("k_a"),window)
    with Path(path).open(newline="",encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            event=row["event"];worker=int(row["worker_id"]) if event in ("start","end") else None
            v.observe(float(row["t"]),event,int(row["q_admission"]),int(row["q_block"]),
                int(row["busy_workers"]),worker,
                int(row["send_ns"]) if event=="start" else None,
                int(row["receive_ns"]) if event=="end" else None)
    return v.report(max(v.previous,window[1]),final=True)
