"""Online observations; no event rows or per-job output are retained here."""

from bisect import bisect_right
from collections import Counter
import math

CLASSES = ("admission", "block_tx", "block_sig")
QUEUES = (*CLASSES, "block")


class OnlineSummary:
    def __init__(self, config):
        spec = config.get("summary", {})
        if set(spec)-{"histogram_edges", "window_width", "analysis_window"}:
            raise ValueError("unknown summary option")
        self.edges = spec.get("histogram_edges", [0, .00001, .0001, .001, .01, .1, 1, 10])
        if (not self.edges or self.edges[0] != 0 or any(not math.isfinite(x) for x in self.edges)
                or any(a >= b for a,b in zip(self.edges,self.edges[1:]))):
            raise ValueError("histogram edges must start at zero and strictly increase")
        self.width = spec.get("window_width", 1)
        if not math.isfinite(self.width) or self.width <= 0:
            raise ValueError("summary window width must be positive")
        self.window = spec.get("analysis_window")
        if self.window is not None and (len(self.window)!=2 or not 0 <= self.window[0] < self.window[1]
                or not all(math.isfinite(x) for x in self.window)):
            raise ValueError("invalid analysis window")
        self.last = 0.0
        self.q = dict.fromkeys(QUEUES, 0)
        self.area = dict.fromkeys(QUEUES, 0.0)
        self.maxima = dict.fromkeys(QUEUES, 0)
        self.clipped = dict.fromkeys(QUEUES, 0.0)
        self.boundaries = {"start":None, "end":None}
        self.waits = {c:dict(count=0,sum=0.0,sum_squares=0.0,histogram=[0]*len(self.edges)) for c in CLASSES}
        self.cohort = {c:dict(enqueued=0,count=0,wait_sum=0.0) for c in CLASSES}
        self.busy = dict.fromkeys(CLASSES, 0.0)
        self.blocks, self.drops, self.cache, self.pool = {}, Counter(), Counter(), Counter()
        self.dispatches = self.accepted = self.event_count = 0
        self.samples = []
        self.next_sample = 0
        self.block_sizes = {b["block_id"]:len(b["tx_ids"]) for b in config.get("blocks",[])}

    def observe(self, t, event, counts, job, block_id, block, extra):
        dt = t-self.last
        for c in QUEUES:
            self.area[c] += dt*self.q[c]
        if self.window:
            lo,hi = self.window
            overlap = max(0,min(t,hi)-max(self.last,lo))
            for c in QUEUES:self.clipped[c] += overlap*self.q[c]
            for label,bound in (("start",lo),("end",hi)):
                if self.last <= bound < t and self.boundaries[label] is None:
                    self.boundaries[label] = dict(self.q)
        while self.next_sample*self.width < t:
            self.samples.append(dict(t=self.next_sample*self.width,queues=dict(self.q)))
            self.next_sample += 1
        self.q = dict(zip(CLASSES,counts))
        self.q["block"] = self.q["block_tx"]+self.q["block_sig"]
        for c in QUEUES:self.maxima[c] = max(self.maxima[c],self.q[c])
        if self.samples and self.samples[-1]["t"] == t:self.samples[-1]["queues"] = dict(self.q)
        if self.next_sample*self.width == t:
            self.samples.append(dict(t=t,queues=dict(self.q)));self.next_sample+=1
        if self.window:
            for label,bound in zip(("start","end"),self.window):
                if t == bound:self.boundaries[label] = dict(self.q)
        self.last=t;self.event_count+=1
        if event=="dispatch":self.dispatches+=1
        if event in ("drop","dup_drop","struct_reject","state_reject","neg_hit"):
            self.drops[event+":"+str(extra.get("detail",""))]+=1
        if event.startswith("cache_") or event=="neg_hit":self.cache[event]+=1
        if event.startswith("pool_"):self.pool[event]+=1
        if job and event=="enqueue" and self.window and self.window[0]<=t<=self.window[1]:
            self.cohort[job.job_class]["enqueued"]+=1
        if job and event=="end":
            cls=job.job_class;wait=job.start_t-job.enqueue_t
            stats=self.waits[cls];stats["count"]+=1;stats["sum"]+=wait;stats["sum_squares"]+=wait*wait
            stats["histogram"][bisect_right(self.edges,wait)-1]+=1
            self.busy[cls]+=t-job.start_t
            if self.window and self.window[0]<=job.enqueue_t<=self.window[1]:
                self.cohort[cls]["count"]+=1;self.cohort[cls]["wait_sum"]+=wait
        if event in ("block_accept","block_reject"):
            self.blocks[block_id]=dict(delay=t-block["arrival_t"],deadline_missed=t>block["deadline_t"],
                accepted=event=="block_accept")
            if event=="block_accept":self.accepted+=self.block_sizes[block_id]

    def finish(self):
        if self.window:
            lo,hi=self.window
            for c in QUEUES:self.clipped[c]+=max(0,hi-max(self.last,lo))*self.q[c]
            for label in self.boundaries:
                if self.boundaries[label] is None:self.boundaries[label]=dict(self.q)
        return dict(schema_version="paper2-summary-v1",histogram_edges=self.edges,window_width=self.width,
            end_t=self.last,event_count=self.event_count,waiting=self.waits,busy_time=self.busy,
            blocks=self.blocks,accepted_valid_tx_count=self.accepted,drops=dict(self.drops),
            cache_counters=dict(self.cache),pool_counters=dict(self.pool),dispatch_count=self.dispatches,
            queue_integrals=self.area,queue_maxima=self.maxima,queue_samples=self.samples,
            analysis=dict(window=self.window,queue_integrals=self.clipped,queue_boundaries=self.boundaries,
                          classes=self.cohort))
