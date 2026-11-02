"""Indexed waiting queues and an incremental integral of observed worker time."""

import heapq
import itertools
from collections import OrderedDict, deque


class WaitingIndex:
    def __init__(self):
        self.items = OrderedDict()
        self.sequence = {}
        self.serial = itertools.count()
        self.heaps = {c: [] for c in ("admission", "block_tx", "block_sig")}
        self.fees = []

    def __bool__(self):
        return bool(self.items)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items.values())

    def append(self, job):
        self.items[job.job_id] = job
        self.sequence[job.job_id] = next(self.serial)
        self.index(job)

    def index(self, job):
        order = self.sequence[job.job_id]
        heapq.heappush(self.heaps[job.job_class], (job.enqueue_t, order, job.job_id))
        if job.job_class == "admission":
            heapq.heappush(self.fees, (-job.tx["fee_rate"], job.enqueue_t, order, job.job_id))

    def remove(self, job):
        del self.items[job.job_id]

    def head(self, cls, fee=False):
        heap = self.fees if fee else self.heaps[cls]
        while heap:
            jid = heap[0][-1]
            job = self.items.get(jid)
            if job is not None and job.job_class == cls:
                return job
            heapq.heappop(heap)
        return None


class BlockIndex:
    def __init__(self):
        self.waiting = {}
        self.counts = dict(admission=0, block_tx=0, block_sig=0)
        self.heads = []
        self.running = {}

    def enqueue(self, job, sequence):
        self.waiting[job.job_id] = job
        self.counts[job.job_class] += 1
        heapq.heappush(self.heads, (job.enqueue_t, sequence, job.job_id))

    def start(self, job):
        if self.waiting.pop(job.job_id, None) is not None:
            self.counts[job.job_class] -= 1
        self.running[job.job_id] = job

    def end(self, job):
        self.running.pop(job.job_id, None)

    def head(self):
        while self.heads and self.heads[0][-1] not in self.waiting:
            heapq.heappop(self.heads)
        return self.waiting[self.heads[0][-1]] if self.heads else None


class BusyWindow:
    """Piecewise linear cumulative observed busy-time; amortized O(1) expiry."""

    def __init__(self, width):
        self.width = width
        self.points = deque([(0.0, 0.0, 0.0, 0, 0)])

    def change(self, now, admission_delta, total_delta):
        t, a, total, ra, rt = self.points[-1]
        point = (now, a + (now-t)*ra, total + (now-t)*rt,
                 ra + admission_delta, rt + total_delta)
        if t == now:
            self.points[-1] = point
        else:
            self.points.append(point)

    def totals(self, now):
        lower = max(0.0, now-self.width)
        while len(self.points) > 1 and self.points[1][0] <= lower:
            self.points.popleft()
        t, a, total, ra, rt = self.points[0]
        lower_a, lower_total = a+(lower-t)*ra, total+(lower-t)*rt
        t, a, total, ra, rt = self.points[-1]
        return (max(0.0, a+(now-t)*ra-lower_a), max(0.0, total+(now-t)*rt-lower_total))
