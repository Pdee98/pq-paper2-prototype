"""Independent waiting-counter integrals, usable online or from full CSV rows."""

import csv
import json
import math
from pathlib import Path


class QueueCounterIntegral:
    """Observe post-event counters in seq order; same-time updates have zero area.

    This object never reads job start times or service intervals. A summary-mode
    sink can feed the same observed counters without writing an events CSV.
    """

    def __init__(self, warmup, horizon):
        if not 0 <= warmup < horizon:
            raise ValueError("require 0 <= warmup < horizon")
        self.warmup, self.horizon = warmup, horizon
        self.last_t = 0.0
        self.counts = dict(q_admission=0, q_block=0)
        self.areas = dict(q_admission=0.0, q_block=0.0)
        self.enqueued = {}

    def observe(self, t, q_admission, q_block, event="", job_class=""):
        if t < self.last_t or q_admission < 0 or q_block < 0:
            raise ValueError("nonmonotone time or negative queue counter")
        overlap = max(0, min(t, self.horizon) - max(self.last_t, self.warmup))
        for field in self.areas:
            self.areas[field] += self.counts[field] * overlap
        self.counts.update(q_admission=q_admission, q_block=q_block)
        self.last_t = t
        if event == "enqueue" and self.warmup <= t <= self.horizon:
            self.enqueued[job_class] = self.enqueued.get(job_class, 0) + 1

    def area(self, field):
        tail = max(0, self.horizon - max(self.last_t, self.warmup))
        return self.areas[field] + self.counts[field] * tail


def logged_counters(events_csv, warmup, horizon):
    integral = QueueCounterIntegral(warmup, horizon)
    with Path(events_csv).open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            integral.observe(float(row["t"]), int(row["q_admission"]), int(row["q_block"]),
                             row["event"], row["job_class"])
    return integral


def measure_replicate(events_csv, jobs_csv, warmup, horizon, classes):
    counters = logged_counters(events_csv, warmup, horizon)
    stats = {c: dict(n=0, wait=0.0, total_jobs=0) for c in classes}
    with Path(jobs_csv).open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            job = json.loads(row["record"])
            if job["job_class"] not in stats or job["status"] != "end":
                continue
            value = stats[job["job_class"]]
            value["total_jobs"] += 1
            if warmup <= job["enqueue_t"] <= horizon:
                value["n"] += 1
                value["wait"] += job["start_t"] - job["enqueue_t"]
    for cls, value in stats.items():
        n = counters.enqueued.get(cls, 0)
        if n != value["n"] or not n:
            raise ValueError("enqueued event count and completed job cohort disagree: " + cls)
        field = "q_admission" if cls == "admission" else "q_block"
        window = horizon - warmup
        L, rate, W = counters.area(field)/window, n/window, value["wait"]/n
        rhs = rate*W
        relative = abs(L-rhs)/rhs if rhs else (0.0 if L == 0 else math.inf)
        value.update(counter_field=field, counter_area=counters.area(field), enqueued_in_window=n,
                     mean_wait=W, mean_number_waiting=L, observed_arrival_rate=rate,
                     little_rhs=rhs, little_relative_error=relative)
    return stats


def legacy_interval_mean(jobs_csv, warmup, horizon, job_class):
    """Historical definition solely for comparison when re-evaluating old runs."""
    area = 0.0
    with Path(jobs_csv).open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            job = json.loads(row["record"])
            if job["job_class"] == job_class and job["status"] == "end":
                area += max(0, min(job["start_t"], horizon) - max(job["enqueue_t"], warmup))
    return area/(horizon-warmup)
