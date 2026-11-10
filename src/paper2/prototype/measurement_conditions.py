"""Deviation 8 author amendment: physical drain/load guards and dip diagnostics."""
import csv
import json
from pathlib import Path
from .analysis import read_jobs


def evaluate(records, spans, events, drain_receipt, incomplete, window=(30, 90), boundary=105):
    left, right = window
    # Union first: overlapping/nested spans must never count dispatcher time twice.
    merged = []
    for a, b in sorted((max(left, s['start_t']), min(right, s['end_t'])) for s in spans):
        if b <= a:
            continue
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    busy = sum(b-a for a, b in merged)/(right-left)
    pending = {c: dict(waiting=0, running=0) for c in ('admission', 'block_tx', 'block_sig')}
    for job in records:
        enqueued, start, end = (job.get(k) for k in ('enqueue_t', 'start_t', 'end_t'))
        if enqueued is None or enqueued > boundary or (end is not None and end <= boundary):
            continue
        # Cache hits/coalesced checks/tail drops are logical checks, not queued physical work.
        if job['status'] not in ('queued', 'running', 'end'):
            continue
        pending[job['job_class']]['running' if start is not None and start <= boundary else 'waiting'] += 1
    drained = bool(drain_receipt) and not incomplete and not any(sum(v.values()) for v in pending.values())
    bins = {s: [0, 0] for s in range(int(left), int(right))}
    for row in events:
        t = float(row['t'])
        if left <= t < right and row['job_class'] == 'block_tx' and row['event'] in ('cache_hit', 'cache_miss'):
            bins[int(t)][row['event'] == 'cache_miss'] += 1
    rates = {s: h/(h+m) for s, (h, m) in bins.items() if h+m}
    dips = [s for s, rate in rates.items() if rate < .5]
    return dict(passed=drained and busy <= .5,
        drain=dict(passed=drained, boundary=boundary, drain_complete_receipt=bool(drain_receipt),
                   manifest_incomplete=incomplete, pending_by_class=pending),
        observed_dispatcher_load=dict(passed=busy <= .5, window=list(window),
                                      busy_fraction=busy, limit=.5),
        cache_bin_diagnostic=dict(affects_validity=False, minimum_one_second_hit_rate=min(rates.values()) if rates else None,
            first_one_second_below_50=dips[0] if dips else 'never', sub_50_seconds=dips,
            one_second_bins={str(s):dict(hits=h, misses=m, hit_rate=rates.get(s)) for s,(h,m) in bins.items()}))


def from_packet(directory, window=(30, 90)):
    base = Path(directory)/'prototype'
    meta = json.loads((base/'manifest.json').read_bytes())['prototype']
    progress = [json.loads(line) for line in (base/'progress.jsonl').read_text().splitlines()]
    receipt = any(r.get('phase') == 'drain_end' and r.get('drain_complete') is True
                  and all(r.get(k) == 0 for k in ('q_admission', 'q_block', 'running')) for r in progress)
    with (base/'events.csv').open(newline='') as stream:
        return evaluate(read_jobs(base/'jobs.csv'), json.loads((base/'dispatcher_spans.json').read_bytes()),
                        csv.DictReader(stream), receipt, meta.get('incomplete', True), window)


def apply(prototype, directory, window=(30, 90)):
    conditions = from_packet(directory, window)
    validity = prototype['validity']
    validity['measurement_conditions'] = conditions
    validity['passed'] = validity['passed'] and conditions['passed']
    validity['status'] = 'VALID' if validity['passed'] else 'INVALID'
    return prototype
