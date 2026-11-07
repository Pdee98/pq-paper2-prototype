"""Unoptimised checker reference from source a990487; retained for equivalence tests."""
"""Independent schema-v4 checker. Imports no engine or state implementation."""

import collections
import csv
import hashlib
import json
import math
from pathlib import Path


def check_reference(events_csv, jobs_csv, manifest):
    """Return diagnostic dictionaries; input files are the only source of state."""
    with Path(events_csv).open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    with Path(jobs_csv).open(encoding="utf-8", newline="") as f:
        records = [json.loads(r["record"]) for r in csv.DictReader(f)]
    data = json.loads(Path(manifest).read_text(encoding="utf-8"))
    errors = []
    def bad(code, message, **context):
        errors.append(dict(code=code, message=message, **context))
    def close(a, b):
        return a is not None and b is not None and math.isclose(a, b, rel_tol=0, abs_tol=1e-12)
    jobs = {j["job_id"]: j for j in records}
    if len(jobs) != len(records):
        bad("job_identity", "duplicate physical/logical job record")
    cfg, blocks = data["config"], data["blocks"]
    identity_mode = cfg.get("prototype", {}).get("mode")
    real = identity_mode == "real-time-v1"
    real_identity = identity_mode in ("real-time-v1", "real-byte-simulation-v1", "precomputed-key-replay-v1")
    real_keys, busy_spans = {}, []
    if real_identity:
        from .prototype import inspect, covered_reference as covered, overlap_reference as overlap
        try:
            extra, real_keys, busy_spans = inspect(rows, records, data, manifest)
            errors.extend(extra)
        except (KeyError, ValueError, TypeError, OSError) as exc:
            bad("prototype_evidence", "invalid prototype evidence: " + str(exc))
    k = cfg.get("k", 1)
    policy = cfg.get("policy", {"name": "fifo"})
    split = policy["name"] == "static_split"
    ka = policy.get("k_a", cfg.get("k_a")) if split else k
    def eligible(worker, cls):
        return not split or (worker < ka) == (cls == "admission")
    active, waiting, direct, selected = {}, {}, {}, {}
    starts, ends, arrivals, decisions = collections.Counter(), collections.Counter(), {}, {}
    proofs, attachments, h0 = {}, collections.defaultdict(list), {}
    proof_keys = {}
    previous = -math.inf
    for i, row in enumerate(rows):
        t, event, jid = float(row["t"]), row["event"], row["job_id"]
        if int(row["seq"]) != i or t < previous:
            bad("chronology", "nonmonotone time or sequence", row=i)
        previous = t
        if event == "block_arrive":
            if row["block_id"] in arrivals:
                bad("block_arrival", "duplicate block arrival")
            arrivals[row["block_id"]] = t
        bid = row["block_id"]
        if bid and row["deadline_t"]:
            arrival = arrivals.get(bid, blocks.get(bid, {}).get("arrival_t"))
            if arrival is None or float(row["deadline_t"]) != arrival + cfg.get("deadline", 1):
                bad("block_deadline", "event deadline differs from arrival plus configured deadline", row=i, block_id=bid)
        if event == "drop" and row["detail"] == "queue_capacity":
            admission_waiting = sum(c == "admission" for c in waiting.values())
            free = [w for w in range(k) if w not in active and eligible(w, "admission")]
            if row["job_class"] != "admission" or admission_waiting != cfg.get("q_max", 1000) or free:
                bad("tail_drop", "capacity drop without a full admission queue and occupied eligible workers",
                    row=i, t=t, waiting=admission_waiting, free_worker_ids=free)
        if event == "enqueue":
            cls = row["job_class"]
            if policy["name"] == "block_priority" and not cfg.get("coalesce_inflight", False) and cls != "admission":
                residuals = [max(0, jobs[v]["end_t"]-t) for v in active.values()]
                ahead = sum(jobs[v]["service_time"] for v, c in waiting.items() if c != "admission")
                h0[jid] = max(residuals, default=0)+ahead
            target = direct if any(w not in active and eligible(w, cls) for w in range(k)) else waiting
            target[jid] = cls
        elif event == "dispatch" and row["chosen_job_id"]:
            chosen = row["chosen_job_id"]
            cls = waiting.pop(chosen, None) or direct.pop(chosen, None)
            if cls is None:
                bad("queue_recount", "dispatch selected a job that was not waiting", job_id=chosen, t=t)
            else:
                selected[chosen] = cls
            waiting.update(direct)
            direct.clear()
        elif event == "coalesce_promote":
            if jid not in waiting:
                bad("coalesce_attachment", "promoted source was not waiting", job_id=jid)
            else:
                waiting[jid] = "block_tx"
            attachments[row["detail"]].append((t, jid))
        elif event == "coalesce_wait":
            attachments[jid].append((t, row["detail"]))
        elif event == "start":
            starts[jid] += 1
            w = int(row["worker_id"]) if row["worker_id"] else -1
            if w < 0 or w >= k or w in active or not eligible(w, row["job_class"]):
                bad("worker_ownership", "start without an eligible free worker", t=t, worker=w, job_id=jid)
            if jid not in selected:
                bad("queue_recount", "start without a dispatch reservation", job_id=jid)
            selected.pop(jid, None)
            active[w] = jid
            if jid in jobs and (not close(t, jobs[jid]["start_t"]) or jobs[jid]["worker_id"] != w):
                bad("job_timing", "start row and job record disagree", job_id=jid)
        elif event == "end":
            ends[jid] += 1
            w = int(row["worker_id"]) if row["worker_id"] else -1
            if active.get(w) != jid:
                bad("worker_ownership", "end does not own its worker", t=t, worker=w, job_id=jid)
            active.pop(w, None)
            job = jobs.get(jid)
            if job is None or not close(t, job["end_t"]) or row["outcome"] != job["outcome"]:
                bad("job_timing", "end row and job record disagree", job_id=jid)
            if row["outcome"] == "valid" and row["cache_key"]:
                proofs[row["cache_key"], jid] = t
                proof_keys[row["cache_key"]] = t
        elif event == "cache_hit":
            if row["cache_key"] not in proof_keys or proof_keys[row["cache_key"]] > t:
                bad("cache_safety", "cache hit lacks earlier identical-key success", job_id=jid, t=t)
        elif event in ("block_accept", "block_reject"):
            bid = row["block_id"]
            if bid in decisions:
                bad("block_decision", "multiple block decisions", block_id=bid)
            decisions[bid] = (t, event, row["reject_reasons"])
        qa = sum(c == "admission" for c in waiting.values())
        qb = len(waiting)-qa
        if not 0 <= int(row["q_admission"]) <= cfg.get("q_max", 1000):
            bad("admission_capacity", "event admission queue exceeds configured bounds", row=i, t=t)
        if (qa, qb) != (int(row["q_admission"]), int(row["q_block"])):
            bad("queue_recount", "queue counters disagree with event replay", row=i, t=t, expected=[qa, qb])
        if int(row["busy_workers"]) != len(active) or len(active) > k:
            bad("worker_ownership", "busy counter disagrees with worker replay", row=i, t=t)
        if i+1 == len(rows) or float(rows[i+1]["t"]) != t:
            all_waiting = dict(waiting, **direct, **selected)
            for w in range(k):
                eligible_jobs = [j for j, c in all_waiting.items() if eligible(w, c)]
                accounted = real and i+1 < len(rows) and covered(busy_spans, t, float(rows[i+1]["t"]))
                if w not in active and eligible_jobs and not accounted:
                    bad("work_conservation", "idle eligible worker in settled state", t=t,
                        worker_ids=[w], waiting_job_ids=eligible_jobs)
    if active or waiting or direct or selected:
        bad("unfinished_work", "trace ended with running/waiting/reserved jobs")
    intervals = collections.defaultdict(list)
    serving = collections.defaultdict(list)
    for job in records:
        jid = job["job_id"]
        if job["start_t"] is not None:
            if (job["enqueue_t"] is None or job["end_t"] is None or
                not job["enqueue_t"] <= job["start_t"] <= job["end_t"] or
                not close(job["end_t"]-job["start_t"], job["service_time"])):
                bad("job_timing", "invalid service interval", job_id=jid)
            if starts[jid] != 1 or ends[jid] != 1:
                bad("single_service", "physical job needs exactly one start/end", job_id=jid)
            if job["end_t"] is not None:
                intervals[job["worker_id"]].append((job["start_t"], job["end_t"], jid))
                for bid in set(job["block_waiters"] + ([job["block_id"]] if job["block_id"] else [])):
                    serving[bid].append(job)
            if jid in h0:
                wait = job["start_t"]-job["enqueue_t"]
                overhead = overlap(busy_spans, job["enqueue_t"], job["start_t"]) if real else 0
                if ((k == 1 and not real and not close(wait, h0[jid])) or
                    (real and (wait < h0[jid]-1e-12 if k == 1 else False)) or
                    ((k > 1 or real) and wait > h0[jid]+overhead+1e-12)):
                    bad("H0", "block wait violates non-preemptive priority residual bound", job_id=jid,
                        wait=wait, bound=h0[jid])
        if job["block_id"] and not job["admission_origin"]:
            arrival = arrivals.get(job["block_id"])
            if arrival is None or job["created_t"] < arrival or (job["enqueue_t"] is not None and job["enqueue_t"] < arrival):
                bad("block_chronology", "block job predates arrival", job_id=jid)
        if len(job["block_waiters"]) != len(set(job["block_waiters"])):
            bad("single_service", "one source decrements the same block more than once", job_id=jid)
        if job["status"] == "coalesced":
            source = jobs.get(job["proof_job_id"])
            attached = attachments[jid]
            bid = job["block_id"]
            if source is None or source["cache_key"] != job["cache_key"]:
                bad("coalesce_key", "coalesced source has wrong key", job_id=jid)
                continue
            if len(attached) != 1 or attached[0][1] != source["job_id"] or not (
                source["enqueue_t"] is not None and source["end_t"] is not None and
                arrivals.get(bid, math.inf) <= attached[0][0] and
                source["enqueue_t"] <= attached[0][0] < source["end_t"]):
                bad("coalesce_attachment", "attachment outside live source interval", job_id=jid)
            decision = decisions.get(bid)
            if decision is None or source["end_t"] is None or source["end_t"] > decision[0]:
                bad("coalesce_completion", "source completes after block decision", job_id=jid)
            if decision and source["outcome"] != "valid" and (
                    decision[1] == "block_accept" or "invalid_signature" not in decision[2].split(";")):
                bad("coalesce_outcome", "decision not bound to invalid coalesced result", job_id=jid)
            if source["block_waiters"].count(bid) != 1 or starts[source["job_id"]] != 1 or ends[source["job_id"]] != 1:
                bad("single_service", "coalesced source/block accounting is not unique", job_id=jid)
    for worker, spans in intervals.items():
        last = -math.inf
        for start, end, jid in sorted(spans):
            if start < last:
                bad("worker_ownership", "job-record service intervals overlap", worker=worker, job_id=jid)
            last = max(last, end)
    for i, spec in enumerate(cfg.get("blocks", [])):
        bid = spec["block_id"]
        arrival = arrivals.get(bid, blocks[bid]["arrival_t"])
        if blocks[bid]["deadline_t"] != arrival + cfg.get("deadline", 1):
            bad("block_deadline", "manifest deadline differs from arrival plus configured deadline", block_id=bid)
        expected = cfg["block_times"][i] if cfg.get("block_times") is not None else cfg.get("block_start", 0)+i*cfg.get("block_period", 1)
        if (not real and arrivals.get(bid) != expected) or (real and arrivals.get(bid, -math.inf) < expected):
            bad("block_arrival", "block arrival does not match schedule", block_id=bid)
        if bid not in decisions:
            bad("block_decision", "missing block decision", block_id=bid)
            continue
        decision = decisions[bid]
        for j in serving[bid]:
            if j["end_t"] > decision[0]:
                bad("block_decision", "decision before last serving job ends", block_id=bid)
            if decision[1] == "block_accept" and j["outcome"] != "valid":
                bad("acceptance_safety", "accepted block has invalid signature service", block_id=bid)
        if blocks[bid]["pending"] != 0:
            bad("block_accounting", "decision has nonzero remaining work", block_id=bid)
    balances = dict(cfg["genesis"]["balances"])
    nonces = dict(cfg["genesis"]["next_nonces"])
    for account in set(balances) | set(nonces):
        balances.setdefault(account, 0); nonces.setdefault(account, 0)
    seen = set()
    for accepted in data["accepted_transactions"]:
        tx, bid = accepted["tx"], accepted["block_id"]
        if tx["tx_id"] in seen:
            bad("unique_counting", "accepted tx_id counted twice", tx_id=tx["tx_id"])
        seen.add(tx["tx_id"])
        fields = [tx["sender"], tx["receiver"], str(tx["amount"]), repr(float(tx["timestamp"])), tx["transaction_id"], tx["nonce"]]
        key = hashlib.sha256(json.dumps([tx["domain_tag"], tx["chain_id"], tx["alg_id"], tx["param_set_id"],
            tx["public_key_id"], fields, tx["signature_id"]], ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()
        if real_identity:
            key = real_keys.get(tx["tx_id"], "")
            if tx != cfg["transactions"].get(tx["tx_id"]):
                bad("real_payload", "accepted transaction differs from corpus-bound configuration", tx_id=tx["tx_id"])
        proof = proofs.get((key, accepted["proof_job_id"]))
        decision = decisions.get(bid)
        if key != accepted["key"] or proof is None or decision is None or proof > decision[0] or decision[1] != "block_accept" or not accepted["state_passed"] or tx["sig_label"] != "valid":
            bad("acceptance_safety", "accepted transaction lacks successful bound proof/state", tx_id=tx["tx_id"])
        if any(not c["passed"] for c in blocks[bid]["state_checks"]):
            bad("acceptance_safety", "accepted block failed state checks", block_id=bid)
        s, r = tx["sender"], tx["receiver"]
        debit = tx["amount"]+tx["fee_rate"]*tx["size_bytes"]
        if tx["nonce"] != nonces.get(s, 0) or balances.get(s, 0) < debit:
            bad("ledger_replay", "accepted transaction fails sequential ledger replay", tx_id=tx["tx_id"])
        balances[s] = balances.get(s, 0)-debit
        balances[r] = balances.get(r, 0)+tx["amount"]
        nonces[s] = nonces.get(s, 0)+1
        nonces.setdefault(r, 0)
    if dict(balances=balances, next_nonces=nonces) != data["ledger"]:
        bad("ledger_replay", "final ledger differs from replay")
    return errors
