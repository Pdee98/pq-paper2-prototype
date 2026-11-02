"""Independent trace checks shared by Phase 1 tests."""

import csv
import json
from src.paper2.state import cache_key
from src.paper2.model.records import read_jobs


def tx(tx_id, **overrides):
    value = dict(tx_id=tx_id, sender="sender:" + tx_id, receiver="sink", nonce=0,
                 amount=1, fee_rate=0, size_bytes=249, timestamp=0, sig_label="valid")
    value.update(overrides)
    return value


def config(**overrides):
    result = dict(run_id="handcheck", replicate=0, k=1, q_max=100,
                  structural_cost=0, block_period=1, block_start=0, deadline=2,
                  admissions=[], blocks=[], service=dict(mode="constant", seconds={
                      "admission": 1, "block_tx": 1, "block_sig": 1}))
    result.update(overrides)
    transactions = dict(result.get("transactions", {}))
    ids = {a["tx_id"] for a in result["admissions"]}
    ids.update(t for b in result["blocks"] for t in b["tx_ids"])
    for identifier in sorted(ids):
        transactions.setdefault(identifier, tx(identifier))
    result["transactions"] = transactions
    senders = {t["sender"] for t in transactions.values()}
    result.setdefault("genesis", dict(balances=dict.fromkeys(sorted(senders), 1000000),
                                      next_nonces=dict.fromkeys(sorted(senders), 0)))
    result.setdefault("cache", {"capacity": 0})
    result.setdefault("pool", {"enabled": False})
    return result


def check_trace(case, log, manifest, k):
    with log.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["jobs"] = read_jobs(manifest.parent / data["job_records"]["path"])
    from src.paper2.verify.invariants import check
    case.assertEqual(check(log, manifest.parent / data["job_records"]["path"], manifest), [])
    required = {"run_id", "seq", "t", "event", "job_id", "job_class", "tx_id", "block_id",
                "worker_id", "service_time", "q_admission", "q_block", "busy_workers"}
    if rows:
        case.assertTrue(required <= set(rows[0]))
    case.assertEqual([int(r["seq"]) for r in rows], list(range(len(rows))))
    times = [float(r["t"]) for r in rows]
    case.assertEqual(times, sorted(times))
    active = {}
    by_job = {}
    for row in rows:
        event, jid = row["event"], row["job_id"]
        if jid:
            by_job.setdefault(jid, []).append(row)
        worker = int(row["worker_id"]) if row["worker_id"] else None
        if event == "start":
            case.assertIsNotNone(worker)
            case.assertTrue(0 <= worker < k)
            case.assertNotIn(worker, active)
            active[worker] = jid
        elif event == "end":
            case.assertEqual(active.pop(worker), jid)
        case.assertEqual(int(row["busy_workers"]), len(active))
        case.assertTrue(0 <= len(active) <= k)
        case.assertGreaterEqual(int(row["q_admission"]), 0)
        case.assertLessEqual(int(row["q_admission"]), data["config"]["q_max"])
        case.assertGreaterEqual(int(row["q_block"]), 0)
    case.assertEqual(active, {})
    for job in data["jobs"]:
        if job["status"] == "coalesced":
            source = next(j for j in data["jobs"] if j["job_id"] == job["proof_job_id"])
            case.assertEqual(job["cache_key"], source["cache_key"])
            block = data["blocks"][job["block_id"]]
            decision_t = block["accept_t"] if block["valid"] else block["reject_t"]
            case.assertLessEqual(source["end_t"], decision_t)
        if job["block_id"] and not job.get("admission_origin"):
            case.assertEqual(job["created_t"], data["blocks"][job["block_id"]]["arrival_t"])
        if job["status"] in ("drop", "struct_reject", "cache_hit", "neg_hit", "dup_drop", "coalesced"):
            case.assertIsNone(job["enqueue_t"])
            case.assertIsNone(job["start_t"])
            case.assertIsNone(job["end_t"])
            continue
        case.assertEqual(job["status"], "end")
        case.assertLessEqual(job["enqueue_t"], job["start_t"])
        case.assertLessEqual(job["start_t"], job["end_t"])
        case.assertAlmostEqual(job["end_t"] - job["start_t"], job["service_time"])
        case.assertIn(job["outcome"], ("valid", "invalid"))
        case.assertEqual([r["event"] for r in by_job[job["job_id"]] if r["event"] in ("enqueue", "start", "end")],
                         ["enqueue", "start", "end"])
        if job["block_id"] and not job.get("admission_origin"):
            case.assertGreaterEqual(job["enqueue_t"], data["blocks"][job["block_id"]]["arrival_t"])
    for block_id, block in data["blocks"].items():
        case.assertEqual(block["deadline_t"], block["arrival_t"] + data["config"]["deadline"])
        ended = [j["end_t"] for j in data["jobs"] if j["block_id"] == block_id and j["end_t"] is not None]
        decisions = [r for r in rows if r["block_id"] == block_id and r["event"] in ("block_accept", "block_reject")]
        case.assertEqual(len(decisions), 1)
        if block["structurally_rejected"]:
            case.assertIsNone(block["accept_t"])
        else:
            case.assertTrue(ended)
            decision_t = block["accept_t"] if block["valid"] else block["reject_t"]
            case.assertGreaterEqual(decision_t, max(ended))
            if block["valid"]:
                case.assertTrue(all(c["passed"] for c in block["state_checks"]))
    proofs = {(v["key"], v["job_id"]) for v in data["verification_history"] if v["outcome"] == "valid"}
    for row in rows:
        if row["event"] in ("cache_hit", "pool_insert"):
            case.assertTrue(any(v["key"] == row["cache_key"] and v["t"] <= float(row["t"])
                                for v in data["verification_history"]))
        if row["event"] == "pool_insert":
            case.assertTrue(any(c["job_id"] == row["job_id"] and c["key"] == row["cache_key"] and c["passed"]
                                for c in data["admission_checks"]))
    balances = dict(data["config"]["genesis"]["balances"])
    nonces = dict(data["config"]["genesis"]["next_nonces"])
    for account in set(balances) | set(nonces):
        balances.setdefault(account, 0)
        nonces.setdefault(account, 0)
    for accepted in data["accepted_transactions"]:
        case.assertEqual(cache_key(accepted["tx"]), accepted["key"])
        case.assertIn((accepted["key"], accepted["proof_job_id"]), proofs)
        case.assertTrue(accepted["state_passed"])
        case.assertTrue(data["blocks"][accepted["block_id"]]["valid"])
        case.assertTrue(any(v["job_id"] == accepted["proof_job_id"] and v["key"] == accepted["key"]
                            and v["t"] <= data["blocks"][accepted["block_id"]]["accept_t"]
                            for v in data["verification_history"]))
        transaction = accepted["tx"]
        sender, receiver = transaction["sender"], transaction["receiver"]
        case.assertEqual(transaction["nonce"], nonces.get(sender, 0))
        debit = transaction["amount"] + transaction["fee_rate"] * transaction["size_bytes"]
        case.assertGreaterEqual(balances.get(sender, 0), debit)
        balances[sender] = balances.get(sender, 0) - debit
        balances[receiver] = balances.get(receiver, 0) + transaction["amount"]
        nonces.setdefault(receiver, 0)
        nonces[sender] = transaction["nonce"] + 1
    case.assertEqual(data["ledger"], dict(balances=balances, next_nonces=nonces))
    return rows, data


def sequence(rows):
    return [(float(r["t"]), r["event"], r["job_id"],
             int(r["worker_id"]) if r["worker_id"] else None,
             int(r["q_admission"]), int(r["q_block"]), int(r["busy_workers"])) for r in rows if r["event"] != "dispatch"]
