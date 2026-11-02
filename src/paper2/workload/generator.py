"""Poisson/MMPP arrivals, integer fees, label isolation, and nonce-aware proposing."""

import hashlib
import json
import heapq
import math
from collections import defaultdict, deque

from src.paper2.model.service_times import WorkloadStream, derive_seed, nonnegative
from src.paper2.state.core import integer, normalize_tx


def probability(value, name):
    value = nonnegative(value, name)
    if value > 1:
        raise ValueError(name + " must be <= 1")
    return value


def integer_distribution(spec, stream):
    if spec.get("name") == "constant" and set(spec) == {"name", "value"}:
        return integer(spec["value"], "distribution value")
    if spec.get("name") == "uniform_int" and set(spec) == {"name", "low", "high"}:
        low, high = integer(spec["low"], "low"), integer(spec["high"], "high")
        if high < low:
            raise ValueError("distribution high < low")
        return stream.randint(low, high)
    raise ValueError("explicit constant or uniform_int integer distribution required")


TX_DRAW_VERSION = "paper2-tx-draw-v1"


def tx_draw_integer(run_id, replicate, attribute, identity):
    derive_seed(run_id, "arrivals", replicate)
    if attribute not in {"sender", "amount", "fee_rate", "invalid_kind", "victim_sender", "p_seen_keep"}:
        raise ValueError("unknown transaction attribute")
    if (not isinstance(identity, list) or len(identity) != 2 or identity[0] not in ("valid", "invalid")
            or isinstance(identity[1], bool) or not isinstance(identity[1], int) or identity[1] < 0):
        raise ValueError("invalid transaction identity")
    payload = json.dumps([TX_DRAW_VERSION, run_id, replicate, attribute, identity],
                         ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


class IdentityDraw:
    def __init__(self, value):
        self.value = value

    def randint(self, low, high):
        return low + self.value % (high - low + 1)


def _exponential(rate, stream):
    return -math.log1p(-stream.random()) / rate if rate > 0 else math.inf


def arrival_times(spec, horizon, stream, limit=None):
    t = 0.0
    if spec.get("kind") == "poisson":
        if set(spec) != {"kind", "rate"}:
            raise ValueError("Poisson requires kind and rate")
        rate = nonnegative(spec["rate"], "arrival rate")
        while limit is None or limit > 0:
            t += _exponential(rate, stream)
            if t >= horizon:
                return
            yield t
            if limit is not None:
                limit -= 1
    elif spec.get("kind") == "mmpp":
        if set(spec) - {"kind", "rates", "switching_rates", "initial_state"}:
            raise ValueError("unknown MMPP fields")
        rates, switches = spec["rates"], spec["switching_rates"]
        if len(rates) != 2 or len(switches) != 2:
            raise ValueError("MMPP requires two rates and two switching rates")
        rates = [nonnegative(r, "MMPP rate") for r in rates]
        switches = [nonnegative(r, "MMPP switching rate") for r in switches]
        state = spec.get("initial_state", 0)
        if isinstance(state, bool) or state not in (0, 1):
            raise ValueError("MMPP initial_state must be 0 or 1")
        while limit is None or limit > 0:
            arrival = _exponential(rates[state], stream)
            switch = _exponential(switches[state], stream)
            t += min(arrival, switch)
            if t >= horizon:
                return
            if arrival < switch:
                yield t
                if limit is not None:
                    limit -= 1
            else:
                state = 1 - state
    else:
        raise ValueError("arrival kind must be poisson or mmpp")


def generate_workload(parameters, *, service_seed=None):
    """Return model workload lists/genesis/provenance; never read a service stream.

    service_seed is an explicitly ignored compatibility argument, used to check
    that workload generation cannot depend on a service seed. max_transactions
    is an optional explicit generation cap applied separately to each process.
    """
    p = parameters
    required = {"run_id", "replicate", "horizon", "arrivals_valid", "arrivals_invalid", "fee_distribution",
                "amount_distribution", "senders", "initial_balance", "receiver",
                "scheme", "block_period", "block_size", "p_seen", "invalid_kinds"}
    optional = {"max_transactions", "invalid_sender_mode", "attacker_senders", "attacker_balance",
                "context", "deadline"}
    if not required <= set(p) or set(p) - required - optional:
        raise ValueError("missing or unknown generator fields")
    seeds = {name: derive_seed(p["run_id"], name, p["replicate"])
             for name in ("arrivals", "arrivals_invalid")}
    streams = {name: WorkloadStream(seed) for name, seed in seeds.items()}
    horizon = nonnegative(p["horizon"], "horizon")
    period = nonnegative(p["block_period"], "block_period")
    if not horizon or not period:
        raise ValueError("horizon and block_period must be positive")
    block_size = integer(p["block_size"], "block_size", 1)
    limit = p.get("max_transactions")
    if limit is not None:
        integer(limit, "max_transactions", 1)
    seen = probability(p["p_seen"], "p_seen")
    kinds = p["invalid_kinds"]
    if not isinstance(kinds, list) or not kinds or not set(kinds) <= {"bit_flip", "random_bytes"}:
        raise ValueError("invalid_kinds must explicitly list invalid signature kinds")
    senders = p["senders"]
    if not isinstance(senders, list) or not senders or len(set(senders)) != len(senders):
        raise ValueError("senders must be a nonempty unique list")
    mode = p.get("invalid_sender_mode", "victim")
    if mode not in ("victim", "attacker"):
        raise ValueError("unknown invalid_sender_mode")
    victims = senders if mode == "victim" else p["attacker_senders"]
    if not victims or len(set(victims)) != len(victims) or (mode == "attacker" and set(victims) & set(senders)):
        raise ValueError("attacker accounts must be distinct from valid accounts")
    balance = integer(p["initial_balance"], "initial_balance")
    genesis = dict(balances={sender: balance for sender in senders}, next_nonces=dict.fromkeys(senders, 0))
    if mode == "attacker":
        attacker_balance = integer(p["attacker_balance"], "attacker_balance")
        genesis["balances"].update(dict.fromkeys(victims, attacker_balance))
        genesis["next_nonces"].update(dict.fromkeys(victims, 0))
    scheme = p["scheme"]
    if set(scheme) - {"signature_bytes", "public_key_bytes", "include_public_key", "alg_id", "param_set_id"}:
        raise ValueError("unknown scheme fields")
    include_key = scheme.get("include_public_key", False)
    if not isinstance(include_key, bool):
        raise ValueError("include_public_key must be boolean")
    size = integer(scheme["signature_bytes"], "signature_bytes") + 185
    if include_key:
        size += integer(scheme["public_key_bytes"], "public_key_bytes")
    context = dict(p.get("context", {}))
    context.update({k: scheme[k] for k in ("alg_id", "param_set_id") if k in scheme})
    next_valid = defaultdict(int)
    transactions, offered = {}, []
    # Validate distributions even if the arrival process generates no items.
    for spec in (p["fee_distribution"], p["amount_distribution"]):
        integer_distribution(spec, WorkloadStream(0))
    # The explicit generation cap applies independently to each process.
    arrivals = []
    for kind, stream in (("valid", "arrivals"), ("invalid", "arrivals_invalid")):
        arrivals.extend((t, kind, i) for i, t in enumerate(
            arrival_times(p["arrivals_" + kind], horizon, streams[stream], limit)))
    identities = {}
    for t, kind, i in sorted(arrivals):
        identity = [kind, i]
        def draw(attribute):
            return tx_draw_integer(p["run_id"], p["replicate"], attribute, identity)
        invalid = kind == "invalid"
        label = kinds[draw("invalid_kind") % len(kinds)] if invalid else "valid"
        accounts = victims if invalid else senders
        sender = accounts[draw("victim_sender" if invalid else "sender") % len(accounts)]
        nonce = next_valid[sender]
        if not invalid:
            next_valid[sender] += 1
        tx_id = f"{'x' if invalid else 'v'}:{i}"
        tx = normalize_tx(dict(tx_id=tx_id, sender=sender, receiver=p["receiver"], nonce=nonce,
                               amount=integer_distribution(p["amount_distribution"], IdentityDraw(draw("amount"))),
                               fee_rate=integer_distribution(p["fee_distribution"], IdentityDraw(draw("fee_rate"))),
                               size_bytes=size, timestamp=t, sig_label=label,
                               signature_id=f"signature:{tx_id}:{label}"), context)
        transactions[tx_id] = tx
        identities[tx_id] = identity
        offered.append(dict(tx, arrival_t=t))
    valid = [tx for tx in offered if tx["sig_label"] == "valid"]
    waiting, ready, queued_senders = defaultdict(deque), [], set()
    included, blocks, cursor = set(), [], 0
    proposer_nonce = defaultdict(int)
    def expose(sender):
        if sender not in queued_senders and waiting[sender]:
            tx = waiting[sender][0]
            if tx["nonce"] == proposer_nonce[sender]:
                heapq.heappush(ready, (-tx["fee_rate"], tx["arrival_t"], tx["tx_id"], sender))
                queued_senders.add(sender)
    count_blocks = int(math.floor(horizon / period))
    for i in range(count_blocks):
        block_t = (i + 1) * period
        while cursor < len(valid) and valid[cursor]["arrival_t"] < block_t:
            tx = valid[cursor]
            waiting[tx["sender"]].append(tx)
            expose(tx["sender"])
            cursor += 1
        chosen = []
        while ready and len(chosen) < block_size:
            _, _, tx_id, sender = heapq.heappop(ready)
            queued_senders.remove(sender)
            tx = waiting[sender].popleft()
            assert tx["tx_id"] == tx_id and tx["nonce"] == proposer_nonce[sender]
            chosen.append(tx_id)
            included.add(tx_id)
            proposer_nonce[sender] += 1
            expose(sender)
        blocks.append(dict(block_id=f"block:{i}", tx_ids=chosen, block_sig_label="valid"))
    seen_numerator, seen_denominator = seen.as_integer_ratio()
    admissions = [tx for tx in offered if tx["tx_id"] not in included or
                  tx_draw_integer(p["run_id"], p["replicate"], "p_seen_keep", identities[tx["tx_id"]]) *
                  seen_denominator < seen_numerator * 2**256]
    beyond = sum(tx["sig_label"] != "valid" and tx["nonce"] == next_valid[tx["sender"]] for tx in offered)
    manifest = dict(parameters=dict(p), seeds=seeds, counts=dict(offered=len(offered),
        valid=len(valid), invalid=len(offered) - len(valid), included=len(included),
        node_admissions=len(admissions), blocks=len(blocks)),
        invalid_nonce_beyond_horizon=beyond, next_unassigned_valid_nonce=dict(next_valid),
        fee_rule="integer fee_rate per byte; fees burned", service_streams_consumed=False,
        tx_draw_version=TX_DRAW_VERSION, cap_per_process=limit,
        capped=limit is not None and any(sum(1 for _, kind, _ in arrivals if kind == k) == limit for k in ("valid", "invalid")))
    return dict(run_id=p["run_id"], replicate=p["replicate"], transactions=transactions,
                admissions=admissions, blocks=blocks, genesis=genesis,
                block_start=period, block_period=period, deadline=p.get("deadline", period),
                generator_manifest=manifest)
