"""Presigned frozen blockchain objects, metadata commitments and real cache keys."""

from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import time
from pathlib import Path

from src.blockchain.transaction import Transaction
from src.blockchain.block import Block
from src.paper2.model.service_times import ROOT
from src.paper2.state import normalize_tx
from .backends import Signer, Verifier, negative

CONTEXT = dict(domain_tag="paper2-real-transaction-v1", chain_id="paper2-g3-chain",
               alg_id="ed25519", param_set_id="Ed25519")
PARAMETERS = dict(ed25519="Ed25519", sleep="Ed25519-sleep-diagnostic",
                  xmss="XMSS-SHA2_10_256", ml_dsa_44="ML-DSA-44",
                  slh_dsa_sha2_128s="SLH-DSA-SHA2-128s")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def cache_key(context, public_key, payload, nonce, signature):
    if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0 or nonce >= 2**64:
        raise ValueError("nonce must fit uint64")
    parts = [b"paper2-real-cache-key-v1"] + [context[k].encode() for k in CONTEXT]
    parts += [bytes(public_key), bytes(payload), nonce.to_bytes(8, "big"), bytes(signature)]
    return hashlib.sha256(b"".join(len(p).to_bytes(8, "big")+p for p in parts)).hexdigest()


def commitment(tx, context):
    return digest(dict(context=context, tx_id=tx["tx_id"], sender=tx["sender"], receiver=tx["receiver"],
        amount=tx["amount"], timestamp=tx["timestamp"], nonce=tx["nonce"], fee_rate=tx["fee_rate"],
        size_bytes=tx["size_bytes"], sender_id=tx["sender_id"]))


def frozen_tx(meta, signature=b""):
    return Transaction(sender=meta["sender"], receiver=meta["receiver"], amount=meta["amount"],
        timestamp=meta["timestamp"], sender_id=meta["sender_id"],
        transaction_id=meta["transaction_id"], signature=signature)


def signed_parts(entry):
    return tuple(bytes.fromhex(entry[k]) for k in ("payload_hex", "signature_hex", "public_key_hex"))


def validate_entry(entry, context, tx=None):
    payload, signature, public = signed_parts(entry)
    if tx is not None:
        if commitment(tx, context) != tx["transaction_id"]:
            raise ValueError("transaction metadata commitment mismatch")
        if payload != frozen_tx(tx).signed_payload():
            raise ValueError("signed payload differs from frozen Transaction")
        if len(frozen_tx(tx, signature).serialize()) != tx["size_bytes"]:
            raise ValueError("declared size differs from frozen wire representation")
        if cache_key(context, public, payload, tx["nonce"], signature) != entry["cache_key"]:
            raise ValueError("real cache key mismatch")
    return payload, signature, public


def _sign_batch(task):
    backend, batch_id, messages = task
    key_begin=time.perf_counter_ns()
    signer = Signer(backend)
    keygen_ns=time.perf_counter_ns()-key_begin
    start = time.perf_counter_ns()
    try:
        key_id = hashlib.sha256(signer.public_key).hexdigest()
        entries = []
        for i, (identity, payload, label) in enumerate(messages):
            valid = signer.sign(bytes.fromhex(payload))
            signature = negative(valid, label, identity)
            entries.append(dict(identity=identity, payload_hex=payload, signature_hex=signature.hex(),
                public_key_hex=signer.public_key.hex(), key_id=key_id,
                leaf_index=i if backend == "xmss" else None, batch_id=batch_id))
        return dict(entries=entries, key_id=key_id, next_leaf=len(messages) if backend == "xmss" else None,
                    count=len(messages), signing_ns=time.perf_counter_ns()-start,keygen_ns=keygen_ns)
    finally:
        signer.close()


def sign_messages(backend, messages, processes=1):
    if processes < 1:
        raise ValueError("positive presigning process count required")
    batches = [(backend, i//512, messages[i:i+512]) for i in range(0,len(messages),512)]
    # Every batch creates a distinct key. No secret key crosses a process boundary.
    start=time.perf_counter_ns()
    if processes == 1:
        results=list(map(_sign_batch,batches))
    else:
        with ProcessPoolExecutor(max_workers=processes) as executor:
            results=list(executor.map(_sign_batch,batches))
    ledger=[{k:v for k,v in r.items() if k!="entries"} for r in results]
    if len({r["key_id"] for r in ledger})!=len(ledger):
        raise ValueError("duplicate presigning keys")
    return [e for r in results for e in r["entries"]],dict(keys=ledger,wall_ns=time.perf_counter_ns()-start,
        count=len(messages),processes=processes,leaf_rule="one key/batch; indices 0..count-1; max 512 per H10 key")


def build(workload, backend="ed25519", processes=1, master=None, primitive_checks=False):
    """Build a public corpus. Optional master reuses signed transaction prefixes."""
    import copy
    w=copy.deepcopy(workload)
    context=dict(CONTEXT,alg_id=backend,param_set_id=PARAMETERS[backend])
    w["context"]=context
    accounts=sorted({t["sender"] for t in w["transactions"].values()})
    sender_ids={name:int.from_bytes(hashlib.sha256(name.encode()).digest()[:4],"big") for name in accounts}
    if len(set(sender_ids.values()))!=len(sender_ids):raise ValueError("sender identity hash collision")
    probe=Signer(backend)
    signature_size=probe.signature_size
    probe.close()
    messages=[]
    for i,(identity,tx) in enumerate(w["transactions"].items()):
        # Timestamp is stable corpus metadata, independent of replay rate/policy.
        ordinal=int(identity.split(":")[-1]) if identity.split(":")[-1].isdigit() else i
        tx.update(context,timestamp=float(ordinal),sender_id=sender_ids[tx["sender"]],transaction_id="0"*64)
        tx["size_bytes"]=len(frozen_tx(tx,bytes(signature_size)).serialize())
        tx["transaction_id"]=commitment(tx,context)
        tx=normalize_tx(tx,context);w["transactions"][identity]=tx
        if master is None or identity not in master["transactions"]:
            messages.append((identity,frozen_tx(tx).signed_payload().hex(),tx["sig_label"]))
    signed,tx_ledger=sign_messages(backend,messages,processes)
    entries={e.pop("identity"):e for e in signed}
    for identity,tx in w["transactions"].items():
        if identity not in entries:
            entries[identity]=copy.deepcopy(master["transactions"][identity])
        entry=entries[identity]
        entry["cache_key"]=cache_key(context,bytes.fromhex(entry["public_key_hex"]),
            bytes.fromhex(entry["payload_hex"]),tx["nonce"],bytes.fromhex(entry["signature_hex"]))
        tx.update(public_key_id=entry["key_id"],signature_id=hashlib.sha256(bytes.fromhex(entry["signature_hex"])).hexdigest())
    # Admission dictionaries may carry their own copies of metadata in generated workloads.
    for a in w["admissions"]:
        arrival=a["arrival_t"];a.update(w["transactions"][a["tx_id"]]);a["arrival_t"]=arrival
    blocks={};objects={};previous="0"*64;block_messages=[]
    for i,b in enumerate(w["blocks"]):
        arrival=w.get("block_times",[])[i] if w.get("block_times") is not None else w.get("block_start",0)+i*w["block_period"]
        obj=Block(i,[frozen_tx(w["transactions"][name],bytes.fromhex(entries[name]["signature_hex"]))
                     for name in b["tx_ids"]],previous,proposer_id=1000000,timestamp=arrival)
        previous=obj.hash;objects[b["block_id"]]=dict(index=i,previous_hash=obj.previous_hash,
            proposer_id=obj.proposer_id,timestamp=obj.timestamp,nonce=obj.nonce,hash=obj.hash)
        block_messages.append((b["block_id"],obj.get_signable_message().encode().hex(),b.get("block_sig_label","valid")))
    signed,block_ledger=sign_messages(backend,block_messages,processes)
    for e in signed:blocks[e.pop("identity")]=e
    result=dict(version="paper2-public-corpus-v1",backend=backend,context=context,workload=w,
        transactions=entries,blocks=blocks,block_objects=objects,
        presigning=dict(transactions=tx_ledger,blocks=block_ledger))
    validate(result,primitive_checks=primitive_checks)
    return result


def validate(corpus, primitive_checks=False):
    context=corpus["context"];w=corpus["workload"]
    verifier=Verifier(corpus["backend"]) if primitive_checks else None
    try:
        for identity,entry in corpus["transactions"].items():
            parts=validate_entry(entry,context,w["transactions"][identity])
            if verifier:
                verifier.register(parts[2])
                valid=verifier.verify(*parts)
                if valid != (w["transactions"][identity]["sig_label"]=="valid"):
                    raise ValueError("corpus signature label not verified")
        for b in w["blocks"]:
            fields=corpus["block_objects"][b["block_id"]]
            obj=Block(fields["index"],[frozen_tx(w["transactions"][name],
                bytes.fromhex(corpus["transactions"][name]["signature_hex"])) for name in b["tx_ids"]],
                fields["previous_hash"],proposer_id=fields["proposer_id"],timestamp=fields["timestamp"],nonce=fields["nonce"])
            parts=signed_parts(corpus["blocks"][b["block_id"]])
            if obj.hash!=fields["hash"] or obj.get_signable_message().encode()!=parts[0]:
                raise ValueError("block signed bytes differ from frozen Block")
            if verifier:
                verifier.register(parts[2])
                if verifier.verify(*parts)!=(b.get("block_sig_label","valid")=="valid"):
                    raise ValueError("block corpus signature not verified")
    finally:
        if verifier:verifier.close()


def write(corpus, path):
    path=Path(path).resolve()
    if ROOT==path or ROOT in path.parents:
        raise ValueError("corpus output must be outside repository")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(canonical(corpus)+b"\n")
    return path
