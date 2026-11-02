"""Independent real-byte/clock/span checks. No model objects or prototype helper imports."""

import hashlib
import json
from pathlib import Path

from src.blockchain.transaction import Transaction
from src.blockchain.block import Block


def inspect(rows,jobs,data,manifest):
    errors=[];keys={};intervals=[]
    def bad(code,message,**kw):errors.append(dict(code=code,message=message,**kw))
    def load(path,sha):
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=sha:bad("prototype_checksum","artifact checksum mismatch",path=str(path))
        return json.loads(raw)
    p=data.get("prototype",{})
    runtime=p.get("mode")=="real-time-v1"
    if p.get("mode") not in ("real-time-v1","real-byte-simulation-v1"):
        bad("prototype_schema","missing real-time provenance");return errors,keys,intervals
    base=Path(manifest).parent
    corpus=load(base/p["corpus_path"],p["corpus_sha256"])
    spans=load(base/p["spans"]["path"],p["spans"]["sha256"]) if runtime else []
    epoch=p["epoch_ns"] if runtime else 0;context=corpus["context"]
    anchors={}
    for row in rows:
        if not runtime:break
        ns=int(row["monotonic_ns"])
        if abs((ns-epoch)/1e9-float(row["t"]))>1e-12:bad("prototype_clock","row time not bound to monotonic clock")
        if row["event"].startswith("dispatcher_busy_"):
            key=(int(row["dispatcher_span_id"]),row["event"])
            if key in anchors:bad("dispatcher_span","duplicate busy anchor")
            anchors[key]=ns
    previous=epoch
    for i,span in enumerate(spans):
        a,b=span["start_ns"],span["end_ns"]
        if span["id"]!=i or not previous<=a<=b:
            bad("dispatcher_span","nonmonotone, overlapping or misidentified busy span")
        if (anchors.get((i,"dispatcher_busy_start"))!=a or anchors.get((i,"dispatcher_busy_end"))!=b
                or span["start_t"]!=(a-epoch)/1e9 or span["end_t"]!=(b-epoch)/1e9):
            bad("dispatcher_span","busy span not bound to event anchors")
        intervals.append(((a-epoch)/1e9,(b-epoch)/1e9));previous=b
    if len(anchors)!=2*len(spans):bad("dispatcher_span","unmatched busy markers")
    byid={s["id"]:s for s in spans}
    for row in rows:
        if not runtime:break
        span=byid.get(int(row["dispatcher_span_id"]))
        if span is None or not span["start_ns"]<=int(row["monotonic_ns"])<=span["end_ns"]:
            bad("dispatcher_span","event outside its recorded busy span",row=row["seq"])
    for identity,entry in corpus["transactions"].items():
        tx=corpus["workload"]["transactions"][identity]
        actual=data["config"]["transactions"].get(identity)
        if actual!=tx:bad("real_payload","manifest transaction differs from trusted corpus",tx_id=identity)
        metadata=dict(context=context,**{k:tx[k] for k in
            ("tx_id","sender","receiver","amount","timestamp","nonce","fee_rate","size_bytes","sender_id")})
        commit=hashlib.sha256(json.dumps(metadata,sort_keys=True,ensure_ascii=True,
                    separators=(",",":"),allow_nan=False).encode()).hexdigest()
        if commit!=tx["transaction_id"]:bad("real_payload","unsigned metadata commitment mismatch",tx_id=identity)
        obj=Transaction(sender=tx["sender"],receiver=tx["receiver"],amount=tx["amount"],timestamp=tx["timestamp"],
                        sender_id=tx["sender_id"],transaction_id=tx["transaction_id"],signature=bytes.fromhex(entry["signature_hex"]))
        payload=bytes.fromhex(entry["payload_hex"]);public=bytes.fromhex(entry["public_key_hex"])
        if payload!=obj.signed_payload() or obj.serialized_size()!=tx["size_bytes"]:
            bad("real_payload","frozen signed bytes/wire size mismatch",tx_id=identity)
        parts=[b"paper2-real-cache-key-v1"]+[context[k].encode() for k in ("domain_tag","chain_id","alg_id","param_set_id")]
        parts += [public,payload,tx["nonce"].to_bytes(8,"big"),obj.signature]
        key=hashlib.sha256(b"".join(len(v).to_bytes(8,"big")+v for v in parts)).hexdigest()
        keys[identity]=key
        if key!=entry["cache_key"] or hashlib.sha256(public).hexdigest()!=tx["public_key_id"]:
            bad("real_cache_key","corpus key/public identity mismatch",tx_id=identity)
    if data["config"]["blocks"]!=corpus["workload"]["blocks"]:
        bad("real_payload","manifest blocks differ from trusted corpus")
    previous_hash="0"*64
    for index,spec in enumerate(corpus["workload"]["blocks"]):
        bid=spec["block_id"];fields=corpus["block_objects"][bid]
        objects=[]
        for identity in spec["tx_ids"]:
            tx=corpus["workload"]["transactions"][identity]
            objects.append(Transaction(sender=tx["sender"],receiver=tx["receiver"],amount=tx["amount"],
                timestamp=tx["timestamp"],sender_id=tx["sender_id"],transaction_id=tx["transaction_id"],
                signature=bytes.fromhex(corpus["transactions"][identity]["signature_hex"])))
        obj=Block(fields["index"],objects,fields["previous_hash"],proposer_id=fields["proposer_id"],
                  timestamp=fields["timestamp"],nonce=fields["nonce"])
        if (fields["index"]!=index or fields["previous_hash"]!=previous_hash or fields["hash"]!=obj.hash
                or bytes.fromhex(corpus["blocks"][bid]["payload_hex"])!=obj.get_signable_message().encode()):
            bad("real_payload","frozen block chain/signed bytes mismatch",block_id=bid)
        previous_hash=obj.hash
    offsets={};phases={}
    for record in p.get("worker_clock_offsets",[]):
        phases.setdefault(record["worker_id"],[]).append(record["phase"])
        for probe in record["probes"]:
            a,b,w=probe["dispatcher_before_ns"],probe["dispatcher_after_ns"],probe["worker_ns"]
            if b<a or probe["offset_ns"]!=w-(a+b)//2 or probe["uncertainty_ns"]!=(b-a+1)//2:
                bad("prototype_clock","invalid clock-handshake arithmetic")
        offsets.setdefault(record["worker_id"],[]).extend(record["probes"])
    if runtime:
        for worker in range(data["config"]["k"]):
            if phases.get(worker)!=["before","after"]:
                bad("prototype_clock","missing or duplicate before/after worker handshake",worker_id=worker)
        byjob={j["job_id"]:j for j in jobs}
        for row in rows:
            if row["event"] not in ("start","end"):continue
            job=byjob.get(row["job_id"],{})
            fields=("send_ns",) if row["event"]=="start" else (
                "send_ns","receive_ns","worker_start_ns","worker_end_ns","occupancy_ns","primitive_ns")
            if any(str(job.get(field,""))!=row[field] for field in fields):
                bad("prototype_job_time","event raw clock fields differ from job record",job_id=row["job_id"])
    for j in jobs:
        if j["tx_id"] and j["cache_key"]!=keys.get(j["tx_id"]):
            bad("real_cache_key","logical/physical job has wrong real-byte identity",job_id=j["job_id"])
        if j["status"]!="end":continue
        if not runtime:continue
        try:
            send,receive=j["send_ns"],j["receive_ns"];start,end=j["worker_start_ns"],j["worker_end_ns"]
            if (send>receive or start>end or j["occupancy_ns"]!=receive-send or j["primitive_ns"]!=end-start
                    or abs((send-epoch)/1e9-j["start_t"])>1e-12 or abs((receive-epoch)/1e9-j["end_t"])>1e-12):
                bad("prototype_job_time","occupancy/primitive clock binding mismatch",job_id=j["job_id"])
            probes=offsets[j["worker_id"]]
            lo=min(v["offset_ns"]-v["uncertainty_ns"] for v in probes)
            hi=max(v["offset_ns"]+v["uncertainty_ns"] for v in probes)
            if start<send+lo or end>receive+hi:
                bad("prototype_job_time","primitive outside occupancy after clock uncertainty",job_id=j["job_id"])
        except (KeyError,TypeError,ValueError):bad("prototype_job_time","missing worker timing evidence",job_id=j["job_id"])
        if j["tx_id"]:
            label=corpus["workload"]["transactions"][j["tx_id"]]["sig_label"]
        else:
            spec=next(b for b in corpus["workload"]["blocks"] if b["block_id"]==j["block_id"])
            label=spec.get("block_sig_label","valid")
        if j["outcome"]!=("valid" if label=="valid" else "invalid"):
            bad("prototype_outcome","worker outcome differs from checked corpus label",job_id=j["job_id"])
    return errors,keys,intervals


def overlap(intervals,a,b):
    return sum(max(0,min(b,end)-max(a,start)) for start,end in intervals)


def covered(intervals,a,b):
    cursor=a
    for start,end in intervals:
        if end<cursor:continue
        if start>cursor+1e-12:return False
        cursor=max(cursor,end)
        if cursor>=b-1e-12:return True
    return b<=a
