"""Approved load reference, dispatcher guard, samples, and paired metric definitions."""

from collections import Counter
import csv
import json
import math
from pathlib import Path
import statistics

from src.paper2.verify.little import QueueCounterIntegral
from src.paper2.model.engine import Model, run_model
from src.paper2.model.service_times import sha256_file
from .corpus import cache_key,signed_parts


def references(means,throughput,dispatcher_per_tx):
    if min(means.values())<=0 or min(throughput.values())<=0 or dispatcher_per_tx<0:
        raise ValueError("invalid session calibration")
    result={}
    for k in (1,2):
        scaling=throughput[k]/throughput[1]
        warm=scaling/(means["admission"]+means["block_sig"]/128)
        cold=scaling/(means["admission"]+means["block_tx"]+means["block_sig"]/128)
        result[k]=dict(s_k=scaling,B_ref=min(warm,1/dispatcher_per_tx if dispatcher_per_tx else math.inf),
                       B_cold=cold,d_dispatch=dispatcher_per_tx)
    return result


def cells(calibrations):
    rows=[]
    for backend,cal in calibrations.items():
        for k in (1,2):
            ref=cal[k]
            for policy in ("fifo","block_priority"):
                for rho in (.5,.85):
                    rate=rho*ref["B_ref"]
                    rows.append(dict(backend=backend,k=k,policy=policy,rho=rho,rate=rate,
                        period=128/rate,dispatcher_utilisation=rate*ref["d_dispatch"],**ref))
    return rows


def dispatcher_guard(rows):
    # This function is called for the ENTIRE matrix before any validation is launched.
    return [r for r in rows if r["dispatcher_utilisation"]>.5]


def distribution(values):
    values=sorted(values)
    if not values:return dict(count=0,mean=None,p50=None,p95=None,minimum=None,maximum=None)
    return dict(count=len(values),mean=statistics.fmean(values),p50=values[math.ceil(.5*len(values))-1],
        p95=values[math.ceil(.95*len(values))-1],minimum=values[0],maximum=values[-1])


def costs(meta):
    rows=meta["prototype"]["dispatcher_costs"];result={}
    for kind in ("structural","state"):
        selected=[r for r in rows if r["kind"]==kind]
        units=sum(r["items"] for r in selected)
        result[kind+"_cost"]=sum(r["duration_ns"] for r in selected)/units/1e9 if units else 0
    result["unmodelled_ns"]=meta["prototype"]["unmodelled_dispatcher_ns"]
    return result


def read_jobs(path):
    with Path(path).open(newline="",encoding="utf-8") as f:return [json.loads(r["record"]) for r in csv.DictReader(f)]


def metrics(events,jobs,manifest,warmup=30,horizon=90):
    meta=json.loads(Path(manifest).read_text());records=read_jobs(jobs);window=horizon-warmup
    physical=[j for j in records if j["start_t"] is not None]
    cohort=[j for j in records if j["job_class"]=="admission" and j["enqueue_t"] is not None
            and warmup<=j["enqueue_t"]<horizon]
    complete=all(j["status"]=="end" for j in cohort)
    waits=[j["start_t"]-j["enqueue_t"] for j in cohort if j["start_t"] is not None]
    blocks=[b for b in meta["blocks"].values() if warmup<=b["arrival_t"]<horizon]
    decided=[b for b in blocks if b["accept_t"] is not None or b["reject_t"] is not None]
    complete=complete and len(decided)==len(blocks) and not meta.get("prototype",{}).get("incomplete",False)
    delays=[(b["accept_t"] if b["accept_t"] is not None else b["reject_t"])-b["arrival_t"] for b in decided]
    misses=sum((b["accept_t"] if b["accept_t"] is not None else b["reject_t"])>b["deadline_t"] for b in decided)
    admissions=sum(c["passed"] and warmup<=c["t"]<horizon for c in meta["admission_checks"])
    integral=QueueCounterIntegral(warmup,horizon);timeline=[]
    with Path(events).open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            t=float(row["t"]);qa,qb=int(row["q_admission"]),int(row["q_block"])
            integral.observe(t,qa,qb,row["event"],row["job_class"])
            timeline.append((t,qa,qb))
    samples=[];cursor=0;qa=qb=0
    for t in range(math.ceil(warmup),math.floor(horizon)+1):
        while cursor<len(timeline) and timeline[cursor][0]<=t:
            _,qa,qb=timeline[cursor];cursor+=1
        samples.append(dict(t=t,q_admission=qa,q_block=qb))
    def at(t):
        value=(0,0)
        for when,a,b in timeline:
            if when>t:break
            value=(a,b)
        return dict(admission=value[0],block=value[1])
    boundaries=dict(warmup=at(warmup),horizon=at(horizon))
    observed=[(r[1],r[2]) for r in timeline if warmup<=r[0]<=horizon]
    observed.append(tuple(boundaries["warmup"][c] for c in ("admission","block")))
    logical=[j for j in records if j["job_class"]=="block_tx" and
             warmup<=meta["blocks"][j["block_id"]]["arrival_t"]<horizon]
    busy=sum(max(0,min(j["end_t"] or horizon,horizon)-max(j["start_t"],warmup)) for j in physical)
    timing=[j for j in physical if warmup<=j["start_t"]<horizon and "primitive_ns" in j]
    dispatch=[j["dispatch_to_start_ns"]/1e9 for j in timing]
    demand={cls:sum(max(0,min(j["end_t"] or horizon,horizon)-max(j["start_t"],warmup))
                   for j in physical if j["job_class"]==cls) for cls in ("admission","block_tx","block_sig")}
    cfg=meta["config"];valid_arrivals=sorted(a["arrival_t"] for a in cfg["admissions"]
                                           if cfg["transactions"][a["tx_id"]]["sig_label"]=="valid")
    backlog=[];cursor=0;included=0
    for i,b in enumerate(cfg["blocks"]):
        t=cfg["block_times"][i] if "block_times" in cfg else cfg.get("block_start",0)+i*cfg.get("block_period",1)
        while cursor<len(valid_arrivals) and valid_arrivals[cursor]<t:cursor+=1
        included+=len(b["tx_ids"])
        backlog.append(dict(block_id=b["block_id"],scheduled_t=t,valid_waiting_after_proposal=cursor-included))
    return dict(complete=complete,block_count=len(blocks),mean_block_delay=statistics.fmean(delays) if delays else None,
        p95_block_delay=distribution(delays)["p95"],deadline_miss_rate=misses/len(blocks) if blocks else None,
        admission_throughput=admissions/window,mean_admission_wait=statistics.fmean(waits) if waits else None,
        realised_worker_utilisation=busy/(window*meta["config"]["k"]),
        block_tx_cache_hit_rate=sum(j["status"]=="cache_hit" for j in logical)/len(logical) if logical else None,
        realised_job_mix=dict(Counter(j["job_class"] for j in physical if warmup<=j["start_t"]<horizon)),
        realised_worker_time_by_class=demand,
        realised_worker_seconds_per_enqueued_admission={cls:value/max(1,len(cohort)) for cls,value in demand.items()},
        proposer_backlog=backlog,
        proposer_backlog_scope="scheduled proposer; valid local arrivals (matrix p_seen=1); not verifier queue",
        queue_mean=dict(admission=integral.area("q_admission")/window,block=integral.area("q_block")/window),
        queue_integrals=dict(admission=integral.area("q_admission"),block=integral.area("q_block")),
        queue_maxima=dict(admission=max(r[0] for r in observed),block=max(r[1] for r in observed)),
        queue_boundaries=boundaries,
        queue_samples=samples,dispatch_to_start=distribution(dispatch),
        dispatch_to_start_definition="policy dispatch row to dispatcher send (occupancy start)",
        dispatch_to_worker_start=distribution([j["dispatch_to_worker_start_ns"]/1e9 for j in timing]),
        dispatch_to_worker_start_definition="policy dispatch to primitive start; minimum-RTT pre-run clock offset; uncertainty retained per job",
        ipc_overhead=distribution([(j["occupancy_ns"]-j["primitive_ns"])/1e9 for j in timing]),
        release_lateness=distribution([r["lateness"] for r in meta.get("prototype",{}).get("releases",[]) if warmup<=r["release_t"]<horizon]),
        rejected_blocks=sum(not b["valid"] for b in decided))


BANDS=dict(mean_block_delay=.10,mean_admission_wait=.10,admission_throughput=.10,
           p95_block_delay=.15,deadline_miss_rate=.02)


def compare(prototype,simulation,diagnostic=False):
    checks={}
    for name,limit in BANDS.items():
        a,b=prototype[name],simulation[name]
        error=None if a is None or b is None else abs(b-a)
        if error is not None and name!="deadline_miss_rate":
            error=error/abs(a) if a else (0 if b==0 else math.inf)
        checks[name]=dict(prototype=a,simulation=b,error=error,limit=limit,passed=error is not None and error<=limit)
    passed=prototype["complete"] and simulation["complete"] and all(c["passed"] for c in checks.values())
    return dict(role="held-out diagnostic" if diagnostic else "primary agreement",passed=passed,
                gates_validation=not diagnostic,checks=checks)


def samples_from_jobs(jobs,path,backend,source):
    rows=[j for j in read_jobs(jobs) if j["status"]=="end"]
    with Path(path).open("x",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=("backend","operation","variant","duration_ns","primitive_ns","job_class","source"))
        writer.writeheader()
        for j in rows:writer.writerow(dict(backend=backend+":"+j["job_class"],operation="verify" if j["outcome"]=="valid" else "verify_invalid",
            variant="valid" if j["outcome"]=="valid" else j["sig_label"],duration_ns=j["occupancy_ns"],
            primitive_ns=j["primitive_ns"],job_class=j["job_class"],source=source))
    return Path(path)


class CapturedService:
    def __init__(self,path,backend):
        self.tables={};self.inputs=[dict(path=str(Path(path).resolve()),sha256=sha256_file(Path(path)),backend=backend)]
        with Path(path).open(newline="") as f:
            for r in csv.DictReader(f):
                if r["backend"].startswith(backend+":"):
                    label="valid" if r["operation"]=="verify" else r["variant"]
                    self.tables.setdefault((r["job_class"],label),[]).append(int(r["duration_ns"])/1e9)
    def sample(self,cls,label,draw):
        values=self.tables.get((cls,label))
        if not values:raise ValueError("no occupancy samples for executed class/label: "+cls+"/"+label)
        return values[draw%len(values)],"valid" if label=="valid" else "invalid"


class PairedModel(Model):
    def __init__(self,config,corpus_path,sample_path,backend):
        self.corpus_path=Path(corpus_path).resolve();self.corpus=json.loads(self.corpus_path.read_text())
        super().__init__(config)
        self.service=CapturedService(sample_path,backend)
        self.config["prototype"]=dict(mode="real-byte-simulation-v1")
    def _key(self,tx):
        payload,signature,public=signed_parts(self.corpus["transactions"][tx["tx_id"]])
        return cache_key(self.corpus["context"],public,payload,tx["nonce"],signature)
    def extra_manifest(self,directory):
        import os
        return dict(prototype=dict(mode="real-byte-simulation-v1",corpus_path=os.path.relpath(self.corpus_path,directory),
                                  corpus_sha256=sha256_file(self.corpus_path)))


def paired(config,corpus_path,sample_path,backend,structural_cost,state_cost):
    c=dict(config,structural_cost=structural_cost,state_cost=state_cost,service=dict(mode="constant",seconds={
        name:dict(valid=0,bit_flip=0,random_bytes=0) for name in ("admission","block_tx","block_sig")}))
    return run_model(c,model_type=lambda value:PairedModel(value,corpus_path,sample_path,backend))
