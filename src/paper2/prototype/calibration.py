"""Fresh-process fixed-corpus throughput and per-job occupancy capture."""

import csv
import json
from multiprocessing.connection import wait
from pathlib import Path
import time

from .corpus import signed_parts
from .workers import Workers
from .runtime import run
from .analysis import distribution,costs
from .analysis import paired
from src.paper2.verify.invariants import check


def calibrate_once(corpus_path,k,output,replicate,warmup=2,measurement=10):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    corpus=json.loads(Path(corpus_path).read_text());backend=corpus["backend"]
    txs=list(corpus["transactions"].values())[:128]
    if len(txs)!=128 or not corpus["blocks"]:raise ValueError("calibration requires 128 distinct transaction messages and a block")
    block=next(iter(corpus["blocks"].values()))
    fixed=[("admission",signed_parts(t)) for t in txs]+[("block_tx",signed_parts(t)) for t in txs]+[("block_sig",signed_parts(block))]
    keys=list({parts[2] for _,parts in fixed})
    workers=Workers(k,backend,keys)
    samples=[];running={};serial=0;decision=[]
    epoch=time.monotonic_ns();end=(warmup+measurement)*1e9
    def dispatch(worker):
        nonlocal serial
        begin=time.monotonic_ns();cls,parts=fixed[serial%len(fixed)];identity=str(serial);serial+=1
        # Selection time is a diagnostic, not a substitute for Model decision costs.
        decision.append(time.monotonic_ns()-begin)
        send=time.monotonic_ns();workers.pipes[worker].send(("verify",identity,*parts))
        running[worker]=(identity,cls,send)
    try:
        for worker in range(k):dispatch(worker)
        while running:
            ready=wait([workers.pipes[w] for w in running],timeout=15)
            if not ready:raise TimeoutError("concurrency calibration worker stalled")
            for worker in list(running):
                pipe=workers.pipes[worker]
                if pipe not in ready:continue
                reply=pipe.recv();receive=time.monotonic_ns();identity,cls,send=running.pop(worker)
                if reply[0]!="result" or reply[1]!=identity or not reply[4]:
                    raise RuntimeError("fixed valid corpus failed verification")
                _,_,start,finish,_=reply
                samples.append(dict(backend=backend+":"+cls,operation="verify",variant="valid",
                    duration_ns=receive-send,primitive_ns=finish-start,job_class=cls,
                    source=f"concurrency-k{k}-rep{replicate}",send_ns=send-epoch,receive_ns=receive-epoch))
                if receive-epoch<end:dispatch(worker)
        workers.handshake("after")
    finally:workers.close()
    selected=[s for s in samples if warmup*1e9<=s["send_ns"]<end]
    with (output/"occupancy.csv").open("x",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=tuple(samples[0]));writer.writeheader();writer.writerows(selected)
    result=dict(backend=backend,k=k,replicate=replicate,warmup=warmup,measurement=measurement,
        throughput=len(selected)/measurement,primitive_and_occupancy_samples=len(selected),
        selection_overhead_ns=distribution(decision),worker_metadata=workers.metadata,
        clock_offsets=workers.clock_records,samples=str(output/"occupancy.csv"))
    # Reuse actual Model decisions for a separate dispatcher-cost probe in this
    # fresh calibration process. Its samples never come from a validation run.
    probes=[];model_costs=[]
    for policy in ("fifo","block_priority"):
        config=dict(corpus["workload"],k=k,policy=dict(name=policy),q_max=10000,
            cache=dict(capacity=4096,ttl=2*corpus["workload"]["block_period"]),
            pool=dict(enabled=True,capacity_bytes=16*1024*1024),output_dir=str(output/("dispatcher-"+policy)))
        e,m=run(config,corpus_path)
        violations=check(e,e.parent/"jobs.csv",m)
        if violations:raise ValueError("calibration prototype invariants failed: "+str(violations[:3]))
        meta=json.loads(m.read_text());n=len(corpus["workload"]["admissions"]);mapped=costs(meta)
        probes.append(dict(policy=policy,dispatcher_per_tx=meta["prototype"]["dispatcher_non_ipc_ns"]/max(n,1)/1e9,
                           dispatcher_definition="active minus measured Pipe send/recv/poll; waits already excluded; no IPC cost added to simulator",
                           mapped_dispatcher=mapped,manifest=str(m)))
        cpu=time.process_time()
        se,sm=paired(dict(config,output_dir=str(output/("simulation-probe-"+policy))),corpus_path,
                     output/"occupancy.csv",backend,mapped["structural_cost"],mapped["state_cost"])
        failures=check(se,se.parent/"jobs.csv",sm)
        if failures:raise ValueError("calibration simulation invariants failed: "+str(failures[:3]))
        count=n+sum(len(b["tx_ids"])+1 for b in config["blocks"])
        model_costs.append((time.process_time()-cpu)/max(count,1))
    result.update(dispatcher_per_tx=max(p["dispatcher_per_tx"] for p in probes),dispatcher_probes=probes,
                  simulation_cpu_seconds_per_logical_item=max(model_costs))
    (output/"calibration.json").write_bytes(json.dumps(result,indent=2).encode()+b"\n")
    return result
