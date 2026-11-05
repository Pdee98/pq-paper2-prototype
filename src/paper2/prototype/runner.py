"""Manual ARM runner protocol. Importing this module never launches experiments."""

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
import multiprocessing as mp
import os
from pathlib import Path
import platform
import statistics
import shutil
import subprocess
import time
import traceback
import tempfile

from src.paper2.model.service_times import ROOT,derive_seed,STREAM_NAMES
from src.paper2.model.engine import _git_state
from src.paper2.workload import generate_workload
from src.paper2.verify.invariants import check
from . import corpus,replay,public_corpus
from .progress import read_progress,phase_times
from .analysis import references,cells,dispatcher_guard,metrics
from .calibration import calibrate_once
from .runtime import run

BACKENDS=("ed25519","ml_dsa_44","slh_dsa_sha2_128s","xmss")
VALIDATION=("xmss","ml_dsa_44")


def partition_cells(planned):
    """Deviation 2: retain every planned cell; exclude guard failures unchanged."""
    failed=dispatcher_guard(planned)
    return ([c for c in planned if c not in failed],
            [dict(cell=c,reason="dispatcher-bound, not a valid worker-contention test") for c in failed])


def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_bytes(json.dumps(value,indent=2).encode()+b"\n")


def parameters(rate,replicate,period,horizon=90):
    return dict(run_id="paper2-g3-v1",replicate=replicate,horizon=horizon,
        arrivals_valid=dict(kind="poisson",rate=rate),arrivals_invalid=dict(kind="poisson",rate=0),
        fee_distribution=dict(name="uniform_int",low=1,high=10),amount_distribution=dict(name="constant",value=1),
        senders=[f"s{i}" for i in range(64)],initial_balance=10**18,receiver="sink",scheme=dict(signature_bytes=64),
        block_period=period,block_size=256,p_seen=1,invalid_kinds=["bit_flip","random_bytes"],deadline=period)


def settings(workload,cell,output):
    return dict(workload,k=cell["k"],policy=dict(name=cell["policy"]),q_max=10000,coalesce_inflight=False,
        cache=dict(capacity=4096,policy="lru",ttl=2*cell["period"],erase_on_inclusion=False),
        pool=dict(enabled=True,capacity_bytes=16*1024*1024),output_dir=str(output))


def _fresh_entry(pipe,function,args):
    try:pipe.send((True,function(*args)))
    except BaseException:pipe.send((False,traceback.format_exc()))
    finally:pipe.close()


def fresh(function,args,timeout,progress_path=None,phase_timeouts=None,partial_dir=None):
    ctx=mp.get_context("spawn");parent,child=ctx.Pipe(False)
    process=ctx.Process(target=_fresh_entry,args=(child,function,args));process.start();child.close()
    try:
        begin=time.monotonic()
        memory_sampler=None
        if progress_path:
            from .gc_control import MemorySampler
            directory=Path(progress_path).parent
            memory_sampler=MemorySampler(None,directory,[process.pid])
        while not parent.poll(.1):
            if memory_sampler and process.is_alive():
                from .gc_control import MemoryStop
                try:memory_sampler.sample()
                except MemoryStop:
                    process.terminate();process.join(5)
                    from .pause_attribution import recover
                    recover(Path(progress_path).parent,write_missing=True)
                    if partial_dir:shutil.copytree(Path(progress_path).parent,partial_dir,dirs_exist_ok=True)
                    raise
            rows=read_progress(progress_path) if progress_path else []
            phases=[r for r in rows if r["phase"]!="second"]
            last=phases[-1]["phase"] if phases else "process_start_pending"
            active="serialisation" if any(r["phase"]=="serialisation_start" for r in phases) else (
                "prototype window" if any(r["phase"]=="prototype_window_start" for r in phases) else "preparation")
            anchor={"preparation":"process_start","prototype window":"prototype_window_start","serialisation":"serialisation_start"}[active]
            stamp=next((r["monotonic_ns"] for r in phases if r["phase"]==anchor),int(begin*1e9))
            exceeded=phase_timeouts and phases and (time.monotonic_ns()-stamp)/1e9>phase_timeouts[active]
            if time.monotonic()-begin>timeout or exceeded:
                process.terminate();process.join(5)
                evidence=None
                if partial_dir and progress_path:
                    from .pause_attribution import recover
                    evidence=Path(partial_dir)
                    if Path(progress_path).parent.exists():
                        recover(Path(progress_path).parent,write_missing=True)
                        shutil.copytree(Path(progress_path).parent,evidence,dirs_exist_ok=True)
                    else:
                        evidence.mkdir(parents=True,exist_ok=True);recover(evidence,write_missing=True)
                    save(evidence/"timeout.json",dict(last_phase=last,stage=active,partial_outputs_preserved=True))
                raise TimeoutError("fresh-process timeout; last phase: "+last+"; evidence: "+str(evidence))
        success,value=parent.recv();process.join(5)
        if not success:raise RuntimeError(value)
        if process.exitcode!=0:raise RuntimeError("fresh process did not exit successfully")
        return value
    finally:
        if process.is_alive():process.terminate();process.join(5)
        parent.close()


def prototype_run(config,corpus_path,validated_sha256=None):
    begin=time.perf_counter();e,m=run(config,corpus_path,stop_t=105,validated_sha256=validated_sha256)
    rows=read_progress(e.parent/"progress.jsonl")
    result=dict(events=str(e),manifest=str(m),progress=str(e.parent/"progress.jsonl"),
        phase_seconds=phase_times(rows),drain_complete=next(r["drain_complete"] for r in reversed(rows) if r["phase"]=="exit"),
        elapsed=time.perf_counter()-begin,postprocessing="pending deterministic replay")
    save(e.parent/"prototype-receipt.json",result)
    return result


def remaining(root):
    start=json.loads((root/"watchdog.json").read_text())["monotonic_ns"]
    return 280*60-(time.monotonic_ns()-start)/1e9


def project(root,stage,seconds,details):
    record=dict(stage=stage,projected_remaining_seconds=seconds,available_seconds=remaining(root),details=details)
    save(root/("projection-"+stage+".json"),record)
    if seconds>record["available_seconds"]:raise RuntimeError("STOP: remaining fixed protocol exceeds 280-minute budget")


STAGE_CAPS=dict(pilot=10*60,calibration=20*60,presigning=50*60,prototype=88*60)
ENGINEERING_CAPS=None  # Author-approved ARM diagnostic measurements are required first.


def arm_remaining_projection(signing_seconds,run_count,engineering_caps=None):
    caps=engineering_caps if engineering_caps is not None else ENGINEERING_CAPS
    if caps is None:raise RuntimeError("STOP: preparation/serialisation caps unset pending ARM diagnostic")
    return signing_seconds+run_count*(110+caps["preparation"]+caps["serialisation"])+7*60


def account(root,totals,stage,seconds):
    totals[stage]=totals.get(stage,0)+seconds
    save(root/"stage-times.json",dict(elapsed_seconds=totals,caps_seconds=STAGE_CAPS))
    if totals[stage]>STAGE_CAPS[stage]:
        raise RuntimeError("STOP: fixed "+stage+" stage cap exceeded; no protocol reduction")


def merge_samples(paths,target):
    with Path(target).open("x",newline="") as f:
        writer=None
        for path in paths:
            with Path(path).open(newline="") as source:
                reader=csv.DictReader(source)
                if writer is None:writer=csv.DictWriter(f,fieldnames=reader.fieldnames);writer.writeheader()
                writer.writerows(reader)


def execute_occupancy_historical(root):
    if ENGINEERING_CAPS is None:raise RuntimeError("STOP: validation awaits ARM diagnostic and preparation/serialisation caps")
    root=Path(root).resolve()
    if ROOT==root or ROOT in root.parents:raise ValueError("runner output must be outside checkout")
    if platform.machine().lower() not in ("aarch64","arm64") or len(os.sched_getaffinity(0))<4:
        raise RuntimeError("ARM runner with at least four usable vCPUs required")
    if not (root/"conformance.json").is_file():raise RuntimeError("native conformance must precede calibration")
    private=tempfile.TemporaryDirectory(prefix="paper2-g3-presigning-");private_root=Path(private.name)
    start=time.monotonic();state=dict(status="calibration",cells=[],prototypes=[]);stage_times={}
    save(root/"protocol.json",state)
    try:
        calibrations={};all_cal={};pilots={}
        # A small corpus signs once; all nine fixed-corpus calibration runs only verify it.
        for backend in BACKENDS:
            before=time.perf_counter()
            w=generate_workload(parameters(2560,0,.05,horizon=.1))
            data=corpus.build(w,backend,processes=1,primitive_checks=True)
            path=corpus.write(data,private_root/(backend+"-calibration.json"))
            pilot=dict(elapsed=time.perf_counter()-before,presigning=data["presigning"],corpus=str(path))
            pilots[backend]=pilot;save(root/"signing-pilots.json",pilots)
            account(root,stage_times,"pilot",time.perf_counter()-before)
            results=[]
            for k in (1,2,3):
                for rep in range(3):
                    before=time.perf_counter()
                    result=fresh(calibrate_once,(path,k,root/"calibration"/f"{backend}-k{k}-r{rep}",rep),
                                 min(20*60,remaining(root)))
                    account(root,stage_times,"calibration",time.perf_counter()-before)
                    results.append(result)
            all_cal[backend]=results
            save(root/"calibration-index.json",all_cal)
            throughput={k:statistics.fmean(r["throughput"] for r in results if r["k"]==k) for k in (1,2,3)}
            means={};paths={}
            for k in (1,2,3):
                paths[k]=root/"calibration"/f"{backend}-k{k}-occupancy.csv"
                merge_samples([r["samples"] for r in results if r["k"]==k],paths[k])
                if k==1:
                    with paths[k].open(newline="") as f:rows=list(csv.DictReader(f))
                    means={cls:statistics.fmean(int(r["duration_ns"])/1e9 for r in rows if r["job_class"]==cls)
                           for cls in ("admission","block_tx","block_sig")}
            dispatch=max(r["dispatcher_per_tx"] for r in results)
            refs=references(means,throughput,dispatch)
            # Per-k guard uses that k's measured dispatcher work, not the minimum.
            for k in (1,2):
                d=max(r["dispatcher_per_tx"] for r in results if r["k"]==k)
                refs[k]["d_dispatch"]=d
                refs[k]["B_ref"]=min(refs[k]["s_k"]/(means["admission"]+means["block_sig"]/128),1/d if d else math.inf)
                refs[k]["occupancy_samples"]=str(paths[k])
            calibrations[backend]=refs
        planned=cells({name:calibrations[name] for name in VALIDATION})
        state["cells"]=planned;save(root/"planned-cells.json",planned)
        eligible,excluded=partition_cells(planned)
        state["excluded_cells"]=excluded;state["eligible_cells"]=eligible
        save(root/"dispatcher-guard.json",dict(limit=.5,violating_cells=dispatcher_guard(planned),
            excluded_cells=excluded,eligible_cells=eligible,cells=planned,deviation=2))
        save(root/"protocol.json",state)
        if not eligible:raise RuntimeError("No eligible G3 cells: dispatcher-bound, not a valid worker-contention test")
        validation_backends=[b for b in VALIDATION if any(c["backend"]==b for c in eligible)]
        run_count=3*len(eligible)
        inputs=root/"replay-inputs"
        index=replay.initialize(inputs,planned,excluded,os.environ.get("GITHUB_SHA") or _git_state()["commit"],
                                os.environ.get("GITHUB_RUN_ID","local"))
        # Project signing before bulk work. Include key generation, verification,
        # measured signing rate and spawn overhead. Replay is a separate workflow.
        traces={};messages={};sign_projection=0
        for backend in validation_backends:
            peak=max((c for c in eligible if c["backend"]==backend),key=lambda c:c["rate"])
            traces[backend]=[];count=0
            for rep in range(3):
                w=generate_workload(parameters(peak["rate"],rep,peak["period"]))
                file=root/"traces"/f"{backend}-r{rep}.json";save(file,w);traces[backend].append(file)
                count+=len(w["transactions"])+len(w["blocks"])
            # Block signatures are condition-specific even when transactions reuse a master.
            block_count=sum(3*math.floor(90/c["period"]) for c in eligible if c["backend"]==backend)
            n=count+block_count;ledgers=[v for kind in pilots[backend]["presigning"].values() for v in kind["keys"]]
            signed=sum(v["count"] for v in ledgers);sign_seconds=sum(v["signing_ns"] for v in ledgers)/1e9
            key_seconds=statistics.fmean(v["keygen_ns"] for v in ledgers)/1e9
            rate=signed/sign_seconds
            # Separate master/cell batches waste the final partial key and each
            # build also probes parameter size once; allow both explicitly.
            key_bound=math.ceil(n/512)+2*27
            seconds=1.25*(n/rate+key_bound*key_seconds)/2
            # Also allow a complete native verification of the prepared signatures.
            seconds+=n/max(r["throughput"] for r in all_cal[backend] if r["k"]==2)
            sign_projection+=seconds
            messages[backend]=dict(messages=n,key_count_upper_bound=key_bound,signing_rate_per_process=rate,keygen_seconds=key_seconds,
                                   parallel_processes=2,projected_seconds=seconds)
        projection_detail=dict(signing=messages,prototype_runs=run_count,excluded_cells=excluded,
                               simulation="separate deterministic replay workflow; no ARM simulation budget")
        if sign_projection>STAGE_CAPS["presigning"]:
            save(root/"projection-stage-cap-failure.json",projection_detail)
            raise RuntimeError("STOP: fixed signing stage projection exceeds approved cap")
        project(root,"presigning",arm_remaining_projection(sign_projection,run_count),projection_detail)
        masters={}
        for backend in validation_backends:
            for rep,file in enumerate(traces[backend]):
                before=time.perf_counter()
                data=corpus.build(json.loads(file.read_text()),backend,processes=2,primitive_checks=True)
                masters[backend,rep]=corpus.write(data,private_root/f"{backend}-master-r{rep}.json")
                account(root,stage_times,"presigning",time.perf_counter()-before)
        project(root,"prototype",arm_remaining_projection(0,run_count),dict(prototype_runs=run_count,
            simulation="separate replay workflow",signing_projection=messages))
        state["status"]="prototype collection: replay pending"
        for cell_id,cell in enumerate(planned):
            if cell not in eligible:continue
            for rep in range(3):
                if remaining(root)<110+7*60:raise RuntimeError("STOP: insufficient remaining fixed-run/upload budget")
                backend=cell["backend"];master=json.loads(masters[backend,rep].read_text())
                before=time.perf_counter()
                w=generate_workload(parameters(cell["rate"],rep,cell["period"]))
                data=corpus.build(w,backend,processes=2,master=master,primitive_checks=True)
                path=corpus.write(data,private_root/f"cell{cell_id}-r{rep}.json")
                account(root,stage_times,"presigning",time.perf_counter()-before)
                base=root/"validation"/f"cell{cell_id}-r{rep}"
                config=settings(data["workload"],cell,base/"prototype")
                before=time.perf_counter()
                proto=fresh(prototype_run,(config,path,replay.sha256_file(path)),remaining(root),
                    progress_path=base/"prototype/progress.jsonl",
                    phase_timeouts={"preparation":ENGINEERING_CAPS["preparation"],"prototype window":110,
                                    "serialisation":ENGINEERING_CAPS["serialisation"]},
                    partial_dir=root/"timeouts"/f"cell{cell_id}-r{rep}")
                rid=f"cell{cell_id}-r{rep}"
                entry=next(r for r in index["runs"] if r["run_id"]==rid)
                entry["manifest_sha256"]=replay.create_packet(inputs/rid,config,path,proto,
                    calibrations[backend][cell["k"]]["occupancy_samples"],cell,rep)
                state.setdefault("arm_corpus_audits",{})[rid]=replay.read(inputs/rid/"info.json")["arm_corpus_audit"]
                replay.write_index(inputs,index)
                for phase,seconds in proto["phase_seconds"].items():
                    stage="prototype" if phase=="prototype window" else phase
                    stage_times[stage]=stage_times.get(stage,0)+seconds
                    cap=STAGE_CAPS[stage] if stage=="prototype" else run_count*ENGINEERING_CAPS[stage]
                    if stage_times[stage]>cap:raise RuntimeError("STOP: "+stage+" stage cap exceeded")
                save(root/"stage-times.json",dict(elapsed_seconds=stage_times,caps_seconds=dict(STAGE_CAPS,
                    **{s:run_count*ENGINEERING_CAPS[s] for s in ("preparation","serialisation")})))
                state["prototypes"].append(dict(run_id=rid,cell=cell,replicate=rep,prototype=proto))
                save(root/"protocol.json",state)
                state["public_corpus"]=public_corpus.audit_upload(inputs)
                save(root/"protocol.json",state)
                if not proto["drain_complete"]:
                    raise ValueError("prototype incomplete or invariant violations; replay inputs retained")
        index["status"]=replay.PENDING;replay.write_index(inputs,index)
        replay.verify(inputs)
        state["status"]=replay.PENDING
    except BaseException as exc:
        state.update(status="prototype-incomplete: replay pending",failure=str(exc),traceback=traceback.format_exc())
        save(root/"protocol.json",state)
        raise
    finally:
        private.cleanup()
        state["orchestrator_wall_seconds"]=time.monotonic()-start;save(root/"protocol.json",state)
        lines=["# G3 prototype measurement outcome", "", "Status: "+state["status"], "", state.get("failure",""), "",
            "| Backend | k | Policy | Nominal rho | lambda | B_ref | B_cold | lambda*d_dispatch |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for c in state["cells"]:
            lines.append("| "+" | ".join(str(c[k]) for k in ("backend","k","policy","rho","rate","B_ref","B_cold","dispatcher_utilisation"))+" |")
        lines += ["", "## Deviation 2 exclusions", ""]
        for item in state.get("excluded_cells",[]):
            c=item["cell"]
            lines.append(str(c)+": "+item["reason"])
        lines += ["", "Prototype measurements are recorded; metrics and invariant checks run only in replay.",
                  "Paired primary/held-out simulations and G3 agreement are pending the separate replay workflow.",
                  "This ARM workflow makes no G3 agreement pass/fail claim."]
        (root/"PROTOCOL_REPORT.md").write_bytes(("\n".join(lines)+"\n").encode())


def record_host(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    record=dict(platform=platform.platform(),machine=platform.machine(),python=platform.python_version(),
                affinity=sorted(os.sched_getaffinity(0)) if hasattr(os,"sched_getaffinity") else None)
    from .gc_control import memory_snapshot
    record['memory']=memory_snapshot()
    for name,args in (("lscpu",["lscpu"]),("nproc",["nproc"]),("kernel",["uname","-a"])):
        r=subprocess.run(args,capture_output=True,text=True);record[name]=dict(stdout=r.stdout,stderr=r.stderr,returncode=r.returncode)
    for name,file in (("cpuinfo","/proc/cpuinfo"),("governor","/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")):
        try:record[name]=Path(file).read_text()
        except OSError as e:record[name]="UNAVAILABLE: "+str(e)
    save(root/"host.json",record)


def execute(root):
    from .cycle_runner import execute as cycle_execute
    return cycle_execute(root)


def hash_artifacts(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);rows=[]
    for file in sorted(root.rglob("*")):
        if file.is_file() and file.name!="SHA256SUMS":
            h=hashlib.sha256()
            with file.open("rb") as f:
                for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
            rows.append(h.hexdigest()+"  "+file.relative_to(root).as_posix())
    (root/"SHA256SUMS").write_bytes(("\n".join(rows)+"\n").encode())


def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path);p.add_argument("--execute",action="store_true")
    p.add_argument("--record-host",type=Path);p.add_argument("--record-start",type=Path);p.add_argument("--hash-artifacts",type=Path)
    p.add_argument("--require-validation-caps",action="store_true")
    a=p.parse_args()
    if a.require_validation_caps:
        if ENGINEERING_CAPS is None:raise SystemExit("STOP: validation awaits ARM diagnostic; engineering caps unset")
    elif a.record_start:save(a.record_start/"watchdog.json",dict(monotonic_ns=time.monotonic_ns(),work_minutes=280,upload_minutes=10))
    elif a.record_host:record_host(a.record_host)
    elif a.hash_artifacts:hash_artifacts(a.hash_artifacts)
    elif a.execute and a.output and os.environ.get("GITHUB_ACTIONS")=="true":execute(a.output)
    else:p.error("explicit runner execution or a read-only environment/artifact command is required")


if __name__=="__main__":main()
