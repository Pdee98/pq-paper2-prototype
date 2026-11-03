"""One manual ARM diagnostic; its evidence is never a G3 validation repetition."""

import argparse
import bisect
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import tempfile
import time

from src.paper2.model.engine import _git_state
from src.paper2.model.service_times import ROOT, sha256_file
from src.paper2.workload import generate_workload
from . import corpus, public_corpus, replay, runner
from .analysis import distribution, references, read_jobs
from .calibration import calibrate_once
from .progress import read_progress, phase_times

RUN_ID="paper2-g3-diag-v1"
PURPOSE="DIAGNOSTIC"
# Diagnostic watchdogs only. Production preparation/serialisation caps remain unset.
TIMEOUTS={"pilot":600,"calibration":1200,"presigning":900,
          "preparation":900,"prototype window":110,"serialisation":1200}
RUN6=dict(pilot=75.90944254599981,calibration=535.1138159300003,
          presigning=2383.4357920620005,xmss_projection=1812.09324607673,
          ml_dsa_projection=404.23775415266033,
          signing_rate=350.45827532947476,keygen_seconds=.6823413615)


def diagnostic_parameters(rate,period,horizon=90):
    return dict(runner.parameters(rate,0,period,horizon),run_id=RUN_ID)


def projection():
    """Exact generator counts; author-supplied run #6 timings, not inferred shares."""
    workload=generate_workload(diagnostic_parameters(1115.433019832252,.11475364071546823))
    tx=len(workload["transactions"]);blocks=len(workload["blocks"])
    keys=math.ceil(tx/512)+math.ceil(blocks/512)
    margin=RUN6["presigning"]/(RUN6["xmss_projection"]+RUN6["ml_dsa_projection"])
    signing=((tx+blocks)/RUN6["signing_rate"]+keys*RUN6["keygen_seconds"])/2+RUN6["keygen_seconds"]
    signing*=margin
    verification=(tx+blocks)*.0004486
    measured_basis=RUN6["pilot"]+RUN6["calibration"]+signing+verification+110
    return dict(purpose=PURPOSE,source="run #6 artifact values supplied by author; no local stage-times.json",
        run_id=RUN_ID,transactions=tx,blocks=blocks,messages=tx+blocks,signing_keys=keys,size_probe_keys=1,
        observed_projection_margin=margin,presigning_seconds=signing,verification_estimate_seconds=verification,
        conservative_full_pilot_seconds=RUN6["pilot"],conservative_full_calibration_seconds=RUN6["calibration"],
        estimated_post_native_seconds_excluding_unmeasured_preparation_serialisation=measured_basis,
        unmeasured_reserves=dict(preparation=900,serialisation=1200,upload=600,native_build=2400,conformance=900),
        total_planning_reservation_seconds=measured_basis+900+1200+600+2400+900,
        diagnostic_stage_timeouts_seconds=TIMEOUTS,job_timeout_minutes=180,
        caveat="Full-run pilot/calibration used conservatively; preparation, serialisation, native build and conformance are UNVERIFIED reserves, not measured estimates")


def preflight():
    if platform.machine().lower() not in ("aarch64","arm64") or len(os.sched_getaffinity(0))<4:
        raise RuntimeError("ARM runner with at least four usable vCPUs required")


def collect(root):
    root=Path(root).resolve()
    if root==ROOT or ROOT in root.parents:raise ValueError("diagnostic output must be outside checkout")
    preflight()
    if not (root/"conformance.json").is_file():raise RuntimeError("native conformance must precede calibration")
    state=dict(purpose=PURPOSE,run_id=RUN_ID,status="DIAGNOSTIC: collecting",excluded_from_G3=True,
               code_commit=os.environ.get("GITHUB_SHA") or _git_state()["commit"],
               source_run_id=os.environ.get("GITHUB_RUN_ID","local"),projection=projection())
    runner.save(root/"protocol.json",state)
    try:
        # Raw build ledgers stay outside ALL artifact upload roots.
        with tempfile.TemporaryDirectory(prefix="paper2-diagnostic-private-") as td:
            private=Path(td);before=time.perf_counter()
            pilot=corpus.build(generate_workload(diagnostic_parameters(2560,.05,.1)),"xmss",primitive_checks=True)
            cp=corpus.write(pilot,private/"calibration.json")
            state["pilot_seconds"]=time.perf_counter()-before
            if state["pilot_seconds"]>TIMEOUTS["pilot"]:raise TimeoutError("diagnostic pilot watchdog")
            before=time.perf_counter();results=[]
            for k in (1,2,3):
                for rep in range(3):
                    budget=TIMEOUTS["calibration"]-(time.perf_counter()-before)
                    if budget<=0:raise TimeoutError("diagnostic calibration watchdog")
                    results.append(runner.fresh(calibrate_once,(cp,k,root/"calibration"/f"xmss-k{k}-r{rep}",rep),budget))
            state["calibration_seconds"]=time.perf_counter()-before
            runner.save(root/"calibration-index.json",results)
            held=root/"xmss-k1-occupancy.csv"
            runner.merge_samples([r["samples"] for r in results if r["k"]==1],held)
            with held.open(newline="") as stream:samples=list(csv.DictReader(stream))
            means={c:statistics.fmean(int(r["duration_ns"])/1e9 for r in samples if r["job_class"]==c)
                   for c in ("admission","block_tx","block_sig")}
            throughput={k:statistics.fmean(r["throughput"] for r in results if r["k"]==k) for k in (1,2,3)}
            d=max(r["dispatcher_per_tx"] for r in results if r["k"]==1)
            ref=references(means,throughput,d)[1];rate=.5*ref["B_ref"]
            cell=dict(backend="xmss",k=1,policy="fifo",rho=.5,rate=rate,period=128/rate,
                      dispatcher_utilisation=rate*d,**ref)
            state["cell"]=cell;state["guard_holds"]=cell["dispatcher_utilisation"]<=.5
            runner.save(root/"protocol.json",state)
            if not state["guard_holds"]:raise RuntimeError("DIAGNOSTIC STOP: dispatcher guard exceeded; no prototype launched")
            before=time.perf_counter()
            doc=corpus.build(generate_workload(diagnostic_parameters(rate,cell["period"])),"xmss",processes=2,primitive_checks=True)
            cp=corpus.write(doc,private/"validation.json");validated=sha256_file(cp)
            state["presigning_seconds"]=time.perf_counter()-before
            if state["presigning_seconds"]>TIMEOUTS["presigning"]:raise TimeoutError("diagnostic presigning watchdog")
            cfg=runner.settings(doc["workload"],cell,root/"prototype")
            proto=runner.fresh(runner.prototype_run,(cfg,cp,validated),sum(TIMEOUTS[s] for s in
                ("preparation","prototype window","serialisation")),progress_path=root/"prototype/progress.jsonl",
                phase_timeouts=TIMEOUTS,partial_dir=root/"timeout-evidence")
            inputs=root/"replay-inputs";packet=inputs/RUN_ID
            digest=replay.create_packet(packet,cfg,cp,proto,held,cell,0)
            index=dict(purpose=PURPOSE,run_id=RUN_ID,code_commit=state["code_commit"],source_run_id=state["source_run_id"],
                       packet_sha256=digest,excluded_from_G3=True)
            replay.save(inputs/"DIAGNOSTIC_INDEX.json",index)
            (inputs/"DIAGNOSTIC_INDEX.sha256").write_text(sha256_file(inputs/"DIAGNOSTIC_INDEX.json")+"\n")
            state.update(status="DIAGNOSTIC: prototype recorded; analysis pending replay",prototype=proto,
                         public_corpus=public_corpus.audit_upload(inputs))
    except BaseException as exc:
        state.update(status="DIAGNOSTIC: stopped",failure=str(exc));raise
    finally:
        # Per-file corpus hashes and compressed/uncompressed totals precede upload.
        runner.save(root/"protocol.json",state)


def verify(root,source_run_id):
    root=Path(root);path=root/"DIAGNOSTIC_INDEX.json";index=replay.read(path)
    if sha256_file(path)!=(root/"DIAGNOSTIC_INDEX.sha256").read_text().strip():raise ValueError("diagnostic index SHA-256 mismatch")
    if index["purpose"]!=PURPOSE or index["run_id"]!=RUN_ID or index["source_run_id"]!=str(source_run_id):
        raise ValueError("diagnostic provenance mismatch")
    packet=root/RUN_ID
    if sha256_file(packet/"REPLAY_MANIFEST.json")!=index["packet_sha256"]:raise ValueError("diagnostic packet SHA-256 mismatch")
    replay.verify_files(packet,"REPLAY_MANIFEST.json");public_corpus.audit_upload(root)
    return index,packet


def verify_checkout(index):
    if os.environ.get("GITHUB_ACTIONS")=="true" and _git_state()["commit"]!=index["code_commit"]:
        raise ValueError("diagnostic replay checkout differs from source commit")


class SpanIntegral:
    """Union busy time with logarithmic queries, including large trace gaps."""
    def __init__(self,spans):
        self.starts=[a for a,b in spans];self.ends=[b for a,b in spans];self.prefix=[0.]
        for a,b in spans:self.prefix.append(self.prefix[-1]+b-a)
    def at(self,t):
        i=bisect.bisect_right(self.ends,t)
        return self.prefix[i]+(max(0,t-self.starts[i]) if i<len(self.starts) else 0)


def overlap(start,end,spans):
    if isinstance(spans,SpanIntegral):return max(0,spans.at(end)-spans.at(start))
    return sum(max(0,min(end,b)-max(start,a)) for a,b in spans if b>start and a<end)


def may_prepare_validation(drain,calibration_utilisation,observed_busy,hit,first_drop,violations):
    return (drain and calibration_utilisation<=.5 and observed_busy<=.5 and
            hit is not None and hit>=.9 and first_drop is None and not violations)


def analyse(root,output,source_run_id):
    """Post-processing only, on x86 replay. Never computes G3 agreement."""
    index,packet=verify(root,source_run_id);verify_checkout(index);output=Path(output).resolve()
    if output==ROOT or ROOT in output.parents:raise ValueError("diagnostic analysis must be outside checkout")
    output.mkdir(parents=True,exist_ok=False)
    proto=replay.postprocess_prototype(packet,output/"prototype-check")
    meta=replay.read(packet/"prototype/manifest.json");p=meta["prototype"]
    records=read_jobs(packet/"prototype/jobs.csv");seconds=[dict(second=s,arrived=0,admitted=0,started=0,completed=0,
        block_tx_hit=0,block_tx_miss=0,q_admission=0,q_block=0) for s in range(105)]
    spans_raw=replay.read(packet/"prototype/dispatcher_spans.json")
    spans=[]
    for row in spans_raw:
        a,b=row["start_t"],row["end_t"]
        if spans and a<=spans[-1][1]:spans[-1]=(spans[-1][0],max(b,spans[-1][1]))
        else:spans.append((a,b))
    spans=SpanIntegral(spans)
    admission_ends={};qa=qb=busy=0;previous=0.;idle=covered=0.;cursor=0;first_drop=None
    with (packet/"prototype/events.csv").open(newline="") as stream:
        for r in csv.DictReader(stream):
            t=float(r["t"]);end=min(105,t)
            if qa+qb>0 and busy<1 and end>previous:
                idle+=end-previous;covered+=overlap(previous,end,spans)
            while cursor<105 and cursor+1<=t:
                seconds[cursor].update(q_admission=qa,q_block=qb);cursor+=1
            qa,qb,busy=int(r["q_admission"]),int(r["q_block"]),int(r["busy_workers"])
            previous=end
            i=int(t)
            if 0<=i<105:
                target=seconds[i];event=r["event"]
                if event=="tx_arrive":target["arrived"]+=1
                if event=="start":target["started"]+=1
                if event=="end":target["completed"]+=1
                if r["job_class"]=="block_tx" and event in ("cache_hit","cache_miss"):
                    target["block_tx_"+event[6:]]+=1
            if r["event"]=="end" and r["job_class"]=="admission" and r["outcome"]=="valid":
                admission_ends[r["tx_id"]]=t
    if qa+qb>0 and busy<1 and previous<105:
        idle+=105-previous;covered+=overlap(previous,105,spans)
    while cursor<105:seconds[cursor].update(q_admission=qa,q_block=qb);cursor+=1
    for r in meta["admission_checks"]:
        if r["passed"] and 0<=int(r["t"])<105:seconds[int(r["t"])]["admitted"]+=1
    for r in seconds:
        n=r["block_tx_hit"]+r["block_tx_miss"]
        r["block_tx_hit_rate"]=r["block_tx_hit"]/n if n else None
        r["dispatcher_busy_fraction"]=overlap(r["second"],r["second"]+1,spans)
        if first_drop is None and n and r["block_tx_hit_rate"]<.5:first_drop=r["second"]
    phases=read_progress(packet/"prototype/progress.jsonl");timing=phase_times(phases)
    observed_guard=overlap(30,90,spans)/60
    info=replay.read(packet/"info.json");cell=info["cell"]
    hit=proto["metrics"]["block_tx_cache_hit_rate"]
    drain=not p["incomplete"]
    eligible=may_prepare_validation(drain,cell["dispatcher_utilisation"],observed_guard,hit,first_drop,proto["violations"])
    occupancy={}
    for c in ("admission","block_tx","block_sig"):
        jobs=[j for j in records if j["job_class"]==c and "occupancy_ns" in j]
        occupancy[c]={name:distribution([j[field]/1e3 for j in jobs]) for name,field in
                      (("occupancy_us","occupancy_ns"),("primitive_us","primitive_ns"))}
    releases={r["identity"]:r for r in p["releases"] if r["event"]=="block_arrive"}
    arrivals={a["tx_id"]:a["arrival_t"] for a in meta["config"]["admissions"]}
    lags=[]
    for b in meta["config"]["blocks"]:
        release=releases.get(b["block_id"])
        if not release:continue
        for tx in b["tx_ids"]:
            finish=admission_ends.get(tx)
            lags.append(dict(block_id=b["block_id"],tx_id=tx,admission_completion_t=finish,
                admission_completion_lag=None if finish is None else finish-arrivals[tx],
                block_arrival_lag=release["lateness"],
                admission_complete_before_block=finish is not None and finish<=release["release_t"]))
    report=dict(purpose=PURPOSE,excluded_from_G3=True,source_run_id=str(source_run_id),drain_complete=drain,
        prototype_violations=proto["violations"],phase_seconds=timing,occupancy_by_class=occupancy,
        row_counts=dict(events=p["event_buffer"]["rows"],jobs=len(records),spans=len(spans_raw)),
        peak_parent_rss_bytes=max((r.get("peak_parent_rss_bytes",0) for r in phases),default=0),
        measurement_window_block_tx_hit_rate=hit,first_second_hit_rate_below_50_percent=first_drop,
        calibration_dispatcher_utilisation=cell["dispatcher_utilisation"],measurement_dispatcher_busy_fraction=observed_guard,
        idle_while_waiting_seconds=idle,idle_covered_seconds=covered,idle_uncovered_seconds=max(0,idle-covered),
        public_corpus=public_corpus.inventory(root),
        next_action="AUTHOR REVIEW: preparation/serialisation caps may be recorded; not applied" if eligible and not proto["violations"] else "STOP: report to author; do not prepare run #7",
        recommended_caps_seconds={name:2*timing[name] for name in ("preparation","serialisation")} if eligible and not proto["violations"] else None)
    for name,rows in (("per-second.csv",seconds),("admission-block-lags.csv",lags)):
        with (output/name).open("x",newline="") as stream:
            if rows:
                writer=csv.DictWriter(stream,fieldnames=tuple(rows[0]));writer.writeheader();writer.writerows(rows)
    runner.save(output/"DIAGNOSTIC_REPORT.json",report)
    runner.save(output/"prototype-metrics.json",proto)
    (output/"DIAGNOSTIC_REPORT.md").write_text("# DIAGNOSTIC: excluded from G3\n\n"+report["next_action"]+"\n\n```json\n"+json.dumps(report,indent=2)+"\n```\n")
    replay.seal(output,"RESULT_MANIFEST.json")
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument("command",choices=("preflight","projection","collect","prepare","run","gather"))
    p.add_argument("--output",type=Path);p.add_argument("--inputs",type=Path);p.add_argument("--source-run-id")
    p.add_argument("--run-id");p.add_argument("--results",type=Path);a=p.parse_args()
    if a.command=="preflight":preflight()
    elif a.command=="projection":print(json.dumps(projection(),indent=2))
    elif a.command=="collect":
        if os.environ.get("GITHUB_ACTIONS")!="true":p.error("manual ARM workflow only")
        collect(a.output)
    elif a.command=="prepare":
        index,_=verify(a.inputs,a.source_run_id)
        matrix=json.dumps(dict(include=[dict(run_id=RUN_ID)]),separators=(",",":"))
        with open(os.environ["GITHUB_OUTPUT"],"a") as stream:
            stream.write("matrix="+matrix+"\ncode_commit="+index["code_commit"]+"\n")
    elif a.command=="run":analyse(a.inputs,a.output,a.source_run_id)
    else:
        index,_=verify(a.inputs,a.source_run_id);verify_checkout(index)
        found=list(a.results.rglob("DIAGNOSTIC_REPORT.json"))
        if len(found)!=1:raise ValueError("missing/duplicate diagnostic analysis")
        replay.verify_files(found[0].parent,"RESULT_MANIFEST.json")
        import shutil
        shutil.copytree(found[0].parent,a.output,dirs_exist_ok=False)


if __name__=="__main__":main()
