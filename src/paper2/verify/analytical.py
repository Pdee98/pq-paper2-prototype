"""Pre-registered G2: real model artifacts versus M/G/1 formulas."""

import argparse
from contextlib import nullcontext
import csv
import hashlib
import json
import math
import statistics
import tempfile
import time
from pathlib import Path

from src.paper2.model import run_model
from src.paper2.model.service_times import ROOT, CalibrationSamples, WorkloadStream, derive_seed, sha256_file
from src.paper2.workload import generate_workload
from src.paper2.workload.generator import arrival_times
from .little import measure_replicate, legacy_interval_mean

PRE_REGISTRATION_SHA256 = "9c27a7102002d693e405f878ebc65fc523e2b163b5a02a4f5bcf1eb3c8ba8720"


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--reevaluate-first", type=Path, help="reconstruct only the already-run case 0/replicate 0 using this prior summary")
    args=parser.parse_args()
    prior = json.loads(args.reevaluate_first.read_text(encoding="utf-8")) if args.reevaluate_first else None
    if prior is not None and (len(prior["replicate_rows"]) != 1 or
            any(prior["replicate_rows"][0][key] != value for key,value in
                dict(case=0,replicate=0,policy="fifo",rho_admission=0.3,rho_block=0).items())):
        raise ValueError("re-evaluation requires the original single case 0/replicate 0 summary")
    target=Path(args.summary).resolve()
    if target == ROOT or ROOT in target.parents:
        raise ValueError("summary must be outside repository")
    if args.reevaluate_first and target == args.reevaluate_first.resolve():
        raise ValueError("preserve the original analytical summary")
    report=ROOT/"research/paper2/phase4/VERIFICATION_REPORT.md"
    text=report.read_text(encoding="utf-8")
    snapshot=text.split("\n## Execution evidence and gate status",1)[0]
    snapshot_sha=hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    if snapshot_sha != PRE_REGISTRATION_SHA256:
        raise RuntimeError("original pre-execution report prefix was modified")
    if "Pre-registered G2 method" not in text or "2.756385903670335" not in text:
        raise RuntimeError("write fixed tolerance rule before running")
    path=ROOT/"results/revision_r1/cross_platform_20261021_130205/imports/calib-ARM64-rep1/calib-aarch64-rep1/raw_samples.csv"
    spec=dict(path=str(path),sha256=sha256_file(path),backend="ml_dsa_44",operation="verify",variant="valid")
    samples=CalibrationSamples(spec)
    mu=statistics.fmean(samples.durations)
    second=statistics.fmean(s*s for s in samples.durations)
    plan=[("fifo",0.3,0), ("fifo",0.6,0), ("block_priority",0.2,0.2), ("block_priority",0.4,0.2)]
    output=dict(selector=samples.input_record,mean_service=mu,second_moment=second,
        pre_registration_sha256=snapshot_sha,replicates=30,
        little_method="logged-waiting-counter-integral-v1",
        confidence=0.99,t_critical=2.756385903670335,replicate_rows=[],agreement=[],failure=None)
    begin_cpu,begin_wall=time.process_time(),time.perf_counter()
    done_jobs=0
    planned_jobs=30*(26000*2+26000*2+26000*3)
    for case,(policy,ra,rb) in enumerate(plan):
        la,lb=ra/mu,rb/mu
        horizon=26000/min(v for v in (la,lb) if v>0)
        warm=0.1*horizon
        for replicate in range(30):
            p=dict(run_id=f"paper2-g2-v1-{case}",replicate=replicate,horizon=horizon,
                arrivals_valid=dict(kind="poisson",rate=la),arrivals_invalid=dict(kind="poisson",rate=0),
                fee_distribution=dict(name="constant",value=0),amount_distribution=dict(name="constant",value=0),
                senders=["account"],initial_balance=1,receiver="sink",scheme=dict(signature_bytes=64),
                block_period=horizon*2,block_size=1,p_seen=1,invalid_kinds=["bit_flip"])
            workload=generate_workload(p)
            if lb:
                times=list(arrival_times(dict(kind="poisson",rate=lb),horizon,
                    WorkloadStream(derive_seed(p["run_id"],"block_contents",replicate))))
                workload.update(block_times=times,blocks=[dict(block_id=f"p:{i}",tx_ids=[]) for i in range(len(times))])
            replay = Path(tempfile.mkdtemp(prefix="paper2-g2-step0-replay-")) if prior is not None else None
            directory_context = nullcontext(str(replay)) if replay else tempfile.TemporaryDirectory(prefix="paper2-g2-")
            with directory_context as directory:
                events,manifest=run_model(dict(workload,k=1,q_max=1000000,policy=dict(name=policy),
                    cache=dict(capacity=0),pool=dict(enabled=False),
                    service=dict(mode="calibration",selectors={c:dict(valid=spec) for c in ("admission","block_tx","block_sig")}),
                    output_dir=directory))
                stats=measure_replicate(events,events.parent/"jobs.csv",warm,horizon,
                    ("admission","block_sig") if lb else ("admission",))
                for cls,v in stats.items():
                    n=v["n"];mean=v["wait"]/n
                    L=v["mean_number_waiting"];rate=v["observed_arrival_rate"]
                    rhs=v["little_rhs"];relative=v["little_relative_error"]
                    row=dict(case=case,policy=policy,rho_admission=ra,rho_block=rb,replicate=replicate,
                        job_class=cls,completed_after_warmup=n,horizon=horizon,warmup=warm,mean_wait=mean,
                        mean_number_waiting=L,observed_arrival_rate=rate,little_rhs=rhs,little_relative_error=relative,
                        counter_field=v["counter_field"],queue_counter_integral=v["counter_area"],
                        enqueued_in_window=v["enqueued_in_window"],passed=n>=20000 and relative<=0.02)
                    output["replicate_rows"].append(row)
                    done_jobs+=v["total_jobs"]
            cpu,wall=time.process_time()-begin_cpu,time.perf_counter()-begin_wall
            if prior is not None:
                old=prior["replicate_rows"][0]
                row=output["replicate_rows"][0]
                legacy=legacy_interval_mean(events.parent/"jobs.csv",warm,horizon,"admission")
                for key in ("completed_after_warmup","horizon","warmup","mean_wait","observed_arrival_rate","little_rhs"):
                    if row[key] != old[key]:
                        raise RuntimeError("reconstructed existing replicate differs: " + key)
                if legacy != old["mean_number_waiting"]:
                    raise RuntimeError("reconstructed legacy interval result differs")
                output.update(mode="existing-replicate-re-evaluation",new_statistical_replicates=0,
                    replicate_replays=1,G2_status="incomplete",cpu_seconds=cpu,wall_seconds=wall,
                    artifact_directory=str(replay),legacy_original=old,legacy_reconstructed_mean_number_waiting=legacy,
                    prior_summary_sha256=sha256_file(args.reevaluate_first),
                    artifact_sha256={p.name:sha256_file(p) for p in (events,events.parent/"jobs.csv",manifest)})
                target.write_text(json.dumps(output,indent=2),encoding="utf-8")
                print(json.dumps(output),flush=True)
                return
            projection=cpu*planned_jobs/max(done_jobs,1)
            print(json.dumps(dict(case=case,replicate=replicate,cpu_seconds=cpu,wall_seconds=wall,projected_cpu_seconds=projection)),flush=True)
            output.update(cpu_seconds=cpu,wall_seconds=wall,projected_cpu_seconds=projection)
            if cpu>1800 or wall>1800 or projection>1800:
                output["failure"]="compute limit exceeded or projected above 30 CPU-minutes"
                target.write_text(json.dumps(output,indent=2),encoding="utf-8")
                raise SystemExit(output["failure"])
            target.write_text(json.dumps(output,indent=2),encoding="utf-8")
        W0=(la+lb)*second/2
        for cls in ("admission","block_sig") if lb else ("admission",):
            theoretical=(W0/(1-rb)/(1-rb-ra) if cls=="admission" else W0/(1-rb)) if lb else la*second/(2*(1-ra))
            values=[r["mean_wait"] for r in output["replicate_rows"] if r["case"]==case and r["job_class"]==cls]
            mean=statistics.fmean(values);half=output["t_critical"]*statistics.stdev(values)/math.sqrt(len(values))
            output["agreement"].append(dict(case=case,policy=policy,rho_admission=ra,rho_block=rb,job_class=cls,
                analytical=theoretical,mean_wait=mean,ci_low=mean-half,ci_high=mean+half,
                passed=mean-half<=theoretical<=mean+half))
    output["passed"]=all(r["passed"] for r in output["replicate_rows"]+output["agreement"])
    target.write_text(json.dumps(output,indent=2),encoding="utf-8")
    print(json.dumps(dict(agreement=output["agreement"],passed=output["passed"])),flush=True)


if __name__ == "__main__":
    main()
