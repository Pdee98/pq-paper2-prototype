"""G2 with fixed original seeds/horizons, summary observations and a CPU budget."""

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import statistics
import subprocess
import tempfile
import time

from src.paper2.model import run_model
from src.paper2.model.service_times import ROOT, CalibrationSamples, WorkloadStream, derive_seed, sha256_file
from src.paper2.workload import generate_workload
from src.paper2.workload.generator import arrival_times
from .analytical import PRE_REGISTRATION_SHA256
from .invariants import check
from .summary import recompute, differences

PLAN=(("fifo",.3,0),("fifo",.6,0),("block_priority",.2,.2),("block_priority",.4,.2))


def calibration():
    path=ROOT/"results/revision_r1/cross_platform_20261021_130205/imports/calib-ARM64-rep1/calib-aarch64-rep1/raw_samples.csv"
    spec=dict(path=str(path),sha256=sha256_file(path),backend="ml_dsa_44",operation="verify",variant="valid")
    samples=CalibrationSamples(spec)
    return spec,statistics.fmean(samples.durations),statistics.fmean(x*x for x in samples.durations)


def replicate(task):
    case,rep,full=task;begin=time.process_time();wall=time.perf_counter()
    spec,mu,second=calibration();policy,ra,rb=PLAN[case];la,lb=ra/mu,rb/mu
    horizon=26000/min(v for v in (la,lb) if v>0);warm=.1*horizon
    p=dict(run_id=f"paper2-g2-v1-{case}",replicate=rep,horizon=horizon,
        arrivals_valid=dict(kind="poisson",rate=la),arrivals_invalid=dict(kind="poisson",rate=0),
        fee_distribution=dict(name="constant",value=0),amount_distribution=dict(name="constant",value=0),
        senders=["account"],initial_balance=1,receiver="sink",scheme=dict(signature_bytes=64),
        block_period=horizon*2,block_size=1,p_seen=1,invalid_kinds=["bit_flip"])
    workload=generate_workload(p)
    if lb:
        times=list(arrival_times(dict(kind="poisson",rate=lb),horizon,
            WorkloadStream(derive_seed(p["run_id"],"block_contents",rep))))
        workload.update(block_times=times,blocks=[dict(block_id=f"p:{i}",tx_ids=[]) for i in range(len(times))])
    directory=Path(tempfile.mkdtemp(prefix=f"paper2-g2-4b-{case}-{rep}-"))
    c=dict(workload,k=1,q_max=1000000,policy=dict(name=policy),cache=dict(capacity=0),pool=dict(enabled=False),
        service=dict(mode="calibration",selectors={cls:dict(valid=spec) for cls in ("admission","block_tx","block_sig")}),
        summary=dict(analysis_window=[warm,horizon],window_width=horizon/100),
        output="full" if full else "summary",output_dir=str(directory))
    artifact,manifest=run_model(c)
    violations=[]
    if full:
        violations=check(artifact,directory/"jobs.csv",manifest)
        summary=recompute(artifact,directory/"jobs.csv",c)
    else:summary=json.loads(artifact.read_text())
    data=json.loads(manifest.read_text());rows=[]
    for cls in (("admission","block_sig") if lb else ("admission",)):
        v=summary["analysis"]["classes"][cls];n=v["enqueued"]
        if not n or v["count"]!=n:raise RuntimeError("G2 cohort count mismatch")
        field="admission" if cls=="admission" else "block"
        L=summary["analysis"]["queue_integrals"][field]/(horizon-warm)
        rate=n/(horizon-warm);W=v["wait_sum"]/n;rhs=rate*W
        error=abs(L-rhs)/rhs if rhs else (0 if L==0 else math.inf)
        bounds=summary["analysis"]["queue_boundaries"]
        rows.append(dict(case=case,replicate=rep,job_class=cls,policy=policy,rho_admission=ra,rho_block=rb,
            horizon=horizon,warmup=warm,n=n,L=L,arrival_rate=rate,W=W,lambda_W=rhs,relative_error=error,
            q_warmup=bounds["start"][field],q_horizon=bounds["end"][field],passed=n>=20000 and error<=.02))
    result=dict(case=case,replicate=rep,full=full,rows=rows,seeds=data["seeds"],cpu_seconds=time.process_time()-begin,
        wall_seconds=time.perf_counter()-wall,directory=str(directory),violations=violations,
        artifact_sha256=sha256_file(artifact),summary=summary if full or rep==0 else None)
    print(json.dumps({k:v for k,v in result.items() if k not in ("summary","seeds","rows","violations")}),flush=True)
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--summary",type=Path,required=True)
    args=parser.parse_args();target=args.summary.resolve()
    if ROOT in target.parents or target.exists():raise ValueError("new external summary required")
    report=ROOT/"research/paper2/phase4/VERIFICATION_REPORT.md"
    prefix=report.read_bytes().split(b"\n## Execution evidence and gate status",1)[0]
    if hashlib.sha256(prefix).hexdigest()!=PRE_REGISTRATION_SHA256:raise RuntimeError("pre-registration changed")
    physical=int(subprocess.check_output(["powershell","-NoProfile","-Command",
        "(Get-CimInstance Win32_Processor | Measure-Object NumberOfCores -Sum).Sum"],text=True).strip())
    if physical<2:raise RuntimeError("physical cores minus one leaves no worker")
    output=dict(pre_registration_sha256=PRE_REGISTRATION_SHA256,physical_cores=physical,workers=min(physical-1,4),
        budget_cpu_seconds=5400,confidence=.99,t_critical=2.756385903670335,replicates_per_condition=30,
        pilots=[],full_checks=[],replicate_rows=[],agreement=[],status="pilot")
    spec,mu,second=calibration();output.update(selector=spec,mean_service=mu,second_moment=second)
    def save():target.write_text(json.dumps(output,indent=2),encoding="utf-8")
    for case in range(4):
        pilot=replicate((case,0,False));output["pilots"].append(pilot);save()
    # Conservative full-check allowance: four times pilot CPU for each full run/check.
    pilot_cpu=sum(r["cpu_seconds"] for r in output["pilots"])
    projection=30*pilot_cpu+4*pilot_cpu
    output["projected_cpu_seconds"]=projection;output["projection_definition"]="30 * sum(4 summary pilots) + 4 * sum(4 summary pilots) for full checks"
    print(json.dumps(dict(projected_cpu_minutes=projection/60,budget_cpu_minutes=90)),flush=True);save()
    if projection>5400:
        output["status"]="stopped: projected CPU budget";save();return
    used=pilot_cpu
    for case in range(4):
        full=replicate((case,0,True));used+=full["cpu_seconds"]
        errors=differences(output["pilots"][case]["summary"],full["summary"])
        output["full_checks"].append(dict(case=case,directory=full["directory"],violations=full["violations"],
            summary_differences=errors,cpu_seconds=full["cpu_seconds"],seeds=full["seeds"]))
        if errors or full["violations"]:
            output["status"]="failed: full-mode verification";save();return
        save()
    output["replicate_rows"]=[row for p in output["pilots"] for row in p["rows"]]
    output["seed_records"]=[dict(case=p["case"],replicate=0,seeds=p["seeds"]) for p in output["pilots"]]
    with ProcessPoolExecutor(max_workers=output["workers"]) as executor:
        # Submit only one bounded batch at a time; do not launch beyond a budget stop.
        tasks=[(c,r,False) for c in range(4) for r in range(1,30)]
        for start in range(0,len(tasks),output["workers"]):
            futures=[executor.submit(replicate,t) for t in tasks[start:start+output["workers"]]]
            for future in futures:
                r=future.result();used+=r["cpu_seconds"]
                output["replicate_rows"].extend(r["rows"])
                output["seed_records"].append(dict(case=r["case"],replicate=r["replicate"],seeds=r["seeds"]))
            output["actual_cpu_seconds"]=used;save()
            if used>5400:
                output["status"]="stopped: actual CPU budget";save();return
    for case,(policy,ra,rb) in enumerate(PLAN):
        la,lb=ra/mu,rb/mu;W0=(la+lb)*second/2
        for cls in (("admission","block_sig") if rb else ("admission",)):
            theory=(W0/(1-rb)/(1-rb-ra) if cls=="admission" else W0/(1-rb)) if rb else la*second/(2*(1-ra))
            values=[r["W"] for r in output["replicate_rows"] if r["case"]==case and r["job_class"]==cls]
            mean=statistics.fmean(values);half=2.756385903670335*statistics.stdev(values)/math.sqrt(30)
            output["agreement"].append(dict(case=case,job_class=cls,analytical=theory,mean_wait=mean,
                ci_low=mean-half,ci_high=mean+half,passed=mean-half<=theory<=mean+half))
    output["status"]="passed" if all(r["passed"] for r in output["agreement"]+output["replicate_rows"]) else "failed: agreement or Little's law"
    save();print(json.dumps(dict(status=output["status"],agreement=output["agreement"])),flush=True)


if __name__=="__main__":main()
