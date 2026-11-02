"""Separately invoked A6 full-model code-cost check; no performance outputs."""

import argparse
import json
import tempfile
import threading
import _thread
import time
from pathlib import Path

from src.paper2.model import run_model
from src.paper2.model.service_times import ROOT, sha256_file
from src.paper2.workload import generate_workload


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--modes", nargs="+", choices=("full","summary"), default=["full","summary"])
    parser.add_argument("--horizon", type=float, default=100)
    parser.add_argument("--check-summary", action="store_true")
    args=parser.parse_args()
    target=Path(args.summary).resolve()
    if target == ROOT or ROOT in target.parents:
        raise ValueError("summary must be outside repository")
    p=dict(run_id="paper2-a6-v1", replicate=0, horizon=args.horizon,
        arrivals_valid=dict(kind="poisson", rate=1000), arrivals_invalid=dict(kind="poisson", rate=0),
        fee_distribution=dict(name="uniform_int", low=1, high=20), amount_distribution=dict(name="constant", value=1),
        senders=[f"s{i}" for i in range(64)], initial_balance=10**12, receiver="sink",
        scheme=dict(signature_bytes=64), block_period=0.1, block_size=200, p_seen=1,
        invalid_kinds=["bit_flip", "random_bytes"])
    workload=generate_workload(p)
    result=dict(offered_valid=workload["generator_manifest"]["counts"]["valid"],
        nominal_offered_utilization=(1000*0.0022*2+10*0.0001)/4, runs=[],
        source_sha256={p.relative_to(ROOT).as_posix():sha256_file(p) for p in (ROOT/"src/paper2").rglob("*.py")})
    for policy in (dict(name="fifo"), dict(name="deadline_slack", beta=0.3, W=0.1, m=0.01)):
        for on in (False,True):
          expected = None
          for mode in args.modes:
            with tempfile.TemporaryDirectory(prefix="paper2-a6-") as directory:
                start=time.perf_counter()
                timer=threading.Timer(180,_thread.interrupt_main)
                timer.daemon=True
                timer.start()
                timed_out=False
                try:
                    settings=dict(workload, k=4, q_max=1000, cache=dict(capacity=128, ttl=0.05),
                        pool=dict(enabled=True, capacity_bytes=64000), coalesce_inflight=on, policy=policy,
                        initial_estimates=dict(admission=0.0022,block_tx=0.0022,block_sig=0.0001),
                        service=dict(mode="constant",seconds=dict(admission=0.0022,block_tx=0.0022,block_sig=0.0001)),
                        output_dir=directory,output=mode)
                    artifact,_ = run_model(settings)
                except KeyboardInterrupt:
                    timed_out=True
                finally:
                    timer.cancel()
                elapsed=time.perf_counter()-start
                row=dict(policy=policy["name"],coalesce=on,output=mode,elapsed_seconds=elapsed,passed=not timed_out and elapsed<180)
                result["runs"].append(row)
                print(json.dumps(row),flush=True)
                if args.check_summary and not timed_out:
                    from .summary import recompute,differences
                    if mode=="full":expected=recompute(artifact,artifact.parent/"jobs.csv",settings)
                    elif expected is None:raise ValueError("--check-summary requires full before summary")
                    else:
                        errors=differences(json.loads(artifact.read_text()),expected)
                        if errors:raise RuntimeError(str(errors))
                        row["summary_equivalent"]=True
            target.write_text(json.dumps(result,indent=2),encoding="utf-8")
            if not row["passed"]:
                raise SystemExit("A6 failed: run exceeded 180 seconds")


if __name__ == "__main__":
    main()
