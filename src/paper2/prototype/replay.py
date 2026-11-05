"""Hash-bound deterministic replay and full checking of public signed evidence."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import statistics
import time

from src.paper2.model.engine import Model, run_model, _git_state
from src.paper2.model.service_times import JOB_CLASSES, ROOT, sha256_file
from src.paper2.verify.invariants import check
from .analysis import BANDS, CapturedService, compare, costs, metrics, samples_from_jobs
from . import public_corpus
from .validity import from_events as prototype_validity

SCHEMA="paper2-g3-replay-v1"
PENDING="prototype-complete: replay pending"
EXCLUSION="dispatcher-bound, not a valid worker-contention test"


def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(json.dumps(value,separators=(",",":")).encode()+b"\n")


def read(path):return json.loads(Path(path).read_text(encoding="utf-8"))


def safe_file(root,name):
    rel=PurePosixPath(name)
    if not name or rel.is_absolute() or ".." in rel.parts or "\\" in name or ":" in name:
        raise ValueError("unsafe replay path")
    root=Path(root).resolve();path=root/Path(*rel.parts)
    if path.is_symlink() or root not in path.resolve().parents:raise ValueError("unsafe replay file")
    return path


def audit_value(value):
    if isinstance(value,dict):
        for name,item in value.items():
            key=name.lower()
            if ("private" in key or "secret" in key or key in
                    ("signing_state","presigning","leaf_index","next_leaf","signature_hex","payload_hex","public_key_hex","token")):
                raise ValueError("private material or signing state in replay input")
            audit_value(item)
    elif isinstance(value,list):
        for item in value:audit_value(item)
    elif isinstance(value,str) and ("PRIVATE"+" KEY") in value.upper():
        raise ValueError("private material in replay input")


def audit_file(path):
    if path.name=="public-corpus.zip":
        public_corpus.validate_archive(path);return
    if path.name.lower().startswith(".env") or path.suffix.lower() in (".pem",".key",".p12",".pfx"):
        raise ValueError("private material filename in replay input")
    if path.suffix==".json":audit_value(read(path))
    elif path.name=="jobs.csv":
        with path.open(newline="",encoding="utf-8") as stream:
            for row in csv.DictReader(stream):audit_value(json.loads(row["record"]))
    carry=b""
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            raw=carry+chunk
            if (b"PRIVATE"+b" KEY") in raw.upper():raise ValueError("private material in replay input")
            carry=raw[-32:]


def seal(directory,name,extra=None):
    directory=Path(directory)
    files=[dict(path=p.relative_to(directory).as_posix(),sha256=sha256_file(p))
           for p in sorted(directory.rglob("*")) if p.is_file() and p.name not in (name,name+".sha256")]
    manifest=dict(schema=SCHEMA,files=files,**(extra or {}));save(directory/name,manifest)
    (directory/(name+".sha256")).write_bytes((sha256_file(directory/name)+"\n").encode())
    return manifest


def verify_files(directory,name):
    directory=Path(directory);path=directory/name
    if sha256_file(path)!=(directory/(name+".sha256")).read_text().strip():raise ValueError("replay manifest SHA-256 mismatch")
    data=read(path);seen=set()
    if data["schema"]!=SCHEMA:raise ValueError("unsupported replay schema")
    for row in data["files"]:
        file=safe_file(directory,row["path"])
        if row["path"] in seen or sha256_file(file)!=row["sha256"]:raise ValueError("replay payload SHA-256 mismatch: "+row["path"])
        seen.add(row["path"])
    actual={p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    if actual!=seen|{name,name+".sha256"}:raise ValueError("unlisted or missing replay files")
    return data


def initialize(root,cells,excluded,code_commit,source_run_id):
    root=Path(root)
    if root.exists():raise FileExistsError("replay input root must be new")
    if not re.fullmatch(r"[0-9a-f]{40}",code_commit):raise ValueError("full source bundle commit required")
    root.mkdir(parents=True)
    runs=[dict(run_id=('secondary-regime' if cell.get('role')=='secondary' else f"cell{i}-r{rep}"),cell_id=i,replicate=rep,manifest_sha256=None)
          for i,cell in enumerate(cells) if cell["dispatcher_utilisation"]<=.5 for rep in range(1 if cell.get('role')=='secondary' else 3)]
    index=dict(schema=SCHEMA,code_commit=code_commit,source_run_id=str(source_run_id),
               cells=cells,excluded_cells=excluded,runs=runs,status="prototype collection in progress")
    write_index(root,index)
    return index


def write_index(root,index):
    save(Path(root)/"INDEX.json",index)
    (Path(root)/"INDEX.sha256").write_bytes((sha256_file(Path(root)/"INDEX.json")+"\n").encode())


def verify_index(root,source_run_id=None,complete=True):
    root=Path(root);index=read(root/"INDEX.json")
    if str(index.get("purpose","")).startswith("DIAGNOSTIC"):raise ValueError("DIAGNOSTIC inputs excluded from G3 assessment")
    if sha256_file(root/"INDEX.json")!=(root/"INDEX.sha256").read_text().strip():raise ValueError("replay index SHA-256 mismatch")
    if index["schema"]!=SCHEMA or not re.fullmatch(r"[0-9a-f]{40}",index["code_commit"]):raise ValueError("invalid replay index provenance")
    if source_run_id is not None and index["source_run_id"]!=str(source_run_id):raise ValueError("source run identity mismatch")
    expected={('secondary-regime' if c.get('role')=='secondary' else f"cell{i}-r{r}"):(i,r) for i,c in enumerate(index["cells"]) if c["dispatcher_utilisation"]<=.5 for r in range(1 if c.get('role')=='secondary' else 3)}
    excluded=[dict(cell=c,reason=EXCLUSION) for c in index["cells"] if c["dispatcher_utilisation"]>.5]
    if index["excluded_cells"]!=excluded:raise ValueError("exclusion/guard mismatch")
    if not expected or len(index["runs"])!=len(expected):raise ValueError("missing/duplicate expected repetitions")
    seen=set()
    for run in index["runs"]:
        rid=run["run_id"]
        if rid in seen or expected.get(rid)!=(run["cell_id"],run["replicate"]):raise ValueError("unexpected replay repetition")
        seen.add(rid)
        if complete and not re.fullmatch(r"[0-9a-f]{64}",run.get("manifest_sha256") or ""):
            raise ValueError("missing replay repetition: "+rid)
    if complete and index["status"]!=PENDING:raise ValueError("prototype collection is incomplete")
    return index


def create_packet(directory,config,corpus_path,prototype,held_out,cell,replicate,window=(30,90),shared_public=None):
    """Copy public inputs/evidence only; check privacy before creating payloads."""
    directory=Path(directory);doc=read(corpus_path);meta=read(prototype["manifest"])
    if meta.get("prototype",{}).get("mode")!="real-time-v1" or meta["config"].get("prototype",{}).get("mode")!="real-time-v1":
        raise ValueError("native prototype-mode evidence required")
    if sha256_file(Path(corpus_path))!=meta["prototype"]["corpus_sha256"]:raise ValueError("prototype corpus checksum mismatch")
    if config.get("replicate",0)!=replicate or meta["config"]["replicate"]!=replicate:
        raise ValueError("prototype repetition mismatch")
    if sha256_file(Path(prototype["events"]))!=meta["event_log_sha256"] or sha256_file(Path(prototype["events"]).parent/"jobs.csv")!=meta["job_records"]["sha256"]:
        raise ValueError("prototype event/job checksum mismatch")
    keys={name:dict(cache_key=e["cache_key"],size_bytes=doc["workload"]["transactions"][name]["size_bytes"])
          for name,e in doc["transactions"].items()}
    info=dict(cell=cell,replicate=replicate,backend=doc["backend"],mapped=costs(meta),seeds=meta["seeds"],window=list(window),
        source_commit=meta["git"]["commit"],corpus_sha256=meta["prototype"]["corpus_sha256"],
        prototype_checks=dict(mode="prototype",status="pending deterministic replay",
            provenance="compact public artifact hash-verified before full checker; raw signature-ID and wire-Merkle derivations audited on ARM"))
    values={"config.json":config,"workload.json":doc["workload"],"keys.json":keys,
            "info.json":info}
    originals={"prototype/events.csv":Path(prototype["events"]),
        "prototype/jobs.csv":Path(prototype["events"]).parent/"jobs.csv",
        "prototype/manifest.json":Path(prototype["manifest"]),
        "prototype/dispatcher_spans.json":Path(prototype["manifest"]).parent/meta["prototype"]["spans"]["path"],
        "held-out.csv":Path(held_out)}
    progress=Path(prototype["events"]).parent/"progress.jsonl"
    if progress.is_file():originals["prototype/progress.jsonl"]=progress
    for name in ("gc_pauses.json","long_spans.json"):
        path=Path(prototype["events"]).parent/name
        if path.is_file():originals["prototype/"+name]=path
        elif meta["prototype"].get("pause_attribution") and (name=='gc_pauses.json' or meta['prototype']['pause_attribution'].get('detailed',True)):
            raise ValueError("missing pause attribution evidence: "+name)
    callback_cost=Path(prototype["events"]).parent/"callback_overhead.json"
    if callback_cost.is_file():originals["prototype/callback_overhead.json"]=callback_cost
    for value in values.values():audit_value(value)
    for path in originals.values():audit_file(path)
    with Path(held_out).open(newline="",encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            source=(f"concurrency-cycle-k{cell['k']}-rep" if cell.get('g3_input_version')==6 else f"concurrency-k{cell['k']}-rep")
            if not row["backend"].startswith(doc["backend"]+":") or not row.get("source","").startswith(source):
                raise ValueError("held-out calibration backend/k mismatch")
    if directory.exists():raise FileExistsError("replay packet already exists")
    directory.mkdir(parents=True)
    existing=public_corpus.inventory(directory.parent)["files"]
    destination=directory/'prototype/public-corpus.zip'
    if shared_public is not None:
        destination=safe_file(directory.parent,shared_public);info['public_corpus_ref']=shared_public
    if destination.exists():
        info['public_corpus']=public_corpus.validate_archive(destination)
        import zipfile
        from .compact import unpack
        with zipfile.ZipFile(destination) as archive:prior=unpack(archive.read('corpus.bin'))
        if prior['arm_audit']['full_corpus_sha256']!=meta['prototype']['corpus_sha256']:raise ValueError('shared compact corpus differs from full corpus')
    else:info["public_corpus"]=public_corpus.write_archive(doc,destination,existing,full_path=corpus_path)
    from .compact import audit_full
    info["arm_corpus_audit"]=audit_full(doc,corpus_path)
    for name,value in values.items():save(directory/name,value)
    for name,path in originals.items():
        target=directory/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    if cell.get('g3_input_version')==6:
        shutil.copyfile(held_out,directory/'primary.csv')
        info['service_input']='held-out representative-traffic calibration cycles (both legacy comparison slots)'
        save(directory/'info.json',info)
    else:samples_from_jobs(originals["prototype/jobs.csv"],directory/"primary.csv",doc["backend"],"validation")
    for path in directory.rglob("*"):
        if path.is_file():audit_file(path)
    seal(directory,"REPLAY_MANIFEST.json")
    return sha256_file(directory/"REPLAY_MANIFEST.json")


def packet(root,index,run):
    directory=safe_file(root,run["run_id"])
    if sha256_file(directory/"REPLAY_MANIFEST.json")!=run["manifest_sha256"]:raise ValueError("repetition manifest SHA-256 mismatch")
    verify_files(directory,"REPLAY_MANIFEST.json")
    info=read(directory/"info.json")
    if info["source_commit"]!=index["code_commit"] or info["cell"]!=index["cells"][run["cell_id"]] or info["replicate"]!=run["replicate"]:
        raise ValueError("repetition provenance mismatch")
    return directory,info


def verify(root,source_run_id=None):
    index=verify_index(root,source_run_id)
    allowed={"INDEX.json","INDEX.sha256"}
    for run in index["runs"]:
        directory,info=packet(root,index,run)
        if info.get('public_corpus_ref'):
            reference=safe_file(root,info['public_corpus_ref']);public_corpus.validate_archive(reference,info['public_corpus'])
            allowed.add(info['public_corpus_ref'])
        for path in directory.rglob("*"):
            if path.is_file():audit_file(path)
        allowed.update(p.relative_to(root).as_posix() for p in directory.rglob("*") if p.is_file())
    actual={p.relative_to(root).as_posix() for p in Path(root).rglob("*") if p.is_file()}
    if actual!=allowed:raise ValueError("unlisted replay input files")
    return index


class ReplayModel(Model):
    def __init__(self,config,directory,sample):
        self.directory=Path(directory);self.keys=read(self.directory/"keys.json")
        if config.get('g3_input_version')==6:
            info=read(self.directory/'info.json')
            archive=(safe_file(self.directory.parent,info['public_corpus_ref']) if info.get('public_corpus_ref') else self.directory/'prototype/public-corpus.zip')
            public_corpus.validate_archive(archive,info['public_corpus'])
            import zipfile
            from .compact import unpack,expand
            with zipfile.ZipFile(archive) as z:public=expand(unpack(z.read('corpus.bin')))
            computed={name:dict(cache_key=e['cache_key'],size_bytes=public['workload']['transactions'][name]['size_bytes']) for name,e in public['transactions'].items()}
            if computed!=self.keys:raise ValueError('replay key table differs from recomputed compact v2 keys')
            if public['workload']['transactions']!=config['transactions'] or public['workload']['blocks']!=config['blocks']:raise ValueError('replay compact workload mismatch')
            self.keys=computed
        from .cycle_protocol import model_config
        super().__init__(model_config(config))
        self.config.update({k:v for k,v in config.items() if k not in model_config(config)})
        self.service=CapturedService(sample,read(self.directory/"info.json")["backend"])
        self.config["prototype"]=dict(mode="precomputed-key-replay-v1")
    def _key(self,tx):return self.keys[tx["tx_id"]]["cache_key"]
    def extra_manifest(self,directory):
        return dict(prototype=dict(mode="precomputed-key-replay-v1",**{
            name:dict(path=os.path.relpath(self.directory/file,directory),sha256=sha256_file(self.directory/file))
            for name,file in (("workload","workload.json"),("keys","keys.json"))}))


def simulate(directory,sample,output):
    config=read(Path(directory)/"config.json");info=read(Path(directory)/"info.json")
    config.update(output="full",output_dir=str(output),**{name:info["mapped"][name] for name in ("structural_cost","state_cost")},
                  service=dict(mode="constant",seconds={c:dict(valid=0,bit_flip=0,random_bytes=0) for c in JOB_CLASSES}))
    return run_model(config,model_type=lambda c:ReplayModel(c,directory,sample))


def postprocess_prototype(directory,output):
    directory=Path(directory)
    verify_files(directory,"REPLAY_MANIFEST.json")
    info=read(directory/"info.json")
    manifest=public_corpus.checker_manifest(directory,output)
    events,jobs=directory/"prototype/events.csv",directory/"prototype/jobs.csv"
    violations=check(events,jobs,manifest)
    config=read(directory/'config.json')
    if config.get('g3_input_version')==6:
        from .cycle_validity import from_logs
        validity=from_logs(events,jobs,config,manifest,info['window'])
    else:validity=prototype_validity(events,config,info['window'])
    return dict(metrics=metrics(events,jobs,manifest,*info["window"]),violations=violations,
                validity=validity,
                input_sha256=sha256_file(directory/"REPLAY_MANIFEST.json"))


def execute(root,run_id,output,source_run_id=None):
    root=Path(root);output=Path(output)
    index=verify_index(root,source_run_id)
    if os.environ.get("GITHUB_ACTIONS")=="true" and _git_state()["commit"]!=index["code_commit"]:
        raise ValueError("replay checkout differs from recorded source commit")
    run=next((r for r in index["runs"] if r["run_id"]==run_id),None)
    if run is None:raise ValueError("unknown replay repetition")
    directory,info=packet(root,index,run)
    if output.exists():raise FileExistsError("replay outputs must be new")
    if output.resolve()==ROOT or ROOT in output.resolve().parents:raise ValueError("replay outputs must be outside checkout")
    output.mkdir(parents=True)
    result=dict(run_id=run_id,cell_id=run["cell_id"],replicate=run["replicate"],cell=info["cell"],
        code_commit=index["code_commit"],source_run_id=index["source_run_id"],input_sha256=run["manifest_sha256"],
        seeds=info["seeds"])
    try:
        result["prototype"]=postprocess_prototype(directory,output/"prototype-check")
        if not result["prototype"]["validity"]["passed"] and info['cell'].get('role')!='secondary':
            result["status"]="INVALID: prototype validity guard"
            save(output/"result.json",result);seal(output,"RESULT_MANIFEST.json")
            return result
        for name,sample in (("primary","primary.csv"),("held_out","held-out.csv")):
            begin=time.perf_counter();e,m=simulate(directory,directory/sample,output/name)
            if read(m)["seeds"]!=info["seeds"]:raise ValueError("replay seed derivation differs from prototype")
            sim=dict(metrics=metrics(e,e.parent/"jobs.csv",m,*info["window"]),
                     violations=check(e,e.parent/"jobs.csv",m),elapsed=time.perf_counter()-begin)
            result[name]=sim
            if info['cell'].get('role')!='secondary':result[name+"_comparison"]=compare(result["prototype"]["metrics"],sim["metrics"],diagnostic=name=="held_out")
    except Exception as exc:result["execution_error"]=str(exc)
    save(output/"result.json",result);seal(output,"RESULT_MANIFEST.json")
    return result


def gather_records(index,records):
    failures=[];table=[];invalid=[];expected={r["run_id"]:r for r in index["runs"]};seen=set()
    for result in records:
        rid=result.get("run_id");run=expected.get(rid)
        if run is None or rid in seen:
            failures.append(dict(run_id=rid,check="unexpected/duplicate repetition"));continue
        seen.add(rid)
        for name,value in (("input_sha256",run["manifest_sha256"]),("code_commit",index["code_commit"]),
                           ("source_run_id",index["source_run_id"]),("cell_id",run["cell_id"]),("replicate",run["replicate"])):
            if result.get(name)!=value:failures.append(dict(run_id=rid,check=name+" mismatch"))
        row=dict(run_id=rid,cell_id=run["cell_id"],replicate=run["replicate"])
        if index['cells'][run['cell_id']].get('role')=='secondary':
            from .cycle_protocol import regime_category
            row.update(role='secondary',category=regime_category(result.get('prototype',{}).get('metrics',{}).get('block_tx_cache_hit_rate'),result.get('primary',{}).get('metrics',{}).get('block_tx_cache_hit_rate')),
                prototype_hit=result.get('prototype',{}).get('metrics',{}).get('block_tx_cache_hit_rate'),simulation_hit=result.get('primary',{}).get('metrics',{}).get('block_tx_cache_hit_rate'))
            for name in ('prototype','primary','held_out'):
                if result.get(name,{}).get('violations'):row.setdefault('diagnostic_errors',[]).append(dict(source=name,violations=result[name]['violations']))
            if result.get('execution_error'):row['diagnostic_errors']=[result['execution_error']]
            table.append(row);continue
        if result.get("execution_error"):failures.append(dict(run_id=rid,check="execution",detail=result["execution_error"]))
        validity=result.get("prototype",{}).get("validity")
        row["prototype_validity"]=validity
        if not isinstance(validity,dict) or not validity.get("passed"):
            invalid.append(rid);row["status"]="INVALID: prototype validity guard"
            failures.append(dict(run_id=rid,check="prototype validity",validity=validity))
            table.append(row);continue
        try:
            primary=compare(result["prototype"]["metrics"],result["primary"]["metrics"])
            held=compare(result["prototype"]["metrics"],result["held_out"]["metrics"],diagnostic=True)
            row.update(primary=primary,held_out=held)
            for name,item in primary["checks"].items():
                if not item["passed"]:failures.append(dict(run_id=rid,check=name,**item))
            if not result["prototype"]["metrics"]["complete"] or not result["primary"]["metrics"]["complete"]:
                failures.append(dict(run_id=rid,check="incomplete primary/prototype"))
            for name in ("prototype","primary","held_out"):
                for violation in result[name]["violations"]:failures.append(dict(run_id=rid,check=name+" invariant",violation=violation))
        except (KeyError,TypeError) as exc:failures.append(dict(run_id=rid,check="missing result fields",detail=str(exc)))
        table.append(row)
    for rid in sorted(expected.keys()-seen):failures.append(dict(run_id=rid,check="missing repetition"))
    aggregates=[]
    for cell_id,cell in enumerate(index["cells"]):
        if cell.get('role')=='secondary':continue
        if cell["dispatcher_utilisation"]>.5:continue
        members=[r for r in table if r["cell_id"]==cell_id and "primary" in r]
        aggregate=dict(cell_id=cell_id,cell=cell,repetitions=len(members),metrics={})
        for name in BANDS:
            aggregate["metrics"][name]={kind:statistics.fmean(r["primary"]["checks"][name][kind] for r in members)
                if members and all(r["primary"]["checks"][name][kind] is not None for r in members) else None
                for kind in ("prototype","simulation")}
        aggregate["passed"]=len(members)==3 and not any(f.get("run_id") in {r["run_id"] for r in members} for f in failures)
        aggregates.append(aggregate)
    return dict(status="invalid" if invalid else "passed" if expected and not failures else "failed",invalid_runs=invalid,failures=failures,
        secondary_regime=[r for r in table if r.get('role')=='secondary'],
        per_repetition=sorted(table,key=lambda r:r["run_id"]),aggregates=aggregates,excluded_cells=index["excluded_cells"],
        bands=BANDS,source_run_id=index["source_run_id"],code_commit=index["code_commit"])


def gather(root,results,output,source_run_id=None):
    output=Path(output)
    if output.resolve()==ROOT or ROOT in output.resolve().parents:raise ValueError("gather outputs must be outside checkout")
    output.mkdir(parents=True,exist_ok=True);errors=[];records=[]
    try:
        index=verify_index(root,source_run_id,complete=False)
        if os.environ.get("GITHUB_ACTIONS")=="true" and _git_state()["commit"]!=index["code_commit"]:
            errors.append(dict(check="replay checkout differs from recorded source commit"))
        try:verify(root,source_run_id)
        except (OSError,ValueError,KeyError) as exc:errors.append(dict(check="input checksum/schema",detail=str(exc)))
        for path in sorted(Path(results).rglob("result.json")):
            try:
                verify_files(path.parent,"RESULT_MANIFEST.json");result=read(path)
                run=next((r for r in index["runs"] if r["run_id"]==result.get("run_id")),None)
                if run is not None:
                    directory,info=packet(root,index,run)
                    receipt=result.get("prototype",{}).get("input_sha256")
                    if receipt!=run["manifest_sha256"] or result.get("seeds")!=info["seeds"]:
                        raise ValueError("result differs from recorded prototype evidence/seeds")
                records.append(result)
            except (OSError,ValueError,KeyError) as exc:errors.append(dict(check="result checksum/schema",path=path.parent.name,detail=str(exc)))
        report=gather_records(index,records);report["failures"].extend(errors)
        if errors:report["status"]="failed"
    except (OSError,ValueError,KeyError) as exc:
        report=dict(status="failed",failures=[dict(check="input checksum/schema",detail=str(exc))],per_repetition=[],aggregates=[],excluded_cells=[])
    save(output/"G3_STATUS.json",report)
    lines=["# G3 deterministic replay outcome","","Status: "+report["status"],"",
           "| Run | Metric | Prototype | Primary | Error | Limit | Passed | Held-out error (diagnostic) |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in report["per_repetition"]:
        for name,item in row.get("primary",{}).get("checks",{}).items():
            lines.append("| "+" | ".join(str(x) for x in (row["run_id"],name,item["prototype"],item["simulation"],item["error"],item["limit"],item["passed"],row["held_out"]["checks"][name]["error"]))+" |")
    lines.extend(("","## Per-cell aggregates","",json.dumps(report["aggregates"],indent=2),
                  "","## Secondary regime (qualitative, excluded from primary G3 bands)","",
                  json.dumps(report.get("secondary_regime",[]),indent=2),
                  "","## Prototype validity (INVALID repetitions have no G3 comparison)","",
                  json.dumps([{k:r.get(k) for k in ("run_id","status","prototype_validity")} for r in report["per_repetition"]],indent=2),
                  "","## Deviation 2 exclusions","",json.dumps(report["excluded_cells"],indent=2),
                  "","## Every failing check","",json.dumps(report["failures"],indent=2)))
    (output/"G3_REPORT.md").write_bytes(("\n".join(lines)+"\n").encode())
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument("command",choices=("prepare","run","gather"))
    p.add_argument("--inputs",type=Path,required=True);p.add_argument("--source-run-id",required=True)
    p.add_argument("--run-id");p.add_argument("--results",type=Path);p.add_argument("--output",type=Path)
    args=p.parse_args()
    if not re.fullmatch(r"[0-9]+",args.source_run_id):p.error("source_run_id must be numeric")
    if args.command=="prepare":
        index=verify(args.inputs,args.source_run_id)
        matrix=json.dumps(dict(include=[dict(run_id=r["run_id"]) for r in index["runs"]]),separators=(",",":"))
        print(matrix)
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"],"a",encoding="utf-8") as stream:
                stream.write("matrix="+matrix+"\ncode_commit="+index["code_commit"]+"\n")
    elif args.command=="run":
        result=execute(args.inputs,args.run_id,args.output,args.source_run_id)
        index=verify_index(args.inputs,args.source_run_id)
        raise SystemExit(0 if gather_records(dict(index,runs=[r for r in index["runs"] if r["run_id"]==args.run_id]),[result])["status"]=="passed" else 1)
    else:raise SystemExit(0 if gather(args.inputs,args.results,args.output,args.source_run_id)["status"]=="passed" else 1)


if __name__=="__main__":main()
