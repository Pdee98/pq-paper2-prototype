"""Export only approved code/public provenance; verify every frozen import byte."""

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys
from importlib.metadata import version, PackageNotFoundError

from src.paper2.model.service_times import ROOT,BASELINE,sha256_file
from src.paper2.model.engine import _git_state

ALLOWLIST={
    "/proc/self/maps":"runner host inspection",
    "/proc/cpuinfo":"runner host inspection",
    "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor":"runner host inspection",
    "C:/Program Files/Git/cmd/git.exe":"standard Windows install fallback",
}
EXCLUDED=["research/**", "research/paper2/STANDING_RULES.md", "research/paper2/phase5/RUNTIME_PLAN.md"]
ACTIONLINT_PY_VERSION="1.7.12.25"


def actionlint_command():
    local=Path(sys.executable).parent/("actionlint.exe" if sys.platform=="win32" else "actionlint")
    return str(local) if local.is_file() else shutil.which("actionlint")


def lint_workflow(path):
    command=actionlint_command()
    if not command:raise RuntimeError("actionlint is required; install actionlint-py=="+ACTIONLINT_PY_VERSION)
    result=subprocess.run([command,"-no-color",str(path)],capture_output=True,text=True,timeout=60)
    if result.returncode or result.stdout.strip() or result.stderr.strip():
        raise RuntimeError("actionlint rejected generated workflow:\n"+result.stdout+result.stderr)
    info=subprocess.run([command,"-version"],capture_output=True,text=True,check=True,timeout=30)
    try:package_version=version("actionlint-py")
    except PackageNotFoundError:package_version=None
    return dict(version=info.stdout.splitlines()[0],package_version=package_version,
                returncode=result.returncode,stdout=result.stdout,stderr=result.stderr,
                workflow_sha256=sha256_file(Path(path)))


def baseline_source():
    return BASELINE if BASELINE.is_file() else ROOT/"PROTECTED_SHA256.txt"


def audit_payload(directory,records):
    """Fail closed without printing potentially sensitive matched contents."""
    patterns={
        "user-profile path":re.compile(rb"c:[/\\]users[/\\]",re.I),
        "email address":re.compile(rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"),
        "private-key marker":re.compile(b"PRIVATE"+b" KEY",re.I),
    }
    hits=[]
    for row in records:
        rel=row["path"];path=Path(directory)/rel
        if any(part.lower()==".env" or part.lower().startswith(".env.") for part in Path(rel).parts):
            hits.append(dict(path=rel,line=None,reason="environment file"))
        raw=path.read_bytes()
        for reason,pattern in patterns.items():
            for match in pattern.finditer(raw):
                hits.append(dict(path=rel,line=raw[:match.start()].count(b"\n")+1,reason=reason))
    if hits:raise ValueError("export privacy audit failed: "+json.dumps(hits))
    return dict(passed=True,allowlist=[dict(value=v,reason=r,match="exact string only") for v,r in ALLOWLIST.items()],
                checks=list(patterns)+["environment file"],hits=[])


def frozen_closure(initial):
    selected=set(initial);pending=list(initial)
    def add_module(name):
        for candidate in (ROOT/(name.replace(".","/")+".py"),ROOT/name.replace(".","/")/"__init__.py"):
            if candidate.is_file() and candidate not in selected:
                selected.add(candidate);pending.append(candidate)
        for i in range(1,len(name.split("."))):
            init=ROOT/Path(*name.split(".")[:i])/"__init__.py"
            if init.is_file() and init not in selected:selected.add(init);pending.append(init)
    while pending:
        path=pending.pop()
        if path.suffix!=".py":continue
        tree=ast.parse(path.read_text(encoding="utf-8-sig"))
        package=path.relative_to(ROOT).parent.parts
        for node in ast.walk(tree):
            names=[]
            if isinstance(node,ast.Import):names=[v.name for v in node.names]
            elif isinstance(node,ast.ImportFrom):
                prefix=".".join(package[:len(package)-node.level+1]) if node.level else ""
                name=".".join(v for v in (prefix,node.module) if v)
                names=[name]+[name+"."+v.name for v in node.names]
            for name in names:
                if name.startswith(("src.","tests.paper2.")):add_module(name)
    return selected


def export(destination,allow_dirty=False):
    destination=Path(destination).resolve()
    if destination==ROOT or ROOT in destination.parents or destination in ROOT.parents:
        raise ValueError("export must be outside repository and not an ancestor")
    if destination.exists() and any(destination.iterdir()):raise FileExistsError("export directory must be new/empty")
    git=_git_state()
    if git["dirty"] and not allow_dirty:raise ValueError("commit code first; dirty exports require explicit --allow-dirty")
    initial=set((ROOT/"src/paper2").rglob("*.py"))
    initial.update((ROOT/"src/paper2/prototype").glob("*.json"))
    initial.update((ROOT/"src/paper2/prototype").glob("*.yml"))
    initial.update((ROOT/"tests/paper2").glob("test_phase5a*.py"))
    initial.update(ROOT/p for p in ("tests/paper2/__init__.py","tests/paper2/_support.py","tests/paper2/_provenance.py"))
    selected=frozen_closure(initial)
    baseline_file=baseline_source()
    baseline={line.split(None,1)[1].strip().replace("\\","/"):line.split(None,1)[0]
              for line in baseline_file.read_text().splitlines()}
    records=[]
    for path in sorted(selected):
        rel=path.relative_to(ROOT).as_posix();sha=sha256_file(path)
        frozen=not rel.startswith(("src/paper2/","tests/paper2/"))
        if frozen and baseline.get(rel)!=sha:raise ValueError("frozen import differs from baseline: "+rel)
        records.append(dict(path=rel,origin_path=rel,sha256=sha,frozen=frozen))
    destination.mkdir(parents=True,exist_ok=True)
    for row in records:
        target=destination/row["path"];target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/row["origin_path"],target)
    target=destination/"PROTECTED_SHA256.txt";shutil.copyfile(baseline_file,target)
    records.append(dict(path=target.name,origin_path="research/paper2/phase0/protected_sha256.txt",
                        sha256=sha256_file(target),frozen=False))
    workflow_lints={}
    for template_path in sorted((ROOT/"src/paper2/prototype").glob("paper2-g3*.yml")):
        workflow=".github/workflows/"+template_path.name;target=destination/workflow;target.parent.mkdir(parents=True,exist_ok=True)
        template=template_path.read_text()
        target.write_bytes(template.replace("research/paper2/phase5/RUNTIME_PLAN.md ","").encode())
        workflow_lints[template_path.name]=lint_workflow(target)
        records.append(dict(path=workflow,origin="generated",origin_path="generated:"+template_path.relative_to(ROOT).as_posix(),
                            sha256=sha256_file(target),frozen=False))
    lint=workflow_lints["paper2-g3.yml"]
    generated={
        "README.md": "This is a research prototype for an unpublished study (Paper 2; authors Appiah, Opoku and Asare, Kumasi Technical University). Its results are not yet published or peer-reviewed. In GitHub Actions, manually dispatch Paper 2 G3 validation for ARM measurements; when it reports prototype-complete: replay pending, manually dispatch Paper 2 G3 deterministic replay with source_run_id set to that ARM run ID. Only the replay gather report determines G3 agreement, after reviewing its evidence. Both workflows use workflow_dispatch only; no workflow is dispatched by exporting or publishing this bundle.\n",
        "LICENSE": "License to be decided by the authors before publication.\n",
    }
    for name,content in generated.items():
        target=destination/name;target.write_bytes(content.encode())
        records.append(dict(path=name,origin="generated",origin_path="generated",sha256=sha256_file(target),frozen=False))
    audit=audit_payload(destination,records)
    manifest=dict(schema="paper2-export-v1",source_commit=git["commit"],source_dirty=git["dirty"],
        baseline_sha256=sha256_file(baseline_file),baseline_path="PROTECTED_SHA256.txt",
        excluded=EXCLUDED,export_audit=audit,actionlint=lint,actionlint_workflows=workflow_lints,files=sorted(records,key=lambda r:r["path"]),
        self_descriptors=["BUNDLE_MANIFEST.json","BUNDLE_MANIFEST.sha256"],
        excluded_mutable_directories=[".git","artifacts","__pycache__"],
        no_results_or_calibration_data=True)
    path=destination/"BUNDLE_MANIFEST.json";path.write_bytes(json.dumps(manifest,indent=2).encode()+b"\n")
    (destination/"BUNDLE_MANIFEST.sha256").write_bytes((sha256_file(path)+"  BUNDLE_MANIFEST.json\n").encode())
    verify(destination)
    return manifest


def verify(directory):
    directory=Path(directory).resolve();path=directory/"BUNDLE_MANIFEST.json"
    if (directory/"BUNDLE_MANIFEST.sha256").read_text().split()[0]!=sha256_file(path):raise ValueError("bundle manifest changed")
    manifest=json.loads(path.read_text());seen=set()
    baseline_path=directory/manifest["baseline_path"]
    if sha256_file(baseline_path)!=manifest["baseline_sha256"]:raise ValueError("exported baseline changed")
    baseline={line.split(None,1)[1].strip().replace("\\","/"):line.split(None,1)[0] for line in baseline_path.read_text().splitlines()}
    for row in manifest["files"]:
        rel=Path(row["path"])
        if rel.is_absolute() or ".." in rel.parts or row["path"] in seen:raise ValueError("unsafe/duplicate bundle entry")
        seen.add(row["path"]);file=directory/rel
        if file.is_symlink() or sha256_file(file)!=row["sha256"]:raise ValueError("bundle payload changed: "+row["path"])
        if row["frozen"] and baseline.get(row["origin_path"])!=row["sha256"]:
            raise ValueError("frozen bundle payload not in protected baseline")
        if rel.parts[0]=="results" or rel.suffix in (".pem",".key") or rel.name.startswith(".env"):
            raise ValueError("prohibited bundle data")
    for file in directory.rglob("*"):
        if not file.is_file():continue
        rel=file.relative_to(directory)
        if any(p in (".git","artifacts","__pycache__") for p in rel.parts):continue
        if rel.as_posix() not in seen and rel.as_posix() not in manifest["self_descriptors"]:
            raise ValueError("unlisted bundle file: "+str(rel))
    audit_payload(directory,manifest["files"])
    return manifest


def main():
    parser=argparse.ArgumentParser();parser.add_argument("destination",nargs="?",type=Path)
    parser.add_argument("--verify-bundle",type=Path);parser.add_argument("--allow-dirty",action="store_true")
    args=parser.parse_args()
    if args.verify_bundle:result=verify(args.verify_bundle)
    elif args.destination:result=export(args.destination,args.allow_dirty)
    else:parser.error("destination or --verify-bundle required")
    print(json.dumps(dict(source_commit=result["source_commit"],source_dirty=result["source_dirty"],
        file_count=len(result["files"]),frozen_count=sum(r["frozen"] for r in result["files"]))))


if __name__=="__main__":main()
