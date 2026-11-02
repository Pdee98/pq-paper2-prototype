"""Compare actual bee532b artifacts in an external worktree with current output."""

import argparse
from contextlib import ExitStack
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def main():
    p=argparse.ArgumentParser();p.add_argument("--reference",type=Path,required=True)
    p.add_argument("--summary",type=Path,required=True);args=p.parse_args()
    from src.paper2.model import run_model
    from src.paper2.model.service_times import ROOT
    if ROOT in args.summary.resolve().parents:raise ValueError("external summary required")
    captures=[]
    def observed(c):
        paths=run_model(c)
        if c.get("policy_view","incremental")=="incremental":
            captures.append(dict(config=c,events=hashlib.sha256(paths[0].read_bytes()).hexdigest(),
                jobs=hashlib.sha256((paths[0].parent/"jobs.csv").read_bytes()).hexdigest()))
        return paths
    modules=[importlib.import_module("tests.paper2."+name) for name in
             ("test_phase1_handchecks","test_phase2_state","test_phase3_corrections","test_phase3_policies")]
    with ExitStack() as patches:
        for module in modules:patches.enter_context(patch.object(module,"run_model",observed))
        suite=unittest.TestSuite()
        for module in modules:
            for cls in vars(module).values():
                if isinstance(cls,type) and issubclass(cls,unittest.TestCase):
                    for name in unittest.defaultTestLoader.getTestCaseNames(cls):
                        if name != "test_50000_overloaded_pool_admissions_with_500_prefix_reference":
                            suite.addTest(cls(name))
        result=unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():raise SystemExit("current literal/random tests failed")
    # Failed-input tests produce no capture; all successful incremental outputs compare.
    worker='''
import json,sys,tempfile,hashlib
from pathlib import Path
from unittest.mock import patch
from src.paper2.model import run_model
from src.paper2.model.engine import _git_state
rows=json.loads(Path(sys.argv[1]).read_text());git=_git_state();failures=[]
with tempfile.TemporaryDirectory(prefix="paper2-reference-runs-") as temp,patch("src.paper2.model.engine._git_state",return_value=git):
 for i,row in enumerate(rows):
  c=dict(row["config"],output_dir=str(Path(temp)/str(i)));e,m=run_model(c)
  for key,file in (("events",e),("jobs",e.parent/"jobs.csv")):
   if hashlib.sha256(file.read_bytes()).hexdigest()!=row[key]:failures.append(dict(run=i,file=key))
Path(sys.argv[2]).write_text(json.dumps(dict(compared=len(rows),randomized=474,failures=failures,reference="bee532baf31cb340b9fb0ef029671e7d1abb2b48"),indent=2))
sys.exit(bool(failures))
'''
    with tempfile.TemporaryDirectory(prefix="paper2-equivalence-") as temp:
        settings=Path(temp)/"configs.json";settings.write_text(json.dumps(captures))
        subprocess.run([sys.executable,"-B","-c",worker,str(settings),str(args.summary.resolve())],
                       cwd=args.reference,check=True)
    print(args.summary.read_text())


if __name__=="__main__":main()
