"""Signature-free replay, independent key checks and fail-closed gather coverage."""

from tests.paper2._provenance import setUpModule, tearDownModule

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.prototype import analysis,corpus,export,replay,runner,runtime
from src.paper2.model.service_times import ROOT
from src.paper2.verify.invariants import check
from tests.paper2._support import config


class Replay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="paper2-replay-tests-");cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name)
        c=config(cache=dict(capacity=32),pool=dict(enabled=True,capacity_bytes=100000),
            admissions=[dict(tx_id="a",arrival_t=0),dict(tx_id="b",arrival_t=.001)],
            blocks=[dict(block_id="B",tx_ids=["a","b"])],block_start=.05)
        cls.doc=corpus.build(c,"sleep");cls.cp=corpus.write(cls.doc,cls.root/"corpus.json")
        cls.cell=dict(backend="sleep",k=1,policy="fifo",rho=.5,rate=2,period=1,dispatcher_utilisation=.1)
        cls.inputs=cls.root/"inputs";cls.configs=[];cls.originals=[]
        index=None
        for rep in range(3):
            cfg=dict(cls.doc["workload"],replicate=rep,output_dir=str(cls.root/f"prototype-{rep}"))
            e,m=runtime.run(cfg,cls.cp,sleep_seconds=.003)
            violations=check(e,e.parent/"jobs.csv",m)
            if violations:raise AssertionError(violations)
            proto=dict(events=str(e),manifest=str(m),metrics=analysis.metrics(e,e.parent/"jobs.csv",m,0,1),violations=violations)
            if index is None:index=replay.initialize(cls.inputs,[cls.cell],[],replay.read(m)["git"]["commit"],"123")
            held=analysis.samples_from_jobs(e.parent/"jobs.csv",cls.root/f"held-{rep}.csv","sleep",f"concurrency-k1-rep{rep}")
            entry=index["runs"][rep]
            entry["manifest_sha256"]=replay.create_packet(cls.inputs/entry["run_id"],cfg,cls.cp,proto,held,cls.cell,rep,window=(0,1))
            cls.configs.append(cfg);cls.originals.append(proto)
        index["status"]=replay.PENDING;replay.write_index(cls.inputs,index);cls.index=index

    def test_roundtrip_byte_identical_to_original_in_memory_inputs(self):
        index=replay.verify(self.inputs,"123")
        packet=self.inputs/index["runs"][0]["run_id"];info=replay.read(packet/"info.json")
        self.assertEqual(replay.read(packet/"config.json"),self.configs[0])
        self.assertEqual(replay.read(packet/"workload.json"),self.doc["workload"])
        mapped=info["mapped"]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for label,sample in (("primary","primary.csv"),("held-out","held-out.csv")):
                old_e,old_m=analysis.paired(dict(self.configs[0],output_dir=str(root/(label+"-original"))),
                    self.cp,packet/sample,"sleep",mapped["structural_cost"],mapped["state_cost"])
                new_e,new_m=replay.simulate(packet,packet/sample,root/(label+"-saved"))
                self.assertEqual(old_e.read_bytes(),new_e.read_bytes())
                self.assertEqual((old_e.parent/"jobs.csv").read_bytes(),(new_e.parent/"jobs.csv").read_bytes())
                self.assertEqual(check(new_e,new_e.parent/"jobs.csv",new_m),[])
            result=replay.execute(self.inputs,"cell0-r0",root/"execution","123")
            self.assertNotIn("execution_error",result)
            self.assertEqual(result["seeds"],info["seeds"])
            self.assertEqual(result["prototype"]["violations"],[])
            self.assertEqual(result["primary"]["violations"],[])
            self.assertEqual(result["held_out"]["violations"],[])
            report=replay.gather(self.inputs,root/"execution",root/"gather","123")
            self.assertEqual(report["status"],"failed")
            self.assertEqual({v["run_id"] for v in report["failures"] if v["check"]=="missing repetition"},{"cell0-r1","cell0-r2"})

    def test_hash_mismatch_and_source_identity_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/"data.json";replay.save(path,dict(value=1));replay.seal(root,"REPLAY_MANIFEST.json")
            path.write_bytes(path.read_bytes()+b" ")
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
                replay.verify_files(root,"REPLAY_MANIFEST.json")
        with self.assertRaisesRegex(ValueError,"source run identity"):
            replay.verify(self.inputs,"124")
        with self.assertRaisesRegex(ValueError,"unsafe replay"):
            replay.safe_file(self.inputs,"../escape")

    def test_no_private_material_signing_state_or_signature_bytes(self):
        replay.verify(self.inputs,"123")
        raw=b"".join(p.read_bytes() for p in self.inputs.rglob("*") if p.is_file())
        for entry in self.doc["transactions"].values():self.assertNotIn(entry["signature_hex"].encode(),raw)
        for key in ("private"+"_key","signing_state","presigning","leaf_index","signature_hex"):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,"private material|signing state"):
                replay.audit_value({key:"test"})

    def test_replay_rejects_corrupt_public_corpus_before_checker(self):
        import shutil
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=root/"packet";shutil.copytree(self.inputs/"cell0-r0",packet)
            path=packet/"prototype/public-corpus.zip";path.write_bytes(path.read_bytes()+b"corrupt")
            replay.seal(packet,"REPLAY_MANIFEST.json")
            with patch.object(replay,"check",side_effect=AssertionError("checker ran before hashes")):
                with self.assertRaisesRegex(ValueError,"corpus archive SHA-256 mismatch"):
                    replay.postprocess_prototype(packet,root/"check")

    def records(self):
        base={name:1.0 for name in analysis.BANDS};base["complete"]=True
        return [dict(run_id=r["run_id"],cell_id=r["cell_id"],replicate=r["replicate"],input_sha256=r["manifest_sha256"],
            code_commit=self.index["code_commit"],source_run_id="123",
            **{kind:dict(metrics=copy.deepcopy(base),violations=[],**({"validity":dict(passed=True)} if kind=="prototype" else {})) for kind in ("prototype","primary","held_out")})
            for r in self.index["runs"]]

    def test_gather_pass_fail_missing_duplicate_and_diagnostic_logic(self):
        records=self.records()
        records[0]["held_out"]["metrics"]["mean_block_delay"]=100
        self.assertEqual(replay.gather_records(self.index,records)["status"],"passed")
        records[1]["primary"]["metrics"]["mean_block_delay"]=2
        bad=replay.gather_records(self.index,records)
        self.assertEqual(bad["status"],"failed")
        self.assertTrue(any(f["check"]=="mean_block_delay" for f in bad["failures"]))
        missing=replay.gather_records(self.index,self.records()[:2])
        self.assertEqual(missing["status"],"failed")
        self.assertIn(dict(run_id="cell0-r2",check="missing repetition"),missing["failures"])
        self.assertEqual(replay.gather_records(self.index,self.records()+self.records()[:1])["status"],"failed")
        for kind in ("prototype","primary","held_out"):
            records=self.records();records[0][kind]["violations"]=[dict(code="mutation")]
            self.assertEqual(replay.gather_records(self.index,records)["status"],"failed")

    def test_checker_rejects_wrong_precomputed_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);packet=self.inputs/"cell0-r0"
            e,m=replay.simulate(packet,packet/"primary.csv",root/"run")
            import csv
            jobs=e.parent/"jobs.csv"
            with jobs.open(newline="") as stream:rows=list(csv.DictReader(stream))
            job=json.loads(rows[0]["record"]);job["cache_key"]="0"*64;rows[0]["record"]=json.dumps(job)
            with jobs.open("w",newline="") as stream:
                writer=csv.DictWriter(stream,fieldnames=("job_id","record"));writer.writeheader();writer.writerows(rows)
            self.assertIn("real_cache_key",{v["code"] for v in check(e,jobs,m)})

    def test_prepare_and_replay_cli_without_site_packages(self):
        runner.hash_artifacts(self.inputs)
        env=dict(os.environ);env.pop("GITHUB_OUTPUT",None)
        common=[sys.executable,"-B","-S","-m","src.paper2.prototype.replay"]
        ready=subprocess.run(common+["prepare","--inputs",str(self.inputs),"--source-run-id","123"],
                             cwd=ROOT,env=env,capture_output=True,text=True)
        self.assertEqual(ready.returncode,0,ready.stderr)
        self.assertEqual(len(json.loads(ready.stdout)["include"]),3)
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"run"
            result=subprocess.run(common+["run","--inputs",str(self.inputs),"--source-run-id","123",
                "--run-id","cell0-r0","--output",str(output)],cwd=ROOT,env=env,capture_output=True,text=True)
            self.assertIn(result.returncode,(0,1),result.stderr)
            data=replay.read(output/"result.json")
            self.assertNotIn("execution_error",data)
            self.assertEqual(data["primary"]["violations"],[])
            self.assertEqual(data["held_out"]["violations"],[])

    def test_workflow_split_and_arm_projection(self):
        with self.assertRaisesRegex(RuntimeError,"caps unset"):
            runner.arm_remaining_projection(2221,30)
        self.assertEqual(runner.arm_remaining_projection(2221,30,dict(preparation=10,serialisation=20)),6841)
        self.assertNotIn("simulation",runner.STAGE_CAPS)
        text=(ROOT/"src/paper2/prototype/paper2-g3-replay.yml").read_text()
        for expected in ("workflow_dispatch:","source_run_id:","actions: read","max-parallel: 20", "fail-fast: false", "if: always()", "github-token: ${{ github.token }}"):
            self.assertIn(expected,text)
        self.assertNotIn("push:",text);self.assertNotIn("pull_request:",text)
        self.assertEqual(text.count("timeout-minutes: 120"),2)
        self.assertIn("timeout-minutes: ${{ matrix.timeout_minutes }}",text)
        self.assertIn("ref: ${{ needs.prepare.outputs.code_commit }}",text)


if __name__=="__main__":unittest.main()
