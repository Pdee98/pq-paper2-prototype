"""Hash-bound preparation, byte-preserving writers, progress and replay isolation."""

from tests.paper2._provenance import setUpModule, tearDownModule

import copy
import csv
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from src.paper2.prototype import corpus,diagnostic,progress,public_corpus,replay,runner,runtime,serialisation
from src.paper2.model.service_times import ROOT,sha256_file,derive_seed
from tests.paper2._support import config


def partial_timeout(directory):
    p=progress.Progress(directory);p.phase("workers_ready",workers=1)
    (Path(directory)/"partial.csv").write_bytes(b"preserve me\n")
    time.sleep(60)


class Deviation4(unittest.TestCase):
    def fixture(self):
        return config(admissions=[dict(tx_id="a",arrival_t=0),dict(tx_id="b",arrival_t=.001)],
            blocks=[dict(block_id="B",tx_ids=["a","b"])],block_start=.02,
            cache=dict(capacity=32),pool=dict(enabled=True,capacity_bytes=100000))

    def test_binding_identical_and_tampered_corpus_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(),"sleep");cp=corpus.write(doc,root/"corpus.json")
            old=runtime.RealtimeModel(doc["workload"],cp)
            with patch.object(runtime,"validate",side_effect=AssertionError("revalidated")), \
                 patch.object(runtime,"validate_entry",side_effect=AssertionError("revalidated entry")):
                new=runtime.RealtimeModel(doc["workload"],cp,validated_sha256=sha256_file(cp))
            for field in ("transactions","prepared_tx","prepared_blocks","block_transactions","config"):
                self.assertEqual(getattr(old,field),getattr(new,field))
            digest=sha256_file(cp);cp.write_bytes(cp.read_bytes()+b" ")
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
                runtime.RealtimeModel(doc["workload"],cp,validated_sha256=digest)

    def test_build_validates_once(self):
        with patch.object(corpus,"validate",wraps=corpus.validate) as validate:
            corpus.build(self.fixture(),"sleep",primitive_checks=True)
            self.assertEqual(validate.call_count,1)
            self.assertTrue(validate.call_args.kwargs["primitive_checks"])

    def test_writers_preserve_bytes_including_escaping_unicode_and_newlines(self):
        rows=[("job_id","record"),("a",json.dumps(dict(text='comma, quote"\nΩ',x=1e-8))), (None,"",1.0)]
        old=io.StringIO(newline="");new=io.StringIO(newline="")
        csv.writer(old).writerows(rows);writer=serialisation.CSVWriter(new)
        for row in rows:writer.writerow(row)
        writer.flush();self.assertEqual(old.getvalue().encode(),new.getvalue().encode())
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"spans.json";value=[dict(start_t=1e-8,text="Ω\n")]*100
            serialisation.write_json(path,value)
            self.assertEqual(path.read_bytes(),json.dumps(value,separators=(",",":"),allow_nan=False).encode()+b"\n")

    def test_progress_is_flushed_and_counts_seconds(self):
        with tempfile.TemporaryDirectory() as td:
            p=progress.Progress(td)
            p.phase("epoch",epoch_ns=1)
            self.assertEqual(progress.read_progress(p.path)[-1]["phase"],"epoch")
            p.event(.2,"cache_hit","block_tx",(1,2));p.event(.3,"end","admission",(0,2));p.advance(1)
            row=progress.read_progress(p.path)[-1]
            self.assertEqual((row["second"],row["block_tx_hit"],row["completed"],row["q_block"]),(0,1,1,2))
            self.assertIsInstance(row["monotonic_ns"],int);p.close()

    def test_timeout_preserves_partial_outputs_and_last_phase(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/"source";evidence=root/"evidence"
            with self.assertRaisesRegex(TimeoutError,"last phase: workers_ready"):
                runner.fresh(partial_timeout,(source,),20,progress_path=source/"progress.jsonl",
                    phase_timeouts={"preparation":.3,"prototype window":110,"serialisation":2},partial_dir=evidence)
            self.assertEqual((evidence/"partial.csv").read_bytes(),b"preserve me\n")
            self.assertEqual(replay.read(evidence/"timeout.json")["last_phase"],"workers_ready")

    def test_prototype_returns_after_serialisation_without_postprocessing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(),"sleep");cp=corpus.write(doc,root/"corpus.json")
            with patch.object(runner,"check",side_effect=AssertionError("checker on ARM")), \
                 patch.object(runner,"metrics",side_effect=AssertionError("metrics on ARM")):
                result=runner.prototype_run(dict(doc["workload"],output_dir=str(root/"run")),cp,sha256_file(cp))
            self.assertNotIn("metrics",result);self.assertNotIn("violations",result)
            self.assertEqual(set(result["phase_seconds"]),{"preparation","prototype window","serialisation"})
            phases=[r["phase"] for r in progress.read_progress(result["progress"])]
            for name in ("process_start","workers_ready","epoch","drain_end","serialisation_start","serialisation_end","exit"):
                self.assertIn(name,phases)
            self.assertEqual(phases[-1],"exit")

    def test_public_corpus_audit_hashes_size_and_immutable_leaf_identifier(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(),"sleep")
            path=root/"public-corpus.zip";record=public_corpus.write_archive(doc,path,compact=False)
            self.assertEqual(public_corpus.validate_archive(path,record),record)
            with zipfile.ZipFile(path) as z:
                public=json.loads(z.read("corpus.json"))
            self.assertNotIn("presigning",public);self.assertNotIn("generator_manifest",public["workload"])
            self.assertIn("signature_hex",next(iter(public["transactions"].values())))
            public_corpus.audit(dict(leaf_index=7,public_key_id="identifier"))
            for key in ("private"+"_key","seed","signing_state","state_counter","next_leaf"):
                with self.subTest(key=key),self.assertRaisesRegex(ValueError,"excluded"):
                    public_corpus.audit({key:0})
            planted=root/"signing_state.json";planted.write_text("{}")
            with self.assertRaisesRegex(ValueError,"excluded"):public_corpus.audit_upload(root)
            planted.unlink()
            with patch.object(public_corpus,"LIMIT",1):
                with self.assertRaisesRegex(ValueError,"2 GB"):
                    public_corpus.write_archive(doc,root/"oversize.zip")
            path.write_bytes(path.read_bytes()+b"corruption")
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
                public_corpus.validate_archive(path,record)

    def test_diagnostic_is_separate_manual_and_guarded(self):
        self.assertNotEqual(derive_seed(diagnostic.RUN_ID,"arrivals",0),derive_seed("paper2-g3-v1","arrivals",0))
        with patch.object(diagnostic.platform,"machine",return_value="aarch64"), \
             patch.object(diagnostic.os,"sched_getaffinity",return_value={0,1,2},create=True):
            with self.assertRaisesRegex(RuntimeError,"at least four"):diagnostic.preflight()
        with self.assertRaisesRegex(RuntimeError,"diagnostic"):
            runner.execute(Path(tempfile.gettempdir())/"not-created-deviation4")
        text=(ROOT/"src/paper2/prototype/paper2-g3-diagnostic.yml").read_text()
        for marker in ("workflow_dispatch:","ubuntu-24.04-arm","diagnostic preflight","diagnostic collect","timeout-minutes: 180"):
            self.assertIn(marker,text)
        self.assertNotIn("runner --output",text)
        with tempfile.TemporaryDirectory() as td:
            replay.save(Path(td)/"INDEX.json",dict(purpose="DIAGNOSTIC"))
            with self.assertRaisesRegex(ValueError,"excluded from G3"):replay.verify_index(td)

    def test_projection_includes_engineering_stages_without_setting_caps(self):
        self.assertIsNone(runner.ENGINEERING_CAPS)
        self.assertEqual(runner.arm_remaining_projection(20,3,dict(preparation=4,serialisation=6)),800)
        with patch.object(diagnostic,"generate_workload",return_value=dict(transactions={i:None for i in range(99943)},blocks=[None]*784)):
            p=diagnostic.projection_historical()
        self.assertEqual((p["messages"],p["signing_keys"],p["size_probe_keys"]),(100727,198,1))
        self.assertAlmostEqual(p["presigning_seconds"],227.9214610537322)
        self.assertIn("UNVERIFIED",p["caveat"])

    def test_diagnostic_stop_rules_and_busy_integral(self):
        args=[True,.5,.5,.9,None,[]]
        self.assertTrue(diagnostic.may_prepare_validation(*args))
        for i,value in ((0,False),(1,.501),(2,.501),(3,.899),(3,None),(4,0),(5,[dict(code="bad")])):
            changed=list(args);changed[i]=value
            self.assertFalse(diagnostic.may_prepare_validation(*changed))
        intervals=[(1,2),(3,5)]
        integral=diagnostic.SpanIntegral(intervals)
        for a,b,expected in ((0,6,3),(1.5,4,1.5),(2,3,0),(4,7,1)):
            self.assertEqual(diagnostic.overlap(a,b,integral),expected)

    def test_diagnostic_signing_stages_have_hard_fresh_process_timeouts(self):
        for stage,processes in (("pilot",1),("presigning",2)):
            with patch.object(runner,"fresh",return_value=dict(path="public.json")) as fresh:
                diagnostic.bounded_presign(dict(run_id=diagnostic.RUN_ID),processes,"public.json",stage)
                fresh.assert_called_once_with(diagnostic.presign,
                    (dict(run_id=diagnostic.RUN_ID),processes,"public.json"),diagnostic.TIMEOUTS[stage])

    def test_diagnostic_rate_never_refits_to_a_dispatcher_bottleneck(self):
        cell=diagnostic.fixed_cell(dict(B_ref=1000,B_cold=900),.001)
        self.assertEqual(cell["rate"],1115.433019832252)
        self.assertEqual(cell["period"],.11475364071546823)
        self.assertEqual(cell["rho"],.5)
        self.assertGreater(cell["dispatcher_utilisation"],.5)
        self.assertEqual(cell["fresh_calibration_reference"]["B_ref"],1000)

    def test_diagnostic_presigning_returns_only_a_hash_bound_file_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            doc=corpus.build(self.fixture(),"sleep")
            with patch.object(diagnostic,"generate_workload",return_value=doc["workload"]), \
                 patch.object(corpus,"build",return_value=doc) as build:
                receipt=diagnostic.presign(dict(run_id=diagnostic.RUN_ID),2,Path(td)/"public.json")
            build.assert_called_once_with(doc["workload"],"xmss",processes=2,primitive_checks=True)
            self.assertEqual(receipt["sha256"],sha256_file(Path(receipt["path"])))
            self.assertEqual(set(receipt),{"path","sha256","transactions","blocks"})

    def test_diagnostic_artifact_analysis_runs_full_checker_without_G3_assessment(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(),"sleep");cp=corpus.write(doc,root/"corpus.json")
            cfg=dict(doc["workload"],run_id=diagnostic.RUN_ID,output_dir=str(root/"prototype"))
            e,m=runtime.run(cfg,cp,sleep_seconds=.003)
            held=replay.samples_from_jobs(e.parent/"jobs.csv",root/"held.csv","sleep","concurrency-k1-rep0")
            inputs=root/"inputs";cell=dict(backend="sleep",k=1,policy="fifo",rho=.5,rate=2,period=1,dispatcher_utilisation=.1)
            digest=replay.create_packet(inputs/diagnostic.RUN_ID,cfg,cp,dict(events=str(e),manifest=str(m)),held,cell,0)
            replay.save(inputs/"DIAGNOSTIC_INDEX.json",dict(purpose=diagnostic.PURPOSE,run_id=diagnostic.RUN_ID,
                code_commit=replay.read(m)["git"]["commit"],source_run_id="123",packet_sha256=digest))
            (inputs/"DIAGNOSTIC_INDEX.sha256").write_text(sha256_file(inputs/"DIAGNOSTIC_INDEX.json")+"\n")
            # Prepare starts at the current bundle HEAD, discovers the recorded
            # commit, then the matrix/gather checkout is pinned to that commit.
            with patch.dict(diagnostic.os.environ,{"GITHUB_ACTIONS":"true"}), \
                 patch.object(diagnostic,"_git_state",return_value=dict(commit="f"*40)):
                index,_=diagnostic.verify(inputs,"123")
                with self.assertRaisesRegex(ValueError,"checkout differs"):
                    diagnostic.verify_checkout(index)
            report=diagnostic.analyse(inputs,root/"analysis","123")
            self.assertEqual(report["purpose"],diagnostic.PURPOSE)
            self.assertEqual(report["prototype_violations"],[])
            self.assertNotIn("status",report)
            self.assertFalse((root/"analysis/G3_STATUS.json").exists())
            self.assertIsNone(report["recommended_caps_seconds"])
            with (root/"analysis/admission-block-lags.csv").open(newline="") as stream:
                rows=list(csv.DictReader(stream))
            for row in rows:
                self.assertEqual(float(row["block_arrival_lag_from_tx_arrival"]),
                    float(row["block_arrival_t"])-float(row["scheduled_tx_arrival_t"]))


if __name__=="__main__":unittest.main()
