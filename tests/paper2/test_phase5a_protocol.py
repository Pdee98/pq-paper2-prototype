"""Hand-checked amended protocol, independent replay inputs, and export integrity."""

from tests.paper2._provenance import setUpModule, tearDownModule

import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.prototype import analysis,corpus,export
from src.paper2.model.service_times import ROOT
from src.paper2.verify.invariants import check
from tests.paper2._support import config


class Protocol(unittest.TestCase):
    def test_amended_reference_and_prevalidation_dispatcher_guard(self):
        # m_a=2, m_t=4, m_s=128 => warm demand 3, cold demand 7.
        refs=analysis.references(dict(admission=2,block_tx=4,block_sig=128),{1:10,2:15},.1)
        self.assertAlmostEqual(refs[1]["B_ref"],1/3)
        self.assertAlmostEqual(refs[2]["B_ref"],.5)
        self.assertAlmostEqual(refs[2]["B_cold"],1.5/7)
        rows=analysis.cells({"xmss":refs,"ml_dsa_44":refs})
        self.assertEqual(len(rows),16)
        self.assertEqual({r["rho"] for r in rows},{.5,.85})
        self.assertEqual(analysis.dispatcher_guard(rows),[])
        # Exactly .5 is permitted; the first representably larger example fails.
        self.assertEqual(analysis.dispatcher_guard([dict(dispatcher_utilisation=.5)]),[])
        bad=dict(dispatcher_utilisation=.5000001)
        self.assertEqual(analysis.dispatcher_guard([bad]),[bad])
        capped=analysis.references(dict(admission=.001,block_tx=1,block_sig=.001),{1:1,2:2},1)
        self.assertEqual(capped[2]["B_ref"],1)
        self.assertTrue(analysis.dispatcher_guard(analysis.cells({"xmss":capped})))

    def test_primary_and_held_out_samples_are_separate_and_diagnostic(self):
        c=config(admissions=[dict(tx_id="a",arrival_t=0)],
                 blocks=[dict(block_id="B",tx_ids=["a"])],block_start=.1,
                 cache=dict(capacity=32))
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);data=corpus.build(c);path=corpus.write(data,root/"corpus.json")
            results=[]
            for name,duration in (("primary",1000000),("held-out",4000000)):
                samples=root/(name+".csv")
                with samples.open("w",newline="") as f:
                    w=csv.DictWriter(f,fieldnames=("backend","operation","variant","duration_ns","job_class"));w.writeheader()
                    for cls in ("admission","block_tx","block_sig"):
                        w.writerow(dict(backend="ed25519:"+cls,operation="verify",variant="valid",duration_ns=duration,job_class=cls))
                e,m=analysis.paired(dict(data["workload"],output_dir=str(root/name)),path,samples,"ed25519",0,0)
                self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
                results.append(analysis.metrics(e,e.parent/"jobs.csv",m,0,1))
                meta=json.loads(m.read_text())
                self.assertEqual(meta["input_files"][0]["sha256"],analysis.sha256_file(samples))
            self.assertAlmostEqual(results[0]["mean_block_delay"],.001)
            self.assertAlmostEqual(results[1]["mean_block_delay"],.004)
            compared=analysis.compare(results[0],results[1],diagnostic=True)
            self.assertFalse(compared["gates_validation"])
            self.assertFalse(compared["checks"]["mean_block_delay"]["passed"])

    def test_parallel_presigning_uses_distinct_keys_and_public_ledgers(self):
        messages=[(str(i),b"public test".hex(),"valid") for i in range(513)]
        entries,ledger=corpus.sign_messages("ed25519",messages,processes=2)
        self.assertEqual([k["count"] for k in ledger["keys"]],[512,1])
        self.assertEqual(len({k["key_id"] for k in ledger["keys"]}),2)
        self.assertEqual(len(entries),513)
        self.assertTrue(all(k["signing_ns"]>0 and k["keygen_ns"]>0 for k in ledger["keys"]))
        self.assertTrue(all("private" not in key and "secret" not in key for e in entries for key in e))

    def test_export_manifest_baseline_and_payload_corruption(self):
        with tempfile.TemporaryDirectory() as root:
            destination=Path(root)/"bundle"
            manifest=export.export(destination,allow_dirty=True)
            self.assertEqual(export.verify(destination),manifest)
            self.assertTrue(any(r["frozen"] for r in manifest["files"]))
            self.assertTrue(all(not r["path"].startswith("results/") for r in manifest["files"]))
            self.assertFalse((destination/"research").exists())
            self.assertIn("research/**",manifest["excluded"])
            for name in ("README.md","LICENSE"):
                row=next(r for r in manifest["files"] if r["path"]==name)
                self.assertEqual(row["origin"],"generated")
                self.assertEqual(row["sha256"],analysis.sha256_file(destination/name))
            self.assertEqual((destination/"LICENSE").read_text(),"License to be decided by the authors before publication.\n")
            self.assertNotIn("research/",(destination/".github/workflows/paper2-g3.yml").read_text())
            frozen=next(r for r in manifest["files"] if r["frozen"])
            path=destination/frozen["path"];original=path.read_bytes();path.write_bytes(original+b"\n")
            with self.assertRaisesRegex(ValueError,"payload changed"):export.verify(destination)
            path.write_bytes(original)
            (destination/"unlisted.key").write_text("dummy public marker")
            with self.assertRaisesRegex(ValueError,"unlisted bundle file"):export.verify(destination)

    def test_export_time_privacy_audit(self):
        # Assemble forbidden fixtures at runtime so the test source itself is
        # safe to include in a public bundle audited by the same detector.
        cases=[("profile-forward",b"c:"+bytes([47])+b"uSeRs"+bytes([47])+b"sample"),
               ("profile-backward",b"C:"+bytes([92])+b"Users"+bytes([92])+b"sample"),
               ("email",b"sample"+bytes([64])+b"example.invalid"),
               ("key-marker",b"PRIVATE"+b" KEY")]
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            for name,raw in cases:
                with self.subTest(reason=name):
                    # Patch only the exported copy of a source file, never its
                    # repository original, and require the export itself to fail.
                    original=export.shutil.copyfile
                    def contaminated(src,dst):
                        result=original(src,dst)
                        if Path(dst).as_posix().endswith("src/paper2/prototype/__init__.py"):
                            with Path(dst).open("ab") as f:f.write(b"\n# "+raw+b"\n")
                        return result
                    with patch.object(export.shutil,"copyfile",side_effect=contaminated):
                        with self.assertRaisesRegex(ValueError,"export privacy audit failed"):
                            export.export(root/name,allow_dirty=True)
                    self.assertFalse((root/name/"BUNDLE_MANIFEST.json").exists())
            env=root/".env";env.write_text("dummy")
            with self.assertRaisesRegex(ValueError,"environment file"):
                export.audit_payload(root,[dict(path=env.name)])
            allowed=root/"allowed.txt";allowed.write_text("\n".join(export.ALLOWLIST))
            audit=export.audit_payload(root,[dict(path=allowed.name)])
            self.assertTrue(audit["passed"])
            self.assertEqual({r["value"] for r in audit["allowlist"]},set(export.ALLOWLIST))

    def test_workflow_is_manual_arm_pinned_and_bounded(self):
        text=(ROOT/"src/paper2/prototype/paper2-g3.yml").read_text()
        self.assertIn("workflow_dispatch:",text)
        self.assertNotIn("pull_request:",text);self.assertNotIn("push:",text)
        self.assertIn("runs-on: ubuntu-24.04-arm",text)
        self.assertIn("timeout-minutes: 330",text)
        self.assertIn("280m bash",text)
        pins=json.loads((ROOT/"src/paper2/prototype/source_pins.json").read_text())
        for commit in pins["actions"].values():
            self.assertEqual(len(commit),40);self.assertIn("@"+commit,text)

    def test_small_concurrency_capture_and_dispatcher_mapping(self):
        from src.paper2.prototype.calibration import calibrate_once
        from src.paper2.prototype.runner import parameters
        from src.paper2.workload import generate_workload
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            data=corpus.build(generate_workload(parameters(2560,0,.05,horizon=.1)))
            path=corpus.write(data,root/"corpus.json")
            result=calibrate_once(path,1,root/"calibration",0,warmup=.01,measurement=.8)
            with Path(result["samples"]).open(newline="") as f:rows=list(csv.DictReader(f))
            self.assertEqual({r["job_class"] for r in rows},{"admission","block_tx","block_sig"})
            self.assertTrue(all(int(r["duration_ns"])>=int(r["primitive_ns"]) for r in rows))
            self.assertEqual({r["policy"] for r in result["dispatcher_probes"]},{"fifo","block_priority"})
            self.assertGreater(result["dispatcher_per_tx"],0)
            self.assertTrue(all(r["mapped_dispatcher"]["structural_cost"]>0 and
                                r["mapped_dispatcher"]["state_cost"]>0 for r in result["dispatcher_probes"]))
