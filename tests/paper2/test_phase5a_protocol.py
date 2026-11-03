"""Hand-checked amended protocol, independent replay inputs, and export integrity."""

from tests.paper2._provenance import setUpModule as provenance_setup, tearDownModule

import csv
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import urllib.request
from unittest.mock import patch

from src.paper2.prototype import analysis,corpus,export,provision
from src.paper2.model.service_times import ROOT
from src.paper2.verify.invariants import check
from tests.paper2._support import config


def setUpModule():
    provenance_setup()


class Protocol(unittest.TestCase):
    def setUp(self):
        # Only the dedicated actionlint test exercises the external linter.
        # Other exporter unit tests isolate that dependency; CLI exports keep
        # their mandatory real actionlint gate unchanged.
        if self._testMethodName!="test_generated_workflow_passes_actionlint_and_old_context_fails":
            def receipt(path):
                return dict(version="unit-test",package_version=None,returncode=0,stdout="",stderr="",
                            workflow_sha256=analysis.sha256_file(Path(path)))
            stub=patch.object(export,"lint_workflow",side_effect=receipt)
            stub.start();self.addCleanup(stub.stop)

    def test_runner_export_self_tests_do_not_install_or_download(self):
        names=["test_export_manifest_baseline_and_payload_corruption","test_export_time_privacy_audit",
               "test_export_fails_on_actionlint_findings","test_generated_workflow_passes_actionlint_and_old_context_fails"]
        provenance=export._git_state()
        result=unittest.TestResult()
        with patch.dict(os.environ,{"GITHUB_ACTIONS":"true"}), \
             patch.object(export,"_git_state",return_value=provenance), \
             patch.object(export,"actionlint_command",side_effect=AssertionError("runner must not locate/install actionlint")), \
             patch.object(subprocess,"run",side_effect=AssertionError("unexpected subprocess in runner export self-tests")), \
             patch.object(urllib.request,"urlopen",side_effect=AssertionError("unexpected network download")), \
             patch.object(urllib.request,"urlretrieve",side_effect=AssertionError("unexpected network download")), \
             patch(__name__+".provenance_setup") as setup:
            setUpModule();setup.assert_called_once_with()
            for name in names:Protocol(name).run(result)
        self.assertEqual(result.testsRun,len(names))
        self.assertEqual(result.errors,[])
        self.assertEqual(result.failures,[])
        self.assertEqual([(case._testMethodName,reason) for case,reason in result.skipped],[(names[-1],
            "actionlint is an export-time gate; already enforced before bundle export")])

    def test_liboqs_minimal_build_argument_and_installed_algorithm_record(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);native=root/"native";artifacts=root/"artifacts"
            header=native/"liboqs/include/oqs/oqsconfig.h";header.parent.mkdir(parents=True)
            enabled=["#define "+name+" 1" for name in provision.REQUIRED_ALGORITHMS]
            header.write_text("\n".join(enabled)+"\n")
            with patch.object(provision,"fetch",side_effect=[root/"openssl-source",root/"oqs-source"]),patch.object(provision,"command") as commands:
                provision.build(native,artifacts)
            cmake=next(call.args[0] for call in commands.call_args_list if call.args[0][:2]==["cmake","-S"])
            values=[v for v in cmake if isinstance(v,str) and v.startswith("-DOQS_MINIMAL_BUILD=")]
            self.assertEqual(values,["-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44;SIG_STFL_xmss_sha256_h10"])
            self.assertEqual(json.loads((artifacts/"native-build.json").read_text())["enabled_algorithm_lines"],enabled)

    def test_installed_header_requires_both_enabled_algorithms(self):
        with tempfile.TemporaryDirectory() as root:
            header=Path(root)/"oqsconfig.h"
            for missing in provision.REQUIRED_ALGORITHMS:
                with self.subTest(missing=missing):
                    header.write_text("\n".join("#define "+name+" 1" for name in provision.REQUIRED_ALGORITHMS if name!=missing))
                    with self.assertRaisesRegex(ValueError,"liboqs build is missing required algorithms: "+missing):
                        provision.require_algorithms(header)
            header.write_text("\n".join("#define "+name+" 0" for name in provision.REQUIRED_ALGORITHMS))
            with self.assertRaisesRegex(ValueError,"missing required algorithms"):
                provision.require_algorithms(header)

    def test_disabled_xmss_kat_output_has_explicit_error_before_digest(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            (root/"native-build.json").write_text(json.dumps(dict(openssl_source=str(root/"openssl"),
                liboqs_source=str(root/"oqs"),liboqs_build=str(root/"build"))))
            output=b"[sig_stfl_kat] XMSS-SHA2_10_256 was not enabled at compile-time.\n"
            with patch.object(provision.subprocess,"check_output",return_value=output):
                with self.assertRaisesRegex(ValueError,"XMSS KAT algorithm was not enabled at compile-time"):
                    provision.conformance(root)
            self.assertEqual((root/"xmss-kat-output.txt").read_bytes(),output)

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
        job_env=text.split("    env:\n",1)[1].split("    steps:\n",1)[0]
        self.assertNotIn("runner.temp",job_env)
        self.assertIn('echo "G3_ARTIFACTS=$RUNNER_TEMP/paper2-g3-artifacts" >> "$GITHUB_ENV"',text)
        self.assertIn("path: ${{ runner.temp }}/paper2-g3-artifacts/",text)
        for log in ("local-tests.txt","native-build.log"):
            self.assertIn('|| { tail -n 60 "$G3_ARTIFACTS/'+log+'"; exit 1; }',text)
        pins=json.loads((ROOT/"src/paper2/prototype/source_pins.json").read_text())
        workflows=text+(ROOT/"src/paper2/prototype/paper2-g3-replay.yml").read_text()
        for commit in pins["actions"].values():
            self.assertEqual(len(commit),40);self.assertIn("@"+commit,workflows)

    def test_generated_workflow_passes_actionlint_and_old_context_fails(self):
        if os.environ.get("GITHUB_ACTIONS")=="true":
            self.skipTest("actionlint is an export-time gate; already enforced before bundle export")
        if not export.actionlint_command():
            subprocess.run([sys.executable,"-m","pip","install","--disable-pip-version-check",
                            "actionlint-py=="+export.ACTIONLINT_PY_VERSION],check=True,timeout=180)
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);manifest=export.export(root/"bundle",allow_dirty=True)
            receipt=manifest["actionlint"]
            self.assertEqual((receipt["returncode"],receipt["stdout"],receipt["stderr"]),(0,"",""))
            self.assertEqual(set(manifest["actionlint_workflows"]),{"paper2-g3.yml","paper2-g3-replay.yml","paper2-g3-diagnostic.yml"})
            for name,item in manifest["actionlint_workflows"].items():
                self.assertEqual((item["returncode"],item["stdout"],item["stderr"]),(0,"",""))
                self.assertEqual(item["workflow_sha256"],analysis.sha256_file(root/"bundle/.github/workflows"/name))
            workflow=root/"bundle/.github/workflows/paper2-g3.yml"
            self.assertEqual(receipt["workflow_sha256"],analysis.sha256_file(workflow))
            broken=root/"broken.yml"
            broken.write_text(workflow.read_text().replace("    env:\n","    env:\n      INVALID: ${{ runner.temp }}\n",1))
            with self.assertRaisesRegex(RuntimeError,"actionlint rejected"):
                export.lint_workflow(broken)

    def test_export_fails_on_actionlint_findings(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(export,"lint_workflow",side_effect=RuntimeError("actionlint rejected")):
                with self.assertRaisesRegex(RuntimeError,"actionlint rejected"):
                    export.export(Path(root)/"bundle",allow_dirty=True)
            self.assertFalse((Path(root)/"bundle/BUNDLE_MANIFEST.json").exists())

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
