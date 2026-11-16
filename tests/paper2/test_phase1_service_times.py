"""Selector isolation, input authentication, reproducibility and seed separation."""

from tests.paper2._provenance import setUpModule, tearDownModule

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.paper2.model import run_model
from src.paper2.model.service_times import (BASELINE, ROOT, JOB_CLASSES, WorkloadStream,
    CalibrationSamples, CalibrationService, ConstantService, derive_seed, sha256_file, job_draw_integer)
from tests.paper2._support import check_trace, config


FIXTURES = Path(__file__).parent / "fixtures"


def selector(path=None, **overrides):
    path = path or FIXTURES / "session_a.csv"
    result = dict(path=str(path), sha256=sha256_file(path), backend="fixture_a",
                  operation="verify", variant="valid", session="0")
    result.update(overrides)
    return result


class Phase1ServiceTimes(unittest.TestCase):
    def test_deterministic_constants(self):
        model = ConstantService(dict(admission=0.1, block_tx=2, block_sig={"bit_flip": 3}))
        stream = WorkloadStream(0)
        self.assertEqual(model.sample("admission", "valid", 0), (0.1, "valid"))
        self.assertEqual(model.sample("block_tx", "valid", 0), (2, "valid"))
        self.assertEqual(model.sample("block_sig", "bit_flip", 0), (3, "invalid"))
        with self.assertRaises(ValueError):
            ConstantService(dict(admission=-1, block_tx=1, block_sig=1))

    def test_reproducible_exact_selector(self):
        table = CalibrationSamples(selector())
        a = WorkloadStream(derive_seed("repro", "service_admission", 0))
        b = WorkloadStream(derive_seed("repro", "service_admission", 0))
        draws_a = [table.sample(job_draw_integer("repro", 0, "service_admission", ["admission", str(i)])) for i in range(20)]
        draws_b = [table.sample(job_draw_integer("repro", 0, "service_admission", ["admission", str(i)])) for i in range(20)]
        self.assertEqual(draws_a, draws_b)
        self.assertEqual(table.durations, (1, 2))
        self.assertTrue(set(draws_a) <= {(1, "valid"), (2, "valid")})

    def test_only_requested_file_and_session(self):
        other = CalibrationSamples(selector(FIXTURES / "session_b.csv"))
        self.assertEqual(other.durations, (9, 10))
        session_one = CalibrationSamples(selector(session="1"))
        self.assertEqual(session_one.durations, (3,))
        selectors = {c: selector() for c in JOB_CLASSES}
        selectors["block_sig"] = selector(FIXTURES / "session_b.csv")
        with self.assertRaisesRegex(ValueError, "must not be pooled"):
            CalibrationService(selectors)

    def test_missing_combinations_raise_without_substitution(self):
        for override in (dict(backend="absent"), dict(variant="absent"), dict(session="absent"),
                         dict(operation="verify_invalid", variant="valid")):
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, "missing calibration"):
                CalibrationSamples(selector(**override))

    def test_wrong_checksum_refused(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            CalibrationSamples(selector(sha256="0" * 64))

    def test_invalid_operation_label_not_success_column(self):
        table = CalibrationSamples(selector(operation="verify_invalid", variant="single_bit_flip"))
        self.assertEqual(table.sample(0), (7, "invalid"))

    def test_named_streams_are_separate_and_order_independent(self):
        seed = derive_seed("streams", "arrivals", 2)
        control = WorkloadStream(seed)
        arrivals = WorkloadStream(seed)
        service = WorkloadStream(derive_seed("streams", "service_admission", 2))
        expected = [control.random() for _ in range(5)]
        for _ in range(100):
            service.random()
        self.assertEqual([arrivals.random() for _ in range(5)], expected)
        self.assertNotEqual(seed, derive_seed("streams", "block_contents", 2))
        self.assertNotEqual(seed, derive_seed("streams", "arrivals", 3))

    def test_real_primary_files_use_protected_checksums(self):
        baseline = dict(line.split("  ", 1)[::-1] for line in BASELINE.read_text().splitlines())
        for family, arch in [("ARM64", "aarch64"), ("X64", "x86_64")]:
            for rep in (1, 2, 3):
                relative = ("results/revision_r1/cross_platform_20261021_130205/imports/"
                            f"calib-{family}-rep{rep}/calib-{arch}-rep{rep}/raw_samples.csv")
                with self.subTest(path=relative):
                    spec = dict(path=str(ROOT / relative), sha256=baseline[relative],
                                backend="ed25519_cryptography", operation="verify", variant="valid")
                    table = CalibrationSamples(spec)
                    with (ROOT / relative).open(encoding="utf-8-sig", newline="") as stream:
                        expected = tuple(int(r["duration_ns"]) / 1e9 for r in csv.DictReader(stream)
                                         if r["backend"] == spec["backend"] and r["operation"] == "verify" and r["variant"] == "valid")
                    self.assertEqual(table.durations, expected)
                    self.assertEqual(table.input_record["sha256"], baseline[relative])
                    self.assertIsNotNone(table.input_record["protected_baseline"])

    def test_protected_manifest_mismatch_is_not_overridden(self):
        relative = ("results/revision_r1/cross_platform_20261021_130205/imports/"
                    "calib-ARM64-rep1/calib-aarch64-rep1/raw_samples.csv")
        path = ROOT / relative
        with tempfile.TemporaryDirectory(prefix="paper2-baseline-test-") as temp:
            baseline = Path(temp) / "baseline.txt"
            baseline.write_text("0" * 64 + "  " + relative + "\n", encoding="utf-8")
            with patch("src.paper2.model.service_times.BASELINE", baseline):
                with self.assertRaisesRegex(ValueError, "protected Phase 0 baseline"):
                    CalibrationSamples(dict(path=str(path), sha256=sha256_file(path),
                                            backend="ed25519_cryptography", operation="verify", variant="valid"))

    def test_resampled_run_manifest_and_job_trace(self):
        with tempfile.TemporaryDirectory(prefix="paper2-sampled-test-") as temp:
            settings = config(output_dir=temp, admissions=[dict(tx_id="a", arrival_t=0)],
                              blocks=[dict(block_id="B", tx_ids=["a"])],
                              service=dict(mode="calibration", selectors={c: selector() for c in JOB_CLASSES}))
            log, manifest = run_model(settings)
            _, data = check_trace(self, log, manifest, 1)
            self.assertEqual(len(data["input_files"]), 3)
            self.assertTrue(all(j["service_time"] in (1, 2) for j in data["jobs"]))
            self.assertTrue(all(i["sha256"] == selector()["sha256"] for i in data["input_files"]))
