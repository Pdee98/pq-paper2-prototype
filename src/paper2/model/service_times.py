"""Explicit verification selectors, authenticated input files, and named streams."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path

from src.experiment.workload_rng import WorkloadStream


ROOT = Path(__file__).resolve().parents[3]
BASELINE = ROOT / "research/paper2/phase0/protected_sha256.txt"
JOB_CLASSES = ("admission", "block_tx", "block_sig")
STREAM_NAMES = ("arrivals", "arrivals_invalid", "block_contents", "labels", "cache_evict",
                *("service_" + c for c in JOB_CLASSES))
SEED_VERSION = "paper2-stream-sha256-v1"
JOB_DRAW_VERSION = "paper2-job-draw-v1"
LABEL_SELECTORS = {"valid": ("verify", "valid"),
                   "bit_flip": ("verify_invalid", "single_bit_flip"),
                   "random_bytes": ("verify_invalid", "random_bytes")}


def job_draw_integer(run_id, replicate, stream_name, job_key):
    derive_seed(run_id, stream_name, replicate)  # Validate seed components.
    if stream_name not in {"service_" + c for c in JOB_CLASSES}:
        raise ValueError("job draws require a service stream")
    if not isinstance(job_key, list) or not job_key:
        raise ValueError("job_key must be a nonempty list")
    sizes = {"admission": 2, "block_tx": 3, "block_sig": 2}
    if (job_key[0] not in sizes or len(job_key) != sizes[job_key[0]]
            or stream_name != "service_" + job_key[0]
            or any(not isinstance(v, str) or not v for v in job_key)):
        raise ValueError("invalid job identity")
    payload = json.dumps([JOB_DRAW_VERSION, run_id, replicate, stream_name, job_key],
                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


def nonnegative(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite nonnegative number")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite nonnegative number")
    return float(value)


def derive_seed(run_id: str, stream: str, replicate: int) -> int:
    """SHA256(JSON([version, run_id, stream, replicate])) interpreted big-endian."""
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be nonempty text")
    if stream not in STREAM_NAMES:
        raise ValueError("unknown stream")
    if isinstance(replicate, bool) or not isinstance(replicate, int) or replicate < 0:
        raise ValueError("replicate must be a nonnegative integer")
    payload = json.dumps([SEED_VERSION, run_id, stream, replicate],
                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class ConstantService:
    """Per-(class,label) constants. Scalars retain valid-only Phase 1 inputs."""

    def __init__(self, seconds):
        if set(seconds) != set(JOB_CLASSES):
            raise ValueError("seconds must specify exactly the three job classes")
        self.seconds = {}
        for c, value in seconds.items():
            labels = value if isinstance(value, dict) else {"valid": value}
            if not labels or not set(labels) <= set(LABEL_SELECTORS):
                raise ValueError("unknown signature label")
            self.seconds[c] = {label: nonnegative(v, c) for label, v in labels.items()}
        self.inputs = []

    def sample(self, job_class, label, draw):
        if label not in self.seconds[job_class]:
            raise ValueError(f"missing constant label: {job_class}/{label}")
        return self.seconds[job_class][label], "valid" if label == "valid" else "invalid"


class CalibrationSamples:
    """One file and exact selector; no operation, variant, or host fallback."""

    def __init__(self, spec):
        required = {"path", "sha256", "backend", "operation", "variant"}
        if not required <= set(spec) or set(spec) - required - {"session"}:
            raise ValueError("calibration selector requires path, sha256, backend, operation, variant")
        path = Path(spec["path"]).resolve()
        actual = sha256_file(path)
        if not isinstance(spec["sha256"], str) or actual != spec["sha256"].lower():
            raise ValueError("calibration SHA-256 mismatch")
        baseline_ref = None
        try:
            relative = path.relative_to(ROOT).as_posix()
        except ValueError:
            relative = None
        if relative is not None and relative.startswith(("results/", "r4_audit/", "r5_", "r6/", "zenodo_")):
            baseline = dict(line.split("  ", 1)[::-1]
                            for line in BASELINE.read_text(encoding="utf-8").splitlines())
            if relative not in baseline or baseline[relative] != actual:
                raise ValueError("calibration does not match the protected Phase 0 baseline")
            baseline_ref = {"path": str(BASELINE), "sha256": sha256_file(BASELINE)}
        operation = spec["operation"]
        if operation not in ("verify", "verify_invalid"):
            raise ValueError("verification service requires verify or verify_invalid")
        # Publication success=true means the calibration CHECK passed, including
        # successful rejection for verify_invalid. It is not signature validity.
        self.outcome = "valid" if operation == "verify" else "invalid"
        durations = []
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            fields = {"backend", "operation", "variant", "duration_ns"}
            if not fields <= set(reader.fieldnames or ()):
                raise ValueError("calibration CSV is missing required columns")
            for row in reader:
                if any(row[k] != spec[k] for k in ("backend", "operation", "variant")):
                    continue
                if "session" in spec and row.get("session") != str(spec["session"]):
                    continue
                if row.get("success", "true").lower() != "true":
                    raise ValueError("selected calibration contains an unsuccessful check")
                duration = int(row["duration_ns"])
                if duration < 0:
                    raise ValueError("negative calibration duration")
                durations.append(duration / 1_000_000_000)
        if not durations:
            raise ValueError("missing calibration backend/operation/variant/session combination")
        self.durations = tuple(durations)
        self.input_record = dict(spec, path=str(path), sha256=actual,
                                 selected_samples=len(durations), protected_baseline=baseline_ref)

    def sample(self, draw):
        if isinstance(draw, bool) or not isinstance(draw, int) or draw < 0:
            raise ValueError("sample draw must be a nonnegative integer")
        return self.durations[draw % len(self.durations)], self.outcome


class CalibrationService:
    """Exact per-(class,label) selectors from ONE host/session file."""

    def __init__(self, selectors):
        if set(selectors) != set(JOB_CLASSES):
            raise ValueError("selectors must specify exactly the three job classes")
        normalized = {c: ({"valid": value} if "path" in value else value)
                      for c, value in selectors.items()}
        if len({str(Path(s["path"]).resolve()) for v in normalized.values() for s in v.values()}) != 1:
            raise ValueError("one calibration file per run; host/session files must not be pooled")
        self.tables = {}
        for c, labels in normalized.items():
            for label, spec in labels.items():
                if label not in LABEL_SELECTORS or (spec["operation"], spec["variant"]) != LABEL_SELECTORS[label]:
                    raise ValueError("selector does not match class/label operation and variant")
                self.tables[c, label] = CalibrationSamples(spec)
        self.inputs = [dict(table.input_record, job_class=c, label=label)
                       for (c, label), table in self.tables.items()]

    def sample(self, job_class, label, draw):
        if (job_class, label) not in self.tables:
            raise ValueError(f"missing calibration class/label: {job_class}/{label}")
        duration, _ = self.tables[job_class, label].sample(draw)
        return duration, "valid" if label == "valid" else "invalid"
