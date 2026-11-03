"""Audited public signed bytes, transported only as a hash-bound workflow artifact."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

LIMIT = 2_000_000_000
FORBIDDEN_SUFFIXES = {".state", ".key", ".pem", ".p12", ".pfx", ".seed", ".pickle", ".pkl"}


def digest(raw): return hashlib.sha256(raw).hexdigest()


def audit(value):
    if isinstance(value, dict):
        for key, item in value.items():
            name = key.lower()
            if (any(s in name for s in ("private", "secret", "seed", "counter")) or
                name in {"state", "signing_state", "presigning", "next_leaf", "next_index", "next_nonce"}):
                raise ValueError("excluded private/seed/state field in public corpus: " + key)
            audit(item)
    elif isinstance(value, list):
        for item in value: audit(item)
    elif isinstance(value, str) and ("PRIVATE" + " KEY") in value.upper():
        raise ValueError("private material in public corpus")


def document(corpus):
    # Workload RNG provenance and presigning ledgers are not needed by the checker.
    result = {k: corpus[k] for k in ("version", "backend", "context", "transactions", "blocks", "block_objects")}
    result["workload"] = {k: corpus["workload"][k] for k in ("transactions", "blocks")}
    audit(result)
    return result


def validate_archive(path, expected=None):
    path = Path(path)
    if expected is not None and digest(path.read_bytes()) != expected["sha256"]:
        raise ValueError("public corpus archive SHA-256 mismatch")
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != ["corpus.json"]:
            raise ValueError("excluded file or unexpected public corpus inventory")
        info = archive.getinfo("corpus.json")
        if info.file_size > LIMIT: raise ValueError("public corpus exceeds 2 GB")
        raw = archive.read("corpus.json")
    audit(json.loads(raw))
    entry = dict(path="corpus.json", sha256=digest(raw), bytes=len(raw))
    if expected is not None and expected["files"] != [entry]:
        raise ValueError("public corpus file SHA-256 mismatch")
    return dict(sha256=digest(path.read_bytes()), compressed_bytes=path.stat().st_size,
                uncompressed_bytes=len(raw), files=[entry])


def write_archive(corpus, destination, existing=()):
    destination = Path(destination)
    raw = json.dumps(document(corpus), ensure_ascii=True, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(raw) + sum(r["uncompressed_bytes"] for r in existing) > LIMIT:
        raise ValueError("STOP: total public corpus exceeds 2 GB uncompressed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Temporary zip is outside the upload directory until every audit passes.
    with tempfile.TemporaryDirectory(prefix="paper2-public-corpus-") as td:
        temp = Path(td) / "public-corpus.zip"
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            info = zipfile.ZipInfo("corpus.json", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3; info.external_attr = 0o100644 << 16
            archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        record = validate_archive(temp)
        if record["compressed_bytes"] + sum(r["compressed_bytes"] for r in existing) > LIMIT:
            raise ValueError("STOP: total public corpus exceeds 2 GB compressed")
        if destination.exists(): raise FileExistsError("public corpus already exists")
        destination.write_bytes(temp.read_bytes())
    return record


def inventory(root):
    rows = []
    for path in sorted(Path(root).rglob("public-corpus.zip")):
        rows.append(dict(path=path.relative_to(root).as_posix(), **validate_archive(path)))
    result = dict(files=rows, compressed_bytes=sum(r["compressed_bytes"] for r in rows),
                  uncompressed_bytes=sum(r["uncompressed_bytes"] for r in rows), limit_bytes=LIMIT)
    if result["compressed_bytes"] > LIMIT or result["uncompressed_bytes"] > LIMIT:
        raise ValueError("STOP: total public corpus exceeds 2 GB")
    return result


def audit_upload(root):
    root = Path(root)
    for path in root.rglob("*"):
        if path.is_file() and (path.suffix.lower() in FORBIDDEN_SUFFIXES or path.name.lower().startswith(".env") or
            any(s in path.name.lower() for s in ("private", "secret", "seed", "signing_state", "signing-state"))):
            raise ValueError("excluded private/state file in corpus artifact: " + path.name)
    return inventory(root)


def checker_manifest(packet, output):
    """Original checker and original logs; relocate only its public input paths."""
    packet, output = Path(packet), Path(output)
    info = json.loads((packet / "info.json").read_text())
    archive = packet / "prototype/public-corpus.zip"
    validate_archive(archive, info["public_corpus"])
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as source:
        raw = source.read("corpus.json")
    corpus = output / "corpus.json"; corpus.write_bytes(raw)
    manifest = json.loads((packet / "prototype/manifest.json").read_text())
    import os
    manifest["prototype"].update(corpus_path=corpus.name, corpus_sha256=digest(raw),
        spans=dict(path=os.path.relpath(packet / "prototype/dispatcher_spans.json", output),
                   sha256=manifest["prototype"]["spans"]["sha256"]))
    target = output / "manifest.json"
    target.write_bytes(json.dumps(manifest, separators=(",", ":")).encode() + b"\n")
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("root", type=Path)
    args = parser.parse_args(); print(json.dumps(audit_upload(args.root)))
