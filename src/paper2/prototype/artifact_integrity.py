"""Complete, visible artifact inventories shared by upload and replay."""
import hashlib
from pathlib import Path, PurePosixPath
import re

NAME = 'SHA256SUMS'


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''): value.update(chunk)
    return value.hexdigest()


def payload(root):
    root = Path(root).resolve()
    files = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink(): raise ValueError('symlink in artifact output: '+str(path.relative_to(root)))
        if path.is_file() and path != root/NAME: files.append(path)
    return files


def write_checksums(root):
    root = Path(root).resolve(); root.mkdir(parents=True, exist_ok=True)
    rows = [digest(p)+'  '+p.relative_to(root).as_posix() for p in payload(root)]
    (root/NAME).write_bytes(('\n'.join(rows)+('\n' if rows else '')).encode())
    # Hashes were just computed; avoid re-reading the whole output before upload.
    return verify_checksums(root, check_hashes=False)


def verify_checksums(root, *, check_hashes=True):
    root = Path(root).resolve(); manifest = root/NAME
    if not manifest.is_file(): raise ValueError('missing artifact checksum inventory: '+NAME)
    seen = set()
    for line in manifest.read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match: raise ValueError('invalid artifact checksum entry')
        expected, name = match.groups(); rel = PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts or '\\' in name or ':' in name or name in seen or name == NAME:
            raise ValueError('unsafe or duplicate artifact checksum path: '+name)
        if any(part.startswith('.') for part in rel.parts):
            raise ValueError('hidden artifact would be excluded by upload: '+name)
        path = root.joinpath(*rel.parts)
        if root not in path.resolve().parents or any(p.is_symlink() for p in (path, *path.parents) if p != root):
            raise ValueError('unsafe artifact checksum target: '+name)
        if not path.is_file(): raise ValueError('missing artifact checksum entry: '+name)
        if check_hashes and digest(path) != expected: raise ValueError('artifact SHA-256 mismatch: '+name)
        seen.add(name)
    actual = {p.relative_to(root).as_posix() for p in payload(root)}
    if seen != actual: raise ValueError('unlisted artifact files: '+','.join(sorted(actual-seen)))
    return dict(files=len(seen), hashes_verified=check_hashes, hidden_files=0)


def verify_if_present(root):
    if (Path(root)/NAME).is_file(): return verify_checksums(root)
    return None


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Verify complete visible ARM/replay artifact inventory')
    parser.add_argument('root', type=Path)
    print(json.dumps(verify_checksums(parser.parse_args().root)))
