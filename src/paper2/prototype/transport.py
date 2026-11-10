"""Lossless, content-addressed transport of sealed replay evidence.

Scientific readers consume reconstructed original files, never this encoding.
An upload acknowledgement requires a separately downloaded, verified inventory.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
from . import artifact_integrity as inventory
from .replay import safe_file, save, read, sha256_file

SCHEMA = 'paper2-transport-v1'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()+b'\n'


def split_metadata(raw, table):
    """Factor transaction objects only when JSON round-trip is byte-identical.

    All nodes are tagged arrays: input dictionaries resembling references cannot
    be mistaken for transport instructions. Dictionary order is retained.
    """
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return None
    if canonical(value) != raw:
        return None
    def encode(v):
        if isinstance(v, dict):
            if ('nonce' in v and ('sender' in v or 'sender_id' in v)):
                b = canonical(v); key = digest(b)
                table.setdefault(key, v)
                return ['ref', key]
            return ['dict', [[k, encode(x)] for k, x in v.items()]]
        if isinstance(v, list):
            return ['list', [encode(x) for x in v]]
        return ['value', v]
    return canonical(encode(value))


def join_metadata(raw, table):
    def decode(node):
        kind, value = node
        if kind == 'ref':
            item = table[value]
            if digest(canonical(item)) != value:
                raise ValueError('transaction metadata hash mismatch')
            return item
        if kind == 'dict': return {k: decode(v) for k, v in value}
        if kind == 'list': return [decode(v) for v in value]
        if kind == 'value': return value
        raise ValueError('invalid transport JSON node')
    return canonical(decode(json.loads(raw)))


def pack(source, destination, known=None):
    """Publish only new blobs; references bind earlier canonical artifacts.

    known maps blob hashes to the artifact containing them. No raw file is
    removed here. All raw and compressed sizes/hashes are sealed in inventory.
    """
    source, destination = Path(source), Path(destination)
    if destination.exists(): raise FileExistsError('transport destination must be new')
    destination.mkdir(parents=True)
    table, rows, objects = {}, [], {}
    known = known or {}
    def blob(raw):
        encoded = gzip.compress(raw, compresslevel=6, mtime=0)
        key = digest(encoded)
        objects[key] = dict(sha256=key, bytes=len(encoded), raw_sha256=digest(raw), raw_bytes=len(raw),
                            artifact=known.get(key))
        if key not in known:
            path = destination/'objects'/(key+'.gz')
            path.parent.mkdir(exist_ok=True)
            if not path.exists(): path.write_bytes(encoded)
        return key
    for path in sorted(source.rglob("*")):
        if not path.is_file(): continue
        safe_file(source,path.relative_to(source).as_posix())
        raw = path.read_bytes()
        encoded = split_metadata(raw, table) if path.suffix == '.json' else None
        rows.append(dict(path=path.relative_to(source).as_posix(), sha256=digest(raw), bytes=len(raw),
                         codec='json-metadata' if encoded is not None else 'raw',
                         object=blob(encoded if encoded is not None else raw)))
    metadata = blob(canonical(table))
    document = dict(schema=SCHEMA, files=rows, metadata=metadata, objects=objects)
    save(destination/'TRANSPORT.json', document)
    inventory.write_checksums(destination)
    verify(destination, known_roots={}) if not known else inventory.verify_checksums(destination)
    return document


def object_bytes(root, key, description, known_roots):
    path = safe_file(root, 'objects/'+key+'.gz')
    if not path.is_file():
        artifact = description.get('artifact')
        if artifact not in known_roots: raise ValueError('missing canonical transport artifact')
        path = safe_file(known_roots[artifact], 'objects/'+key+'.gz')
    if sha256_file(path) != key or path.stat().st_size != description['bytes']:
        raise ValueError('compressed transport checksum mismatch')
    with gzip.open(path, 'rb') as stream: raw = stream.read()
    if digest(raw) != description['raw_sha256'] or len(raw) != description['raw_bytes']:
        raise ValueError('raw transport checksum mismatch')
    return raw


def verify(root, known_roots=None, output=None):
    root = Path(root); known_roots = known_roots or {}
    inventory.verify_checksums(root)
    doc = read(root/'TRANSPORT.json')
    if doc['schema'] != SCHEMA: raise ValueError('unsupported transport schema')
    def get(key): return object_bytes(root, key, doc['objects'][key], known_roots)
    table = json.loads(get(doc['metadata']))
    seen = set()
    if output is not None:
        output = Path(output)
        if output.exists(): raise FileExistsError('reconstruction must be new')
        output.mkdir(parents=True)
    for row in doc['files']:
        safe_file(root, row['path'])
        if row['path'] in seen: raise ValueError('duplicate raw transport entry')
        seen.add(row['path'])
        raw = get(row['object'])
        if row['codec'] == 'json-metadata': raw = join_metadata(raw, table)
        elif row['codec'] != 'raw': raise ValueError('invalid transport codec')
        if digest(raw) != row['sha256'] or len(raw) != row['bytes']:
            raise ValueError('reconstructed file checksum mismatch')
        if output is not None:
            path = safe_file(output, row['path']); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    return doc


def read_file(root,name,known_roots=None):
    """Restore one inventory-bound file without materialising a whole tree."""
    root=Path(root);inventory.verify_checksums(root)
    doc=read(root/'TRANSPORT.json');known_roots=known_roots or {}
    row=next(r for r in doc['files'] if r['path']==name)
    def get(key):return object_bytes(root,key,doc['objects'][key],known_roots)
    raw=get(row['object'])
    if row['codec']=='json-metadata':
        def needs_table(node):
            kind,value=node
            if kind=='ref':return True
            if kind=='dict':return any(needs_table(v) for _,v in value)
            if kind=='list':return any(needs_table(v) for v in value)
            return False
        table=json.loads(get(doc['metadata'])) if needs_table(json.loads(raw)) else {}
        raw=join_metadata(raw,table)
    elif row['codec']!='raw':raise ValueError('invalid transport codec')
    if len(raw)!=row['bytes'] or digest(raw)!=row['sha256']:
        raise ValueError('selected transport file checksum mismatch')
    return raw


def acknowledge(source, upload, downloaded, artifact, known_roots=None):
    """Delete raw files only after upload/download inventory and content checks.

    artifact is the official upload action's immutable artifact-id and digest.
    The download action selects exactly that artifact-id in the same run.
    """
    if not artifact.get('id') or not artifact.get('digest'):
        raise ValueError('immutable uploaded artifact receipt required')
    inventory.verify_checksums(upload); inventory.verify_checksums(downloaded)
    if (Path(upload)/inventory.NAME).read_bytes() != (Path(downloaded)/inventory.NAME).read_bytes():
        raise ValueError('uploaded inventory differs')
    doc = verify(downloaded, known_roots)
    source = Path(source)
    expected = {row['path'] for row in doc['files']}
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()}
    if actual != expected: raise ValueError('raw deletion inventory differs')
    for row in doc['files']:
        path = safe_file(source, row['path'])
        if sha256_file(path) != row['sha256']: raise ValueError('raw file changed after sealing')
    receipt = dict(artifact=artifact, transport_sha256=sha256_file(Path(downloaded)/'TRANSPORT.json'),
                   files=len(expected), raw_bytes=sum(r['bytes'] for r in doc['files']),
                   compressed_bytes=sum(r['bytes'] for r in doc['objects'].values()), verified=True)
    # Each resolved path is checked by safe_file; never recursively delete raw roots.
    for row in doc['files']: safe_file(source, row['path']).unlink()
    checksum = source/inventory.NAME
    if checksum.is_file(): checksum.unlink()
    return receipt


def verify_uploaded_zip(path,expected):
    import zipfile
    if path is None or not expected: raise ValueError('uploaded archive digest required')
    if sha256_file(Path(path))!=expected.removeprefix('sha256:'):
        raise ValueError('uploaded archive digest mismatch')
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None: raise ValueError('uploaded archive CRC mismatch')
    return True


def disk_guard(path, projected_peak_bytes):
    import math
    if isinstance(projected_peak_bytes, bool) or not isinstance(projected_peak_bytes, int) or projected_peak_bytes <= 0:
        raise ValueError('positive projected peak footprint required')
    free = shutil.disk_usage(path).free
    threshold = math.ceil(1.5*projected_peak_bytes)
    receipt = dict(free_bytes=free, projected_peak_bytes=projected_peak_bytes, threshold_bytes=threshold,
                   margin=1.5, passed=free >= threshold)
    if not receipt['passed']: raise RuntimeError('insufficient disk before presigning: '+json.dumps(receipt))
    return receipt


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('pack','verify','unpack'))
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path)
    a=p.parse_args()
    if a.command=='pack': pack(a.source,a.output)
    else: verify(a.source,output=a.output if a.command=='unpack' else None)


if __name__=='__main__': main()
