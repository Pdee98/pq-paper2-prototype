"""Explicit pre-upload inventory/seal gates; failure evidence never enters them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
from . import artifact_integrity, replay, public_corpus
from .input_trust import reject


def inventory(root):
    root=Path(root);reject(root)
    if not root.exists():raise ValueError('missing upload payload')
    if root.is_file():return {root.name:replay.sha256_file(root)}
    if (root/'SHA256SUMS').is_file():artifact_integrity.verify_checksums(root)
    files=artifact_integrity.payload(root)
    if not files:raise ValueError('empty upload payload')
    if any(any(c.startswith('.') for c in p.relative_to(root).parts) for p in files):
        raise ValueError('hidden upload payload')
    return {p.relative_to(root).as_posix():replay.sha256_file(p) for p in files}


def seal(root):
    root=Path(root);files=inventory(root)
    if root.is_dir():public_corpus.audit_upload(root)
    elif root.suffix.lower() in public_corpus.FORBIDDEN_SUFFIXES or root.name.startswith('.env'):
        raise ValueError('private upload file')
    for name in ('RESULT_MANIFEST.json','REPLAY_MANIFEST.json'):
        if (root/name).is_file():replay.verify_files(root,name)
    if (root/'CONTROL.json').is_file():
        from .transport import read_file
        doc=replay.read(root/'CONTROL.json')
        if doc.get('failure') is not None or not doc.get('part_sha256'):raise ValueError('incomplete control upload')
        raw=read_file(root,'PART.json');part=json.loads(raw)
        if hashlib.sha256(raw).hexdigest()!=doc['part_sha256'] or part.get('operational_status')!='complete':
            raise ValueError('control part seal mismatch')
    if (root/'TRANSPORT.json').is_file() and not (root/'CONTROL.json').is_file() and os.environ.get('G3_ROOT'):
        # The pending raw packet is still present until upload acknowledgement.
        control=Path(os.environ['G3_ROOT'])/'control'
        from .production import load
        state=load(control);pending=state['pending']
        if Path(pending['upload']).resolve()!=root.resolve():raise ValueError('wrong pending packet')
        replay.verify_files(pending['packet'],'REPLAY_MANIFEST.json')
        if replay.sha256_file(Path(pending['packet'])/'REPLAY_MANIFEST.json')!=pending['manifest_sha256']:
            raise ValueError('pending packet seal mismatch')
    elif (root/'TRANSPORT.json').is_file() and not (root/'CONTROL.json').is_file():
        from .transport import verify
        verify(root)
    if root.is_dir() and not any((root/name).is_file() for name in ('SHA256SUMS','RESULT_MANIFEST.json','REPLAY_MANIFEST.json')):
        for name in ('UPLOAD_SEAL.json','UPLOAD_SEAL.json.sha256'):files.pop(name,None)
        replay.save(root/'UPLOAD_SEAL.json',dict(schema='paper2-upload-seal-v1',files=files))
        (root/'UPLOAD_SEAL.json.sha256').write_text(replay.sha256_file(root/'UPLOAD_SEAL.json')+'\n')
    # Standalone seal receipt kept beside the payload, so domain seals/inventories
    # remain byte-identical. Its hashes are also printed into the step log.
    receipt=dict(files=files,sha256=hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest())
    target=root.with_name(root.name+'-upload-seal.json');replay.save(target,receipt)
    print(json.dumps(dict(files=len(files),seal_sha256=receipt['sha256'])),flush=True)
    return receipt


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('inventory','seal'));p.add_argument('--root',type=Path,required=True)
    a=p.parse_args()
    work=Path(os.environ.get('G3_ROOT',''))/'control'
    if os.environ.get('G3_ROOT') and (work/'watchdog.json').exists():
        from .work_budget import require
        require(work)
    (inventory if a.command=='inventory' else seal)(a.root)


if __name__=='__main__':main()
