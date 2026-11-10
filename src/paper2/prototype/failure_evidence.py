"""Retain public partial outputs without representing them as verified inputs."""
import argparse
import json
import os
from pathlib import Path
import shutil
from .input_trust import MARKER
from .public_corpus import FORBIDDEN_SUFFIXES


def preserve(destination, sources):
    destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
    (destination/MARKER).write_text('UNVERIFIED failed attempt; inspection only, not replay or authorization input.\n')
    retained=[];excluded=[]
    for i,source in enumerate(map(Path,sources)):
        files=[source] if source.is_file() else list(source.rglob('*')) if source.is_dir() else []
        for file in files:
            if not file.is_file() or file.is_symlink():continue
            rel=Path(file.name) if source.is_file() else file.relative_to(source)
            if destination.resolve() in (file.resolve(),*file.resolve().parents):continue
            if (any(p in ('private','.git','.venv','venv') for p in rel.parts) or
                file.suffix.lower() in FORBIDDEN_SUFFIXES or file.name.lower().startswith('.env') or
                any(s in file.name.lower() for s in ('private','secret','signing_state','signing-state'))):
                excluded.append(str(rel));continue
            target=destination/str(i)/rel;target.parent.mkdir(parents=True,exist_ok=True)
            if target.exists():continue
            try:os.link(file,target)  # public evidence survives, without duplicating disk bytes
            except OSError:shutil.copyfile(file,target)
            retained.append(str(target.relative_to(destination)))
    (destination/'FAILURE_INVENTORY.json').write_text(json.dumps(dict(verified=False,retained=retained,excluded=excluded)))
    return retained


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('sources',nargs='*',type=Path)
    a=p.parse_args();preserve(a.output,a.sources)


if __name__=='__main__':main()
