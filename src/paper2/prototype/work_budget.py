"""Standalone Linux job watchdog; embedded verbatim before checkout in ARM jobs.

It kills tagged work processes, including Action processes, but exempts failure
evidence steps. No repository imports: system Python can start it in step one.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

LIMIT = 280*60


def start(root, seconds=LIMIT):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    path=root/'watchdog.json'
    if not path.exists():
        path.write_text(json.dumps(dict(monotonic_ns=time.monotonic_ns(),work_seconds=seconds,work_minutes=280)))
    return json.loads(path.read_text())


def require(root, cap=0):
    root=Path(root);record=json.loads((root/'watchdog.json').read_text())
    remaining=record.get('work_seconds',LIMIT)-(time.monotonic_ns()-record['monotonic_ns'])/1e9
    if (root.parent/'WATCHDOG_EXPIRED.json').exists() or remaining<=0 or cap>remaining:
        raise TimeoutError('stage cap exceeds remaining 280-minute work budget')
    return remaining


def tagged_processes(token):
    selected=set();parents={}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            pid=int(path.name);raw=(path/'environ').read_bytes().split(b'\0')
            parents[pid]=int((path/'stat').read_text().rsplit(')',1)[1].split()[1])
            if b'PAPER2_WORK_TOKEN='+token.encode() in raw and b'PAPER2_FAILURE_EVIDENCE=1' not in raw:
                selected.add(pid)
        except (OSError,ValueError):continue
    # Descendants include sudo/native workers whose environment may be scrubbed.
    while True:
        extra={pid for pid,parent in parents.items() if parent in selected}
        if extra<=selected:break
        selected|=extra
    selected.discard(os.getpid())
    return selected


def monitor(root, token, poll=.2, process_source=None, terminate=None):
    root=Path(root);start(root);expired=False
    while not (root.parent/'WATCHDOG_STOP').exists():
        try:require(root)
        except TimeoutError:
            if not expired:
                evidence=root.parent/'failure-upload';evidence.mkdir(parents=True,exist_ok=True)
                receipt=dict(reason='active aggregate 280-minute work limit',monotonic_ns=time.monotonic_ns())
                (root.parent/'WATCHDOG_EXPIRED.json').write_text(json.dumps(receipt))
                (evidence/'UNVERIFIED').write_text('UNVERIFIED: watchdog stopped this attempt; inspection only.\n')
                (evidence/'WATCHDOG_TIMEOUT.json').write_text(json.dumps(receipt))
                expired=True
            for pid in (process_source or tagged_processes)(token):
                if terminate:terminate(pid);continue
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except PermissionError:
                    subprocess.run(['sudo','-n','kill','-KILL',str(pid)],check=False)
        time.sleep(poll)


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=('start','monitor','require','stop'))
    p.add_argument('--root',type=Path,required=True);p.add_argument('--token',default='');p.add_argument('--cap',type=float,default=0)
    a=p.parse_args()
    if a.command=='start':start(a.root)
    elif a.command=='require':require(a.root,a.cap)
    elif a.command=='stop':(a.root.parent/'WATCHDOG_STOP').touch()
    else:monitor(a.root,a.token)


if __name__=='__main__':main()
