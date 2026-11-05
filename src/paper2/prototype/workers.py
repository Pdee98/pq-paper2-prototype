"""Dedicated duplex Pipes and monotonic worker timestamps; no task executor queue."""

import multiprocessing as mp
from multiprocessing.connection import wait
import time

from .backends import Verifier


def worker(pipe, backend, public_keys, sleep_seconds, gc_directory=None):
    verifier=None
    control=monitor=None
    try:
        verifier=Verifier(backend,sleep_seconds)
        for key in public_keys:verifier.register(key)
        if gc_directory is not None:
            from .gc_control import WindowGC
            from .pause_attribution import PauseRecorder
            monitor=PauseRecorder(gc_directory,detailed=False)
            control=WindowGC(gc_directory,monitor);control.enter()
        pipe.send(("ready",verifier.metadata()))
        while True:
            request=pipe.recv()
            if request is None:return
            if request[0]=='gc_end':
                if control:control.leave()
                if monitor:monitor.finish()
                pipe.send(('gc_end',));continue
            if request[0]=="clock":
                pipe.send(("clock",time.monotonic_ns()));continue
            _,identity,message,signature,public=request
            prepared=verifier.prepare(message,signature,public)
            try:
                begin=time.monotonic_ns()
                valid=verifier.primitive(prepared)
                end=time.monotonic_ns()
            finally:verifier.release(prepared)
            pipe.send(("result",identity,begin,end,valid))
    except BaseException as exc:
        try:pipe.send(("error",type(exc).__name__+": "+str(exc)))
        except (OSError,EOFError):pass
    finally:
        if control:control.leave(partial=True)
        if monitor and not monitor.closed:monitor.finish(partial=True)
        if verifier:verifier.close()
        pipe.close()


class Workers:
    def __init__(self,k,backend,public_keys,sleep_seconds=0,timeout=60,gc_directory=None):
        self.processes=[];self.pipes=[];self.metadata=[];self.clock_records=[]
        ctx=mp.get_context("spawn")
        try:
            for i in range(k):
                parent,child=ctx.Pipe(duplex=True)
                from pathlib import Path
                directory=None if gc_directory is None else str(Path(gc_directory)/f'worker-{i}')
                process=ctx.Process(target=worker,args=(child,backend,public_keys,sleep_seconds,directory),name=f"paper2-verify-{i}")
                process.start();child.close();self.pipes.append(parent);self.processes.append(process)
            for pipe in self.pipes:
                if not pipe.poll(timeout):raise TimeoutError("worker backend initialisation timed out")
                reply=pipe.recv()
                if reply[0]!="ready":raise RuntimeError(str(reply))
                self.metadata.append(reply[1])
            self.gc_controlled=gc_directory is not None
            self.handshake("before")
        except BaseException:
            self.close();raise

    def handshake(self,phase):
        for i,pipe in enumerate(self.pipes):
            if phase=='after' and self.gc_controlled:
                pipe.send(('gc_end',))
                if not pipe.poll(30) or pipe.recv()!=('gc_end',):raise RuntimeError('worker GC drain receipt missing')
            probes=[]
            for _ in range(3):
                start=time.monotonic_ns();pipe.send(("clock",))
                if not pipe.poll(30):raise TimeoutError("clock handshake timed out")
                reply=pipe.recv();end=time.monotonic_ns()
                if reply[0]!="clock":raise RuntimeError("unexpected worker clock reply")
                probes.append(dict(dispatcher_before_ns=start,dispatcher_after_ns=end,worker_ns=reply[1],
                    offset_ns=reply[1]-(start+end)//2,uncertainty_ns=(end-start+1)//2))
            self.clock_records.append(dict(worker_id=i,phase=phase,probes=probes))

    def close(self):
        for pipe in self.pipes:
            try:pipe.send(None)
            except (OSError,EOFError,BrokenPipeError):pass
        for process in self.processes:
            process.join(2)
            if process.is_alive():process.terminate();process.join(2)
        for pipe in self.pipes:pipe.close()

