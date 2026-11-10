"""Flushed replay phase evidence; never used for a model or validity decision."""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from inspect import signature
import json
from pathlib import Path
import signal
import threading
import time
from ..model.service_times import ROOT
from ..verify.observer import OBSERVER

CURRENT = ContextVar('paper2_replay_progress', default=None)


def host_receipt():
    import os, platform
    cpu = platform.processor()
    try:
        lines = Path("/proc/cpuinfo").read_text().splitlines()
        cpu = next((line.split(":",1)[1].strip() for line in lines if line.lower().startswith("model name")), cpu)
    except OSError: pass
    return dict(runner_label=os.environ.get("PAPER2_RUNNER_LABEL", "NOT RECORDED"),
                os_image=os.environ.get("ImageOS", platform.platform()),
                os_image_version=os.environ.get("ImageVersion", "NOT RECORDED"),
                cpu_model=cpu or "NOT RECORDED")


def checkout_receipt():
    from ..model.engine import _git_state
    state = _git_state()
    exported = state.get('exported', False)
    return dict(replay_code_commit=None if exported else state['commit'],
                replay_tree_clean=None if exported else not state['dirty'],
                checkout_kind='export without Git checkout' if exported else 'git checkout',
                export_source_commit=state['commit'] if exported else None, host=host_receipt())


def record_source_commit(commit):
    current = CURRENT.get()
    if current is not None: current.source_commit = commit


def result_provenance(directory):
    current = CURRENT.get()
    if current is not None:
        return dict(source_code_commit=current.source_commit, **current.checkout)
    previous = Path(directory)/'RESULT_MANIFEST.json'
    if previous.is_file():
        value = json.loads(previous.read_bytes()).get('provenance')
        if value is not None: return value
    result = Path(directory)/'result.json'
    source = json.loads(result.read_bytes()).get('code_commit') if result.is_file() else None
    return dict(source_code_commit=source, **checkout_receipt())


class ReplayProgress:
    def __init__(self, output, interval=30):
        self.output = Path(output).resolve()
        self.checkout = checkout_receipt(); self.source_commit = None
        self.stream = (self.output/'replay-progress.jsonl').open('x', encoding='utf-8', buffering=8192)
        self.lock = threading.RLock(); self.stop = threading.Event(); self.stack = []; self.counts = {}; self.closed = False
        self.interval = interval
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)
        self.thread.start()
    def write(self, event, phase, **extra):
        with self.lock:
            if self.closed: return
            row = dict(monotonic_ns=time.monotonic_ns(), utc=datetime.now(timezone.utc).isoformat(),
                       event=event, phase=phase, counts=dict(self.counts), **extra)
            raw = json.dumps(row, separators=(',', ':'))
            self.stream.write(raw+'\n'); self.stream.flush(); print(raw, flush=True)
    def observe(self, stage, **counts):
        with self.lock:
            self.counts.update(counts); self.counts['observed_stage'] = stage
    def begin(self, name, **counts):
        with self.lock:
            self.stack.append((name, time.monotonic_ns())); self.counts = dict(counts)
            self.write('phase_start', name)
    def end(self, name, **counts):
        with self.lock:
            self.counts.update(counts)
            if not self.stack or self.stack[-1][0] != name: raise RuntimeError('replay phase stack mismatch')
            _, started = self.stack.pop()
            self.write('phase_end', name, elapsed_ns=time.monotonic_ns()-started)
    @contextmanager
    def phase(self, name):
        self.begin(name)
        try: yield
        except BaseException as exc:
            self.write('phase_error', name, error_type=type(exc).__name__)
            raise
        finally: self.end(name)
    def _heartbeat(self):
        while not self.stop.wait(self.interval):
            with self.lock:
                self.write('heartbeat', self.stack[-1][0] if self.stack else 'replay')
    def close(self, status):
        self.stop.set(); self.thread.join(timeout=1)
        with self.lock:
            # An interrupted inline phase remains explicitly incomplete.
            for name, started in reversed(self.stack):
                self.write('phase_end', name, elapsed_ns=time.monotonic_ns()-started, incomplete=True)
            self.stack.clear(); self.write('run_end', 'replay', status=status)
            self.closed = True; self.stream.close()

def owns_output(path):
    current = CURRENT.get()
    return current is not None and current.output == Path(path).resolve()

def begin(name, **counts):
    current = CURRENT.get()
    if current is not None and not current.closed: current.begin(name, **counts)

def end(name, **counts):
    current = CURRENT.get()
    if current is not None and not current.closed: current.end(name, **counts)

def stage(name, function, *args, **kwargs):
    current = CURRENT.get()
    if current is None or current.closed: return function(*args, **kwargs)
    with current.phase(name): return function(*args, **kwargs)

def tracked_run(function):
    @wraps(function)
    def run(*args, **kwargs):
        bound = signature(function).bind(*args, **kwargs)
        output = Path(bound.arguments['output']).resolve()
        if output == ROOT or ROOT in output.parents: raise ValueError('replay outputs must be outside checkout')
        if output.exists(): raise FileExistsError('replay outputs must be new')
        output.mkdir(parents=True)
        progress = ReplayProgress(output); token = CURRENT.set(progress); observer = OBSERVER.set(progress.observe)
        status = 'interrupted'; previous_handler = None
        if threading.current_thread() is threading.main_thread():
            previous_handler = signal.getsignal(signal.SIGTERM)
            def terminated(signum, frame): raise TimeoutError('replay process watchdog terminated the run')
            signal.signal(signal.SIGTERM, terminated)
        try:
            progress.begin('replay')
            value = function(*args, **kwargs)
            progress.end('replay'); status = 'returned'
            return value
        except BaseException as exc:
            progress.write('run_error', 'replay', error_type=type(exc).__name__)
            raise
        finally:
            if previous_handler is not None: signal.signal(signal.SIGTERM, previous_handler)
            progress.close(status)
            try:
                # Seal closed progress and its actual replay-checkout receipt together.
                from .replay import seal
                seal(output, 'RESULT_MANIFEST.json')
            finally:
                OBSERVER.reset(observer); CURRENT.reset(token)
    return run
