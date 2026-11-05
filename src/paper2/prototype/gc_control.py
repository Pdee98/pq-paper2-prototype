"""Deviation 7 window-scoped cyclic-GC control and fail-closed RSS sampling.

No scheduler/backend decisions live here. Receipts are persisted at transitions
so a terminated process does not need to reach the normal CSV writer.
"""
import gc
import json
import os
from pathlib import Path
import time

GIB = 1024**3
PROCESS_LIMIT = 12 * GIB
AVAILABLE_MINIMUM = 2 * GIB


class MemoryStop(RuntimeError):
    pass


def memory_snapshot(pids=()):
    """Current RSS, never peak RSS; Linux /proc or Windows native APIs."""
    pids = list(dict.fromkeys([os.getpid(), *pids]))
    if os.name != 'nt':
        values = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, value = line.split(':', 1)
            values[key] = int(value.strip().split()[0]) * 1024
        rss = {str(pid): int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
               for pid in pids}
        return dict(parent_pid=os.getpid(), rss_bytes=rss,
                    available_bytes=values['MemAvailable'], total_bytes=values['MemTotal'])
    import ctypes
    from ctypes import wintypes
    class Status(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('load', wintypes.DWORD)] + [
            (name, ctypes.c_ulonglong) for name in ('total', 'available', 'page_total', 'page_available', 'virtual_total', 'virtual_available', 'extended')]
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ('peak', 'working', 'q1', 'q2', 'q3', 'q4', 'page', 'peakpage')]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    api = ctypes.WinDLL('psapi', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    api.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    status = Status(); status.length = ctypes.sizeof(status)
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)): raise OSError('memory availability unavailable')
    rss = {}
    for pid in pids:
        handle = kernel.OpenProcess(0x1000 | 0x10, False, pid)
        if not handle: raise OSError('process RSS unavailable')
        try:
            counters = Counters(); counters.cb = ctypes.sizeof(counters)
            if not api.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb): raise OSError('process RSS unavailable')
            rss[str(pid)] = counters.working
        finally: kernel.CloseHandle(handle)
    return dict(parent_pid=os.getpid(), rss_bytes=rss, available_bytes=status.available, total_bytes=status.total)


def memory_failures(sample):
    reasons = [f'process {pid} RSS exceeds 12 GiB' for pid, value in sample['rss_bytes'].items() if value > PROCESS_LIMIT]
    if sample['available_bytes'] < AVAILABLE_MINIMUM: reasons.append('host available memory below 2 GiB')
    return reasons


class WindowGC:
    def __init__(self, directory, monitor=None):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.monitor = monitor
        self.initial_enabled = gc.isenabled(); self.initial_frozen = gc.get_freeze_count()
        self.rows = []; self.active = False; self.finished = False
        self.record('created')

    def record(self, phase, **extra):
        self.rows.append(dict(monotonic_ns=time.monotonic_ns(), phase=phase, pid=os.getpid(),
                             enabled=gc.isenabled(), frozen_count=gc.get_freeze_count(), **extra))
        # Tiny receipt; explicit flush is required even on a memory stop.
        with (self.directory/'gc_state.json').open('w', encoding='utf-8') as stream:
            json.dump(dict(schema='paper2-gc-control-v7', transitions=self.rows), stream)
            stream.write('\n'); stream.flush()

    def enter(self):
        if self.active or self.finished: raise RuntimeError('GC window entered twice')
        # Pause observation starts AFTER the explicit preparation collection.
        if self.monitor and self.monitor.registered:
            gc.callbacks.remove(self.monitor._callback); self.monitor.registered = False
        collected = gc.collect(); self.record('preparation_collect', collected=collected)
        gc.freeze(); self.record('frozen')
        gc.disable(); self.active = True; self.record('loop_entry')
        if self.monitor: self.monitor.register()

    def leave(self, *, partial=False):
        if self.finished: return
        if self.active:
            self.record('drain_end', partial=partial)
            collected = gc.collect(); self.record('post_drain_collect', collected=collected, partial=partial)
            if self.monitor and self.monitor.registered:
                gc.callbacks.remove(self.monitor._callback); self.monitor.registered = False
            # Freeze itself has no effect on reference counting. Keep the entry
            # frozen set intact; a fresh process is used for every real window.
            if not self.initial_frozen: gc.unfreeze()
            if self.initial_enabled: gc.enable()
            else: gc.disable()
            self.active = False
            self.record('restored', partial=partial)
        self.finished = True


class MemorySampler:
    def __init__(self, progress, directory, pids=()):
        self.progress, self.directory, self.pids = progress, Path(directory), pids
        self.next_ns = 0

    def sample(self, force=False):
        now = time.monotonic_ns()
        if not force and now < self.next_ns: return
        self.next_ns = now + 1_000_000_000
        try:
            sample = memory_snapshot(self.pids)
            reasons = memory_failures(sample)
        except OSError as exc:
            sample = {}; reasons = ['memory telemetry unavailable: '+str(exc)]
        if self.progress: self.progress.phase('memory', **sample, invalid=bool(reasons))
        if reasons:
            self.directory.mkdir(parents=True,exist_ok=True)
            value = dict(status='INVALID', reasons=reasons, monotonic_ns=now, **sample)
            with (self.directory/'memory-stop.json').open('w', encoding='utf-8') as stream:
                json.dump(value, stream); stream.write('\n'); stream.flush()
            if self.progress: self.progress.phase('memory_stop', status='INVALID', reasons=reasons, **sample)
            raise MemoryStop('; '.join(reasons))
