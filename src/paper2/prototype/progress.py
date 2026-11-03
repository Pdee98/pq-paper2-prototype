"""Small flushed phase receipts; no transaction payloads or signing state."""

import json
from pathlib import Path
import os
import time


def peak_rss():
    if os.name != "nt":
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    import ctypes
    from ctypes import wintypes
    class Memory(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (k, ctypes.c_size_t) for k in ("peak", "working", "q1", "q2", "q3", "q4", "page", "peakpage")]
    m = Memory(); m.cb = ctypes.sizeof(m)
    kernel = ctypes.WinDLL("kernel32"); api = ctypes.WinDLL("psapi")
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    api.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Memory), wintypes.DWORD]
    if not api.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(m), m.cb):
        raise OSError("cannot inspect peak RSS")
    return m.peak


class Progress:
    def __init__(self, directory):
        from src.paper2.model.service_times import ROOT
        directory = Path(directory).resolve()
        if directory == ROOT or ROOT in directory.parents:
            raise ValueError("progress outputs must be outside checkout")
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / "progress.jsonl"
        self.stream = self.path.open("x", encoding="utf-8", buffering=8192)
        self.second = 0; self.counts = self.fresh(); self.queues = (0, 0)
        self.phase("process_start", pid=os.getpid())

    @staticmethod
    def fresh():
        return dict(admitted=0, started=0, completed=0, block_tx_hit=0, block_tx_miss=0)

    def phase(self, name, **counts):
        row = dict(monotonic_ns=time.monotonic_ns(), phase=name, **counts)
        self.stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.stream.flush()

    def advance(self, t):
        while self.second < int(t):
            self.phase("second", second=self.second, **self.counts,
                       q_admission=self.queues[0], q_block=self.queues[1])
            self.second += 1; self.counts = self.fresh()

    def event(self, t, event, cls, queues):
        self.advance(t)
        if event == "start": self.counts["started"] += 1
        if event == "end": self.counts["completed"] += 1
        if cls == "block_tx" and event in ("cache_hit", "cache_miss"):
            self.counts["block_tx_" + event.removeprefix("cache_")] += 1
        self.queues = queues

    def close(self):
        self.stream.close()


def read_progress(path):
    rows = []
    if Path(path).is_file():
        for line in Path(path).read_text().splitlines():
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: break  # timeout during a final write
    return rows


def phase_times(rows):
    stamps = {r["phase"]: r["monotonic_ns"] for r in rows if r["phase"] != "second"}
    return {name: (stamps[b] - stamps[a]) / 1e9 for name, a, b in (
        ("preparation", "process_start", "prototype_window_start"),
        ("prototype window", "prototype_window_start", "serialisation_start"),
        ("serialisation", "serialisation_start", "serialisation_end")) if a in stamps and b in stamps}
