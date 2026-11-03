"""Byte-compatible CSV batching and bounded JSON writes on open streams."""

import csv
import io
import json

BUFFER = 8 * 1024 * 1024


class CSVWriter:
    def __init__(self, stream):
        self.stream = stream; self.buffer = io.StringIO(newline="")
        self.writer = csv.writer(self.buffer)

    def writerow(self, row):
        self.writer.writerow(row)
        if self.buffer.tell() >= BUFFER: self.flush()

    def flush(self):
        self.stream.write(self.buffer.getvalue())
        self.buffer.seek(0); self.buffer.truncate(0)


def write_json(path, value, *, exclusive=False):
    # Keep CPython's C encoder. iterencode's Python recursion is much slower for
    # the large, unchanged provenance schema; chunk only the subsequent writes.
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    with path.open("x" if exclusive else "w", encoding="utf-8", newline="", buffering=BUFFER) as stream:
        for start in range(0,len(encoded),BUFFER):stream.write(encoded[start:start+BUFFER])
        stream.write("\n")
