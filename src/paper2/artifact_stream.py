"""Disk-backed append/update sequences and incremental JSON arrays.

Only temporary evidence storage, never scheduling or checker decisions.
"""
from collections.abc import Sequence
import json
from pathlib import Path
import sqlite3


class Spool(Sequence):
    def __init__(self, path, by_id=False):
        self.path=Path(path);self.db=sqlite3.connect(str(self.path));self.by_id=by_id;self.n=0
        self.db.execute('PRAGMA journal_mode=OFF');self.db.execute('PRAGMA synchronous=OFF')
        self.db.execute('PRAGMA cache_size=-1024')
        self.db.execute('CREATE TABLE rows (seq INTEGER PRIMARY KEY, identity INTEGER UNIQUE, value TEXT)')

    def append(self,row):
        self.db.execute('INSERT INTO rows VALUES (?,?,?)',(self.n,row['id'] if self.by_id else self.n,
            json.dumps(row,separators=(',',':'),allow_nan=False)));self.n+=1

    def sync(self,row):
        self.db.execute('UPDATE rows SET value=? WHERE identity=?',
                        (json.dumps(row,separators=(',',':'),allow_nan=False),row['id']))

    def __len__(self):return self.n

    def __iter__(self):
        for (raw,) in self.db.execute('SELECT value FROM rows ORDER BY seq'):yield json.loads(raw)

    def __getitem__(self,index):
        if index<0:index+=self.n
        row=self.db.execute('SELECT value FROM rows WHERE seq=?',(index,)).fetchone()
        if row is None:raise IndexError(index)
        return json.loads(row[0])

    def close(self):
        self.db.close();self.path.unlink(missing_ok=True)


def write_arrays(path,schema,arrays):
    with Path(path).open('wb',buffering=8*1024*1024) as f:
        f.write(b'{"schema":'+json.dumps(schema).encode())
        for name,rows in arrays.items():
            f.write(b','+json.dumps(name).encode()+b':[')
            for i,row in enumerate(rows):
                if i:f.write(b',')
                f.write(json.dumps(row,separators=(',',':'),allow_nan=False).encode())
            f.write(b']')
        f.write(b'}\n')


class Reader:
    def __init__(self,f):self.f=f;self.buffer='';self.position=0;self.decoder=json.JSONDecoder();self.eof=False

    def fill(self):
        self.buffer=self.buffer[self.position:]+self.f.read(65536);self.position=0
        if not self.buffer:self.eof=True

    def peek(self):
        while True:
            while self.position<len(self.buffer) and self.buffer[self.position].isspace():self.position+=1
            if self.position<len(self.buffer):return self.buffer[self.position]
            if self.eof:raise ValueError('unexpected JSON end')
            previous=len(self.buffer);self.fill()
            if not self.buffer and not previous:raise ValueError('unexpected JSON end')

    def take(self,char):
        if self.peek()!=char:raise ValueError('unexpected JSON token')
        self.position+=1

    def value(self):
        self.peek()
        while True:
            try:value,end=self.decoder.raw_decode(self.buffer,self.position)
            except json.JSONDecodeError:
                remainder=self.buffer[self.position:];chunk=self.f.read(65536)
                if not chunk:raise ValueError('incomplete JSON value')
                if len(remainder)>16*1024*1024:raise ValueError('dispatcher item exceeds streaming buffer')
                self.buffer=remainder+chunk;self.position=0
            else:self.position=end;return value


def read_arrays(path,directory):
    """No raw full-file string or in-memory transitions array is constructed."""
    result={}
    try:return _read_arrays(path,directory,result)
    except BaseException:
        for value in result.values():
            if isinstance(value,Spool):value.close()
        raise


def _read_arrays(path,directory,result):
    with Path(path).open(encoding='utf-8') as f:
        r=Reader(f);r.take('{')
        while r.peek()!='}':
            name=r.value();r.take(':')
            if name in result:raise ValueError('duplicate dispatcher field')
            if r.peek()=='[':
                r.take('[');rows=Spool(Path(directory)/(str(len(result))+'.sqlite'));result[name]=rows
                while r.peek()!=']':
                    rows.append(r.value())
                    if r.peek()==']':break
                    r.take(',')
                r.take(']')
            else:result[name]=r.value()
            if r.peek()=='}':break
            r.take(',')
        r.take('}')
        if (r.buffer[r.position:]+f.read()).strip():raise ValueError('trailing dispatcher JSON')
    return result
