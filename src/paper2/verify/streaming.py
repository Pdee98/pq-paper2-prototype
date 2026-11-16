"""Re-iterable full rows with compact time peeks; explicit-mode only."""
from array import array
from collections.abc import Mapping
import csv
from pathlib import Path


class Peek(Mapping):
    def __init__(self,owner,index):self.owner,self.index=owner,index;self.loaded=None
    def load(self):
        if self.loaded is None:
            with self.owner.path.open('rb') as f:
                f.seek(self.owner.offsets[self.index])
                self.loaded=next(csv.DictReader((line.decode('utf-8') for line in f),fieldnames=self.owner.fields))
        return self.loaded
    def __getitem__(self,key):return self.owner.times[self.index] if key=='t' else self.load()[key]
    def __iter__(self):return iter(self.owner.fields)
    def __len__(self):return len(self.owner.fields)


class CSVRows:
    def __init__(self,path):
        self.path=Path(path);self.offsets=array('Q');self.times=array('d')
        with self.path.open('rb') as f:
            reader=csv.DictReader((line.decode('utf-8') for line in f));self.fields=reader.fieldnames
            while True:
                offset=f.tell()
                try:row=next(reader)
                except StopIteration:break
                self.offsets.append(offset);self.times.append(float(row['t']))
    def __len__(self):return len(self.times)
    def __getitem__(self,index):return Peek(self,index)
    def __iter__(self):
        with self.path.open(encoding='utf-8',newline='') as f:yield from csv.DictReader(f)


class RowStates:
    def __init__(self,k=None):self.k=k;self.values=array('q') if k is None else array('Q');self.fallback={} if k and k>63 else None
    def __setitem__(self,index,value):
        if self.fallback is not None:self.fallback[index]=value;return
        if index!=len(self.values):raise ValueError('row state must be appended sequentially')
        self.values.append((-1 if value is None else value) if self.k is None else
            sum(1<<w for w in value if 0<=w<self.k))
    def get(self,index,default=None):
        if self.fallback is not None:return self.fallback.get(index,default)
        if not 0<=index<len(self.values):return default
        v=self.values[index]
        return (None if v==-1 else v) if self.k is None else frozenset(w for w in range(self.k) if v&(1<<w))
