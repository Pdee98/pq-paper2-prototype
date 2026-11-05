"""Pre-registered, deterministic fresh-process calibration replay slots."""
import csv
import json
from pathlib import Path
from src.paper2.model.service_times import sha256_file


def split_samples(paths, prefix):
    if len(paths)!=3: raise ValueError('three calibration repetitions required')
    all_rows=[];header=None
    for rep,path in enumerate(paths):
        with Path(path).open(newline='') as stream:
            reader=csv.DictReader(stream)
            if header is None:header=reader.fieldnames
            if header!=reader.fieldnames:raise ValueError('calibration slot schema mismatch')
            rows=list(reader)
        if not rows or any(not r['source'].endswith('-rep'+str(rep)) for r in rows):
            raise ValueError('calibration repetition/slot mismatch')
        all_rows.append(rows)
    slots={}
    for slot,ids in (('primary',(0,1)),('held_out',(2,))):
        target=Path(str(prefix)+'-'+slot+'.csv')
        with target.open('x',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=header);writer.writeheader()
            for rep in ids:writer.writerows(all_rows[rep])
        slots[slot+'_cycle_samples']=str(target)
    receipt=dict(primary_repetitions=[0,1],held_out_repetitions=[2],rate_stationarity_repetitions=[0,1,2],
                 files={k:dict(path=v,sha256=sha256_file(Path(v))) for k,v in slots.items()})
    Path(str(prefix)+'-SPLIT.json').write_bytes(json.dumps(receipt,indent=2).encode()+b'\n')
    return slots


def verify_slots(primary, held_out):
    for path,expected in ((primary,{0,1}),(held_out,{2})):
        with Path(path).open(newline='') as stream:rows=list(csv.DictReader(stream))
        observed={int(row['source'].rsplit('-rep',1)[1]) for row in rows}
        if observed!=expected:raise ValueError('calibration comparison slots overlap or have wrong repetitions')
