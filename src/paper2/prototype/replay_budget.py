"""Engineering wall-time projection, independent of scientific validity rules."""
import json
import math
from pathlib import Path


def timeout_minutes(seconds):
    if isinstance(seconds,bool) or not isinstance(seconds,(int,float)) or not math.isfinite(seconds) or seconds<0:
        raise ValueError('invalid replay projection')
    result=max(60,math.ceil(2*seconds/60))
    if result>330:
        raise ValueError('replay projection requires more than the 330-minute job ceiling')
    return result


def matrix_entry(root,run_id):
    from .replay import read,safe_file
    info=read(safe_file(root,run_id)/'info.json')
    budget=json.loads(Path(__file__).with_name('replay-budget.json').read_bytes())
    count=info['arm_corpus_audit']['signature_ids_checked']
    if isinstance(count,bool) or not isinstance(count,int) or count<1:
        raise ValueError('missing positive transaction count for replay projection')
    fixed,coefficient=budget['fixed_seconds'],budget['seconds_per_transaction']
    if any(isinstance(v,bool) or not isinstance(v,(int,float)) or not math.isfinite(v) or v<0 for v in (fixed,coefficient)):
        raise ValueError('invalid measured replay budget')
    seconds=fixed+count*coefficient
    return dict(run_id=run_id,timeout_minutes=timeout_minutes(seconds))
