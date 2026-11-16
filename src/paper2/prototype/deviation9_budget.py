"""Engineering projections only. No parameter here changes scientific rates."""
import json,math
from pathlib import Path
from .replay_budget import timeout_minutes

REFERENCE=117292

def replay_projection(count,models=('explicit',)):
    if isinstance(count,bool) or not isinstance(count,int) or count<1:raise ValueError('exact positive audited N required')
    if not models or len(set(models))!=len(models) or set(models)-{'explicit','legacy'}:raise ValueError('unsupported replay model set')
    old=json.loads(Path(__file__).with_name('replay-budget.json').read_bytes())['components']
    components={k:old[k] for k in ('input_verification_seconds','prototype_postprocessing_seconds')}
    for mode in models:
        # Two slots. The SCALE full checker timing already includes all of its
        # internal invariant families; do not add those nested timers again.
        components[mode+'_simulations']=2*214.5 if mode=='explicit' else old['simulations_seconds']
        components[mode+'_full_checks']=2*521.8 if mode=='explicit' else old['simulation_checks_metrics_seconds']
        # Existing old simulation checks+metrics is retained as a conservative
        # extra metrics/postprocessing proxy for explicit (not a fitted cost).
        if mode=='explicit':components[mode+'_metrics_proxy']=old['simulation_checks_metrics_seconds']
        components[mode+'_comparisons']=old['comparisons_seconds']
    scaled={name:seconds*count/REFERENCE for name,seconds in components.items()}
    seconds=60+sum(scaled.values())
    return dict(transactions=count,models=list(models),seconds=seconds,timeout_minutes=timeout_minutes(seconds),
        reserve_seconds=60,components_seconds=scaled,
        basis='author remote SCALE: explicit simulation 214.5 s/checker 521.8 s at 117292 tx; existing replay-budget.json prototype/input/metrics/comparison proxies; not a runtime measurement')

def stage_volume(rows,calibration_raw_bytes,raw_stage_bytes_per_tx):
    """Conservative no-compression saving for new evidence until ARM Phase F.

    The bytes/tx proxy is measured from a capture receipt, not tuned to fit a
    disk limit. Raw calibration bytes are counted once in canonical control.
    """
    if calibration_raw_bytes<0 or raw_stage_bytes_per_tx<0:raise ValueError('negative stage volume proxy')
    raw=sum(math.ceil(r['transactions']*raw_stage_bytes_per_tx) for r in rows)
    largest=max((math.ceil(r['transactions']*raw_stage_bytes_per_tx) for r in rows),default=0)
    # gzip can expand incompressible input slightly; this is an explicit 1%
    # transport/container reserve, not an assumed measured compression ratio.
    encoded=math.ceil(1.01*(raw+calibration_raw_bytes))
    return dict(stage_raw_bytes=raw,calibration_raw_bytes=calibration_raw_bytes,stage_compressed_projection_bytes=encoded,
        added_peak_bytes=calibration_raw_bytes+encoded+2*largest,
        basis='measured small capture bytes/tx; no compression saving, 1% gzip/container reserve; ARM volume UNVERIFIED')
