"""Deviation 6 capacity arithmetic; no calibration or runner side effects.

Per-k means already contain contention at k. Measured throughput scaling is
reported for continuity and must not multiply these means' worker capacity.
"""

import math


CLASSES=("admission","block_tx","block_sig")
RHO_COLD=(.5,.85)
PROTOTYPE_OPTIONS=('g3_input_version','calibration_cycle_means','diagnostic_instrumentation')


def model_config(config):
    """Keep prototype-only provenance outside the unchanged simulator API."""
    return {k:v for k,v in config.items() if k not in PROTOTYPE_OPTIONS}


def cold_cycle_reference(k,means,dispatcher_per_tx,scaling=None):
    """Rates are transactions/s; means and dispatcher time are seconds.

    A zero dispatcher time denotes an unbounded dispatcher reference, matching
    the previous calibration arithmetic. Production calibration supplies its
    measured nonnegative value; this is not a saturation workaround.
    """
    if isinstance(k,bool) or not isinstance(k,int) or k<1:
        raise ValueError("positive integer worker count required")
    if set(means)!=set(CLASSES) or any(isinstance(v,bool) or not math.isfinite(v) or v<=0 for v in means.values()):
        raise ValueError("positive finite per-class cycle means required")
    if isinstance(dispatcher_per_tx,bool) or not math.isfinite(dispatcher_per_tx) or dispatcher_per_tx<0:
        raise ValueError("nonnegative finite dispatcher time required")
    if scaling is not None and (isinstance(scaling,bool) or not math.isfinite(scaling) or scaling<=0):
        raise ValueError("positive finite reported scaling required")
    dispatcher_capacity=1/dispatcher_per_tx if dispatcher_per_tx else math.inf
    cold=k/(means["admission"]+means["block_tx"]+means["block_sig"]/128)
    warm=k/(means["admission"]+means["block_sig"]/128)
    return dict(k=k,cycle_means=dict(means),d_dispatch=dispatcher_per_tx,s_k=scaling,
        B_cold_cycle=min(cold,dispatcher_capacity),B_ref_cycle=min(warm,dispatcher_capacity),
        worker_cold_capacity=cold,worker_reference_capacity=warm,
        service_quantity="per-worker cycle",capacity_numerator="k, not s_k")


def cold_cycle_loads(reference):
    """Preserve planned rho values; flag exclusions without reducing rates."""
    rows=[]
    for rho in RHO_COLD:
        rate=rho*reference["B_cold_cycle"]
        utilisation=rate*reference["d_dispatch"]
        rows.append(dict(rho_cold=rho,rate=rate,period=128/rate,
            dispatcher_utilisation=utilisation,dispatcher_guard_passed=utilisation<=.5))
    return rows


def cycle_cells(calibrations):
    rows=[]
    for backend,by_k in calibrations.items():
        for k in (1,2):
            ref=by_k[k]
            for policy in ('fifo','block_priority'):
                for load in cold_cycle_loads(ref):
                    rows.append(dict(ref,backend=backend,policy=policy,rho=load['rho_cold'],**load,
                        B_cold=ref['B_cold_cycle'],B_ref=ref['B_ref_cycle'],g3_input_version=6))
    return rows


def regime_category(prototype_hit,simulation_hit):
    if prototype_hit is None or simulation_hit is None:return 'NOT RECORDED'
    if prototype_hit<.5 and simulation_hit<.5:return 'AGREE-COLLAPSE'
    if prototype_hit>=.9 and simulation_hit>=.9:return 'AGREE-STABLE'
    return 'DISAGREE'


def corpus_group(cell,replicate):
    # A policy is deliberately absent: policies use common random numbers.
    return f"{cell['backend']}-k{cell['k']}-rho{cell.get('rho_cold',cell.get('rho'))}-r{replicate}"


def volume_projection(planned,sizes,secondary=True):
    groups={}
    for c in planned:
        if c['dispatcher_utilisation']>.5:continue
        for rep in range(3):
            key=corpus_group(c,rep)
            groups.setdefault(key,dict(backend=c['backend'],rate=c['rate'],replicate=rep))
    if secondary:groups['secondary-regime']=dict(backend='xmss',rate=1115.433019832252,replicate=0)
    totals=dict(compressed_bytes=0.,uncompressed_bytes=0.)
    for row in groups.values():
        for field in totals:totals[field]+=90*row['rate']*1.10*sizes[row['backend']][field+'_per_tx']
    return dict(groups=groups,**totals,limit_bytes=2_000_000_000,margin=1.10,
        passed=all(n<=2_000_000_000 for n in totals.values()))
