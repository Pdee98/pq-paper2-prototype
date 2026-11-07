"""Repeat v4 with fresh diagnostic seeds and complete visible artifacts."""
from . import cycle_diagnostic_v4 as v4
from .replay_budget import timeout_minutes
import json
from pathlib import Path

RUN_ID = 'paper2-g3-diag-v5'
BACKENDS, CASES, TIMEOUTS = v4.BACKENDS, v4.CASES, v4.TIMEOUTS
# INSPECTED: v4 run 42106564199 protocol.json; planning inputs only.
PLANNING = [{'backend': 'xmss', 'k': 1, 'rate': 672.2213181480912, 'messages': 61082, 'presigning_seconds': 176.55211468300013}, {'backend': 'xmss', 'k': 2, 'rate': 1298.7938993189457, 'messages': 117675, 'presigning_seconds': 335.262510774}, {'backend': 'ml_dsa_44', 'k': 1, 'rate': 1169.5335930652743, 'messages': 105982, 'presigning_seconds': 71.84968738599991}]


def parameters(rate, period, horizon=90):
    return v4.parameters(rate, period, horizon, run_id=RUN_ID)


def projection():
    budget = json.loads(Path(__file__).with_name('replay-budget.json').read_bytes())
    runs = []
    for old in PLANNING:
        nt, nb = v4.message_counts(parameters(old['rate'],128/old['rate']))
        sign = old['presigning_seconds'] * (nt+nb)/old['messages'] * 1.25
        seconds = budget['fixed_seconds']+nt*budget['seconds_per_transaction']
        runs.append(dict(backend=old['backend'],k=old['k'],provisional_rate=old['rate'],
            transactions=nt,messages=nt+nb,presigning_seconds=sign,preparation_reserve_seconds=30,
            prototype_window_seconds=110,serialisation_reserve_seconds=60,
            replay_projected_seconds=seconds,replay_timeout_minutes=timeout_minutes(seconds)))
    calibration = 1513.410665602 * 1.25
    reserves = dict(native_build=165.189647*1.25,conformance=300,pilots=60,self_tests=60,packet_hash_upload=300)
    return dict(purpose='DIAGNOSTIC v5; excluded from G3',run_id=RUN_ID,runs=runs,
        calibration_planning_seconds=calibration,planning_reserves_seconds=reserves,
        projected_seconds=sum(reserves.values())+calibration+sum(r['presigning_seconds']+200 for r in runs),
        stage_timeouts_seconds=TIMEOUTS,command_watchdog_minutes=165,job_timeout_minutes=180,
        basis='v4 protocol.json rates, calibration seconds and signing seconds/message with 25% planning margin; '
              'fresh v5 generator message counts; native and other reserves retained from v4 planning; '
              'replay-budget.json measured coefficient, unchanged allocation formula',
        caveat='Planning only. Fresh v5 calibration determines actual rates and guard skips. '
               'Replay jobs use exact packet transaction counts. No protocol or validation caps changed.')


def collect(root):
    return v4.collect(root,run_id=RUN_ID,planning_projection=projection())
