"""Engineering disk/upload projections; measured v5 size proxies are explicit."""
import json
import math
from pathlib import Path


def project(rows, groups, backends):
    basis=json.loads(Path(__file__).with_name('transport-budget.json').read_bytes())
    total=0; largest=0; compact_compressed=0;compact_raw=0
    for r in rows:
        p=basis['backends'][r['cell']['backend']]
        # No assumed saving from JSON factoring: projection uses v5 ZIP sizes
        # with a 25% gzip/container margin until the rehearsal measures transport.
        n=r['transactions'];encoded=math.ceil(n*p['packet_compressed_per_tx']*1.25)
        total+=encoded;largest=max(largest,math.ceil(n*p['packet_raw_per_tx']))
    full_group=0
    for g in groups.values():
        p=basis['backends'][g['cell']['backend']];n=g['transactions']
        full_group=max(full_group,math.ceil(n*p['full_corpus_per_tx']))
        compact_compressed+=n*p['compact_compressed_per_tx']
        compact_raw+=n*p['compact_raw_per_tx']
    if max(compact_compressed,compact_raw)*1.1>2_000_000_000:
        raise RuntimeError('projected compact corpus exceeds an unchanged 2 GB limit')
    # Native/build/calibration reserve, retained canonical compressed downloads,
    # one full signing group, raw measurement+packet, and concurrent upload+download.
    reserve=basis['native_calibration_reserve_bytes']
    peak=math.ceil(reserve+total+full_group+2*largest+2*max(
        (r['transactions']*basis['backends'][r['cell']['backend']]['packet_compressed_per_tx']*1.25 for r in rows),default=0))
    peak=max(peak,math.ceil(total+3*reserve))
    return dict(compressed_upload_bytes=total+reserve,packet_compressed_bytes=total,
                control_compressed_reserve_bytes=reserve,peak_runner_bytes=peak,
                disk_threshold_bytes=math.ceil(1.5*peak),compact_compressed_bytes=math.ceil(compact_compressed*1.1),
                compact_raw_bytes=math.ceil(compact_raw*1.1),
                basis='v5 packet sizes; no assumed factoring/dedup savings; gzip margin 25%; native/calibration reserve 3 GiB UNVERIFIED')
