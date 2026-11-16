"""Phase F preparation only: disk probe and disjoint rehearsal namespace."""
from tests.paper2._provenance import setUpModule, tearDownModule
from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def cleanup(raw):
    lines = raw.splitlines()
    first = next(i for i, line in enumerate(lines) if 'p.write_text(json.dumps({"before_bytes"' in line)
    return '\n'.join(line.removeprefix('          ') for line in lines[first:first+4]) + '\n'


class PhaseFPreparation(unittest.TestCase):
    def test_disk_probe_manual_same_cleanup_receipt_only(self):
        base = ROOT / 'src/paper2/prototype'
        probe = (base / 'paper2-arm-disk-probe.yml').read_text()
        rehearsal = (base / 'paper2-g3-rehearsal.yml').read_text()
        self.assertEqual(hashlib.sha256(cleanup(probe).encode()).hexdigest(),
                         hashlib.sha256(cleanup(rehearsal).encode()).hexdigest())
        self.assertEqual(re.findall(r'^on:\n(.*?)(?=^\S)', probe, re.M | re.S),
                         ['  workflow_dispatch:\n'])
        self.assertEqual(re.findall(r'^  ([\w-]+):$', probe.split('\njobs:\n')[1], re.M), ['disk-probe'])
        self.assertIn('runs-on: ubuntu-24.04-arm', probe)
        self.assertIn('runs-on: ubuntu-24.04-arm', rehearsal)
        self.assertIn('timeout-minutes: 20', probe)
        for key in ('before', 'after'):
            self.assertIn('df-' + key + '.txt', probe)
        self.assertEqual(probe.count('df -B1 --output=source,size,used,avail,target "$GITHUB_WORKSPACE" "$RUNNER_TEMP"'), 2)
        for key in ('MemTotal', 'MemAvailable', 'nproc', 'ImageOS', 'ImageVersion', 'SHA256SUMS'):
            self.assertIn(key, probe)
        actions = re.findall(r'uses: (\S+)', probe)
        self.assertEqual(len(actions), 1)
        self.assertRegex(actions[0], r'^actions/upload-artifact@[0-9a-f]{40}$')
        self.assertEqual(re.findall(r'^          path: (.+)$', probe, re.M),
                         ['${{ runner.temp }}/paper2-arm-disk-probe-receipts/'])
        for forbidden in ('pip install', 'checkout@', 'setup-python@', '-m src.', 'prototype run', 'calibration run'):
            self.assertNotIn(forbidden, probe)
        exporter = (base / 'export.py').read_text()
        self.assertIn('paper2-arm-disk-probe.yml', exporter)
        validation = (base / 'paper2-g3.yml').read_text()
        self.assertIn('Run #7 blocked:', validation)

    def test_rehearsal_v2_named_seeds_disjoint_from_validation(self):
        from src.paper2.model.service_times import derive_seed, STREAM_NAMES
        from src.paper2.prototype.production import corpus_group
        ids = ['paper2-g3-rehearsal-v2']
        ids += ['paper2-g3-rehearsal-v2-' + corpus_group(dict(backend=b, k=k, rho=.85), 0)
                for b, k in (('xmss', 2), ('ml_dsa_44', 1))]
        new = {derive_seed(identity, stream, 0) for identity in ids for stream in STREAM_NAMES}
        old = {derive_seed('paper2-g3-v1', stream, rep)
               for stream in STREAM_NAMES for rep in range(4)}
        self.assertEqual(len(new), len(ids)*len(STREAM_NAMES))
        self.assertTrue(new.isdisjoint(old))


if __name__ == '__main__':
    unittest.main()
