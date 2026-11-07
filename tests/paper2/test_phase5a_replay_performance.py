"""Output identity and observational replay progress, without timing assertions."""
from tests.paper2._provenance import setUpModule, tearDownModule
import contextlib
import io
import json
import math
from pathlib import Path
import random
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from src.paper2.verify import prototype
from src.paper2.verify.invariants import check
from src.paper2.verify.reference_invariants import check_reference
from src.paper2.model.engine import run_model
from src.paper2.prototype.replay_progress import ReplayProgress, tracked_run, stage
from src.paper2.prototype import replay
from tests.paper2._support import config


class ReplayPerformance(unittest.TestCase):
    def test_process_timeout_leaves_readable_partial_progress(self):
        with tempfile.TemporaryDirectory() as td:
            output=Path(td)/'partial'
            script="from pathlib import Path\nimport sys,time\nfrom src.paper2.prototype.replay_progress import tracked_run,stage\n@tracked_run\ndef run(output):\n stage('long checker',time.sleep,30)\nrun(Path(sys.argv[1]))\n"
            process=subprocess.Popen([sys.executable,'-B','-c',script,str(output)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                deadline=time.monotonic()+15
                path=output/'replay-progress.jsonl'
                while time.monotonic()<deadline:
                    if path.is_file() and 'long checker' in path.read_text():break
                    if process.poll() is not None:self.fail('progress subprocess exited before timeout')
                    time.sleep(.05)
                self.assertTrue(path.is_file())
                self.assertIn('long checker',path.read_text())
                process.terminate();process.wait(timeout=10)
                rows=[json.loads(s) for s in path.read_text().splitlines()]
                self.assertTrue(any(r['event']=='phase_start' and r['phase']=='long checker' for r in rows))
            finally:
                if process.poll() is None:process.kill();process.wait()

    def test_timeout_projection_rounds_up_and_refuses_ceiling_overflow(self):
        from src.paper2.prototype.replay_budget import timeout_minutes
        self.assertEqual(timeout_minutes(1),60)
        self.assertEqual(timeout_minutes(1800.1),61)
        self.assertEqual(timeout_minutes(9900),330)
        for value in (9900.01,-1,float('inf'),float('nan'),True):
            with self.assertRaises(ValueError):timeout_minutes(value)

    def test_matrix_projection_uses_exact_packet_count(self):
        from src.paper2.prototype import replay_budget
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=root/'case';packet.mkdir()
            replay.save(packet/'info.json',dict(arm_corpus_audit=dict(signature_ids_checked=1000)))
            with patch.object(replay_budget,'Path') as path:
                path.return_value.with_name.return_value.read_bytes.return_value=b'{"fixed_seconds":60,"seconds_per_transaction":2}'
                self.assertEqual(replay_budget.matrix_entry(root,'case'),dict(run_id='case',timeout_minutes=69))
                replay.save(packet/'info.json',dict(arm_corpus_audit=dict(signature_ids_checked=10000)))
                with self.assertRaisesRegex(ValueError,'330-minute'):replay_budget.matrix_entry(root,'case')

    def test_indexed_queries_preserve_reference_arithmetic(self):
        rng = random.Random(72)
        cases = [[], [(0., 1.), (1., 2.)], [(0., 2.), (1., 1.5)],
                 [(1., 2.), (0., 1.)], [(0., float('inf'))]]
        t = 0.; spans = []
        for _ in range(100):
            a = t + rng.random(); t = a + rng.random(); spans.append((a, t))
        cases.append(spans)
        for intervals in cases:
            indexed = prototype.IndexedIntervals(intervals)
            queries = [(-1., 0.), (0., 0.), (1., 1.+1e-13), (1.-1e-13, 2.), (3., 2.)]
            queries += [tuple(sorted((rng.uniform(-1, t+1), rng.uniform(-1, t+1)))) for _ in range(200)]
            for a, b in queries:
                self.assertEqual(prototype.covered(indexed,a,b),prototype.covered_reference(intervals,a,b))
                self.assertEqual(prototype.overlap(indexed,a,b),prototype.overlap_reference(intervals,a,b))

    def test_reference_checker_k1_k2_and_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            for k in (1,2):
                cfg=config(k=k, admissions=[dict(tx_id='a',arrival_t=0),dict(tx_id='b',arrival_t=0)],
                    blocks=[dict(block_id='B',tx_ids=['a','b'])],block_start=.1,
                    output_dir=str(Path(td)/str(k)))
                events,manifest=run_model(cfg);jobs=events.parent/'jobs.csv'
                self.assertEqual(check(events,jobs,manifest),check_reference(events,jobs,manifest))
                doc=json.loads(manifest.read_bytes());doc['blocks']['B']['deadline_t']+=1
                manifest.write_text(json.dumps(doc))
                self.assertEqual(check(events,jobs,manifest),check_reference(events,jobs,manifest))
                self.assertTrue(check(events,jobs,manifest))

    def test_real_prototype_reference_checker_k1_k2(self):
        from src.paper2.prototype import corpus,runtime
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for k in (1,2):
                cfg=config(k=k, admissions=[dict(tx_id='a',arrival_t=0),dict(tx_id='b',arrival_t=.001)],
                    blocks=[dict(block_id='B',tx_ids=['a','b'])],block_start=.04,
                    cache=dict(capacity=32),pool=dict(enabled=True,capacity_bytes=100000))
                doc=corpus.build(cfg,'sleep');cp=corpus.write(doc,root/('corpus'+str(k)+'.json'))
                cfg=dict(doc['workload'],output_dir=str(root/('prototype'+str(k))))
                events,manifest=runtime.run(cfg,cp,sleep_seconds=.001)
                self.assertEqual(check(events,events.parent/'jobs.csv',manifest),check_reference(events,events.parent/'jobs.csv',manifest))
                self.assertEqual(check(events,events.parent/'jobs.csv',manifest),[])

    def test_progress_flush_heartbeat_and_timeout_preserves_seal(self):
        with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()):
            output=Path(td)/'evidence';output.mkdir()
            progress=ReplayProgress(output, interval=.01)
            progress.begin('checker',events=10);progress.observe('rows',events=5)
            deadline=time.monotonic()+3
            rows=[]
            while time.monotonic()<deadline:
                rows=[json.loads(s) for s in (output/'replay-progress.jsonl').read_text().splitlines()]
                if any(r['event']=='heartbeat' for r in rows):break
                time.sleep(.02)
            self.assertTrue(any(r['event']=='heartbeat' and r['counts']['events']==5 for r in rows))
            progress.end('checker');progress.close('returned')
            @tracked_run
            def interrupted(output):
                def stop():raise TimeoutError('synthetic watchdog')
                stage('invariant checker',stop)
            partial=Path(td)/'partial'
            with self.assertRaisesRegex(TimeoutError,'synthetic watchdog'):interrupted(partial)
            replay.verify_files(partial,'RESULT_MANIFEST.json')
            rows=[json.loads(s) for s in (partial/'replay-progress.jsonl').read_text().splitlines()]
            self.assertTrue(any(r['event']=='phase_error' and r['phase']=='invariant checker' for r in rows))
            self.assertEqual(rows[-1]['status'],'interrupted')
