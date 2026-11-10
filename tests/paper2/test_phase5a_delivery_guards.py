"""Upload trust boundary, active aggregate stop, fixed caps and runner cleanup."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from src.paper2.prototype import work_budget as budget, upload_gate, failure_evidence
from src.paper2.prototype import replay, artifact_integrity, production_replay, remote_authorization


class DeliveryGuards(unittest.TestCase):
    def test_active_watchdog_stops_work_preserves_evidence_and_blocks_upload(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td);root=base/'control';root.mkdir()
            (root/'progress.jsonl').write_text('{"phase":"synthetic work"}\n')
            budget.start(root,.15)
            child=subprocess.Popen([sys.executable,'-B','-c','import time; time.sleep(30)'])
            thread=threading.Thread(target=budget.monitor,args=(root,'synthetic'),
                kwargs=dict(poll=.01,process_source=lambda token:[child.pid] if child.poll() is None else [],terminate=lambda pid:child.terminate()))
            thread.start()
            try:
                child.wait(timeout=10)
                self.assertIsNotNone(child.returncode)
                self.assertTrue((base/'WATCHDOG_EXPIRED.json').is_file())
                self.assertTrue((base/'failure-upload/UNVERIFIED').is_file())
                dest=base/'failed-attempt-evidence-fixture'
                failure_evidence.preserve(dest,[root,base/'failure-upload'])
                self.assertTrue((dest/'0/progress.jsonl').is_file())
                with self.assertRaisesRegex(ValueError,'UNVERIFIED'):upload_gate.seal(dest)
                with self.assertRaises(TimeoutError):budget.require(root,0)
            finally:
                (base/'WATCHDOG_STOP').touch();thread.join(5)
                if child.poll() is None:child.kill();child.wait()
            self.assertFalse(thread.is_alive())

    def test_stage_refuses_full_cap_without_shortening_or_resetting_clock(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'control';budget.start(root,2);before=(root/'watchdog.json').read_bytes()
            budget.start(root,100)
            self.assertEqual((root/'watchdog.json').read_bytes(),before)
            self.assertGreater(budget.require(root,1),0)
            with self.assertRaises(TimeoutError):budget.require(root,3)

    def test_replay_gather_and_authorization_reject_failure_marker_or_name(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'UNVERIFIED').write_text('inspection only')
            for call in (lambda:replay.verify_index(root),lambda:replay.verify_files(root,'RESULT_MANIFEST.json'),
                         lambda:artifact_integrity.verify_checksums(root),lambda:production_replay.controls(root),
                         lambda:replay.verify_aggregate(root)):
                with self.assertRaisesRegex(ValueError,'UNVERIFIED'):call()
            with patch.object(remote_authorization,'api',side_effect=AssertionError('must not acquire failure material')):
                with self.assertRaisesRegex(ValueError,'UNVERIFIED'):
                    remote_authorization.download(dict(name='failed-attempt-evidence-1',id=1),root/'download')
                with self.assertRaisesRegex(ValueError,'UNVERIFIED'):
                    remote_authorization.download(dict(name='paper2-g3-report-1',id=1),root/'download')

    def test_failure_retains_partial_public_outputs_and_excludes_private(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'source';source.mkdir()
            (source/'events.csv').write_text('partial\n');(source/'private').mkdir()
            (source/'private/key.json').write_text('not public')
            (source/'key.state').write_text('state')
            destination=root/'evidence';failure_evidence.preserve(destination,[source])
            self.assertTrue((destination/'0/events.csv').is_file())
            self.assertFalse((destination/'0/private/key.json').exists())
            self.assertFalse((destination/'0/key.state').exists())
            self.assertTrue((destination/'UNVERIFIED').is_file())

    def test_arm_monitor_cleanup_and_threshold_order_are_explicit(self):
        base=Path(budget.__file__).parent
        for name in ('paper2-g3.yml','paper2-g3-rehearsal.yml'):
            text=(base/name).read_text()
            self.assertIn('timeout-minutes: 330',text)
            self.assertLess(text.index(' monitor --root '),text.index('sudo rm -rf'))
            self.assertLess(text.index('before_bytes'),text.index('sudo rm -rf'))
            self.assertLess(text.index('sudo rm -rf'),text.index('after_bytes'))
            self.assertLess(text.index('after_bytes'),text.index('disk-job-start.txt'))
            self.assertLess(text.index('disk-job-start.txt'),text.index('production prepare'))
            self.assertIn("PAPER2_FAILURE_EVIDENCE: '1'",text)
            self.assertIn('--cap 3300',text);self.assertIn('--cap 4800',text)
            embedded=text.split("<<'PAPER2_WATCHDOG'\n",1)[1].split('\n          PAPER2_WATCHDOG',1)[0]
            embedded='\n'.join(line[10:] if line.startswith(' '*10) else line for line in embedded.splitlines())
            self.assertEqual(embedded.strip(),Path(budget.__file__).read_text().strip())
        self.assertEqual(budget.LIMIT,280*60)

    def test_inventory_corruption_never_seals(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'log').write_text('one');artifact_integrity.write_checksums(root)
            (root/'log').write_text('two')
            with self.assertRaisesRegex(ValueError,'SHA-256'):upload_gate.seal(root)

    def test_replay_transport_seals_without_arm_pending_state(self):
        from src.paper2.prototype import transport
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{},clear=True):
            root=Path(td);source=root/'raw';source.mkdir();(source/'log').write_text('evidence')
            transport.pack(source,root/'upload')
            self.assertTrue(upload_gate.seal(root/'upload')['files'])
