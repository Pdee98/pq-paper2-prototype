"""Visible complete artifacts, replay checkout receipts and fresh v5 preparation."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.prototype import artifact_integrity as integrity
from src.paper2.prototype import cycle_diagnostic_v4 as v4, cycle_diagnostic_v5 as v5
from src.paper2.prototype import diagnostic, pause_attribution as pause, replay, runner
from src.paper2.prototype import replay_progress as progress
from src.paper2.model.service_times import derive_seed


class PreV5(unittest.TestCase):
    def test_hidden_files_are_listed_then_rejected_not_silently_dropped(self):
        for name in ('.pause_gc.bin', '.unexpected/file.bin'):
            with tempfile.TemporaryDirectory() as td:
                root=Path(td);p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'buffer')
                with self.assertRaisesRegex(ValueError,'hidden artifact'):integrity.write_checksums(root)
                self.assertIn(name,(root/'SHA256SUMS').read_text())

    def test_completeness_rejects_absent_changed_and_unlisted_files(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);p=root/'receipt.json';p.write_bytes(b'{}')
            integrity.write_checksums(root);self.assertEqual(integrity.verify_checksums(root)['files'],1)
            p.unlink()
            for verify in (integrity.verify_checksums,lambda r: diagnostic.verify(r,'1'),lambda r: replay.verify(r,'1')):
                with self.assertRaisesRegex(ValueError,'missing artifact checksum entry'):verify(root)
            p.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):integrity.verify_checksums(root)
            p.write_bytes(b'{}');(root/'unexpected').write_bytes(b'x')
            with self.assertRaisesRegex(ValueError,'unlisted artifact'):integrity.verify_checksums(root)

    def test_nested_replay_inventory_is_covered_by_parent_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);child=root/'replay-inputs';child.mkdir();(child/'INDEX.json').write_bytes(b'{}')
            runner.hash_artifacts(root)
            self.assertEqual(integrity.verify_checksums(child)['files'],1)
            self.assertEqual(integrity.verify_checksums(root)['files'],2)
            self.assertIn('replay-inputs/SHA256SUMS',(root/'SHA256SUMS').read_text())

    def test_renamed_buffers_recover_identical_records_and_remain_hashed_on_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);rec=pause.PauseRecorder(root,gc_capacity=8,span_capacity=8,step_capacity=8)
            rec.callback('start',dict(generation=1));rec.callback('stop',dict(generation=1,collected=2,uncollectable=0))
            rec.begin_span(0,'_block',100);rec.end_span(2000000)
            result=rec.finish(partial=True)
            self.assertIsNone(result['error']);self.assertEqual(result['gc_records'],1)
            before=(root/'gc_pauses.json').read_bytes();pause.recover(root,partial=True)
            self.assertEqual((root/'gc_pauses.json').read_bytes(),before)
            self.assertEqual(pause.FILES,('pause_gc.bin','pause_spans.bin','pause_steps.bin'))
            runner.hash_artifacts(root)
            for name in pause.FILES:
                self.assertTrue((root/name).is_file());self.assertIn(name,(root/'SHA256SUMS').read_text())
            integrity.verify_checksums(root)

    def test_result_manifest_records_actual_checkout_clean_flag_and_source(self):
        for clean in (True,False):
            with tempfile.TemporaryDirectory() as td,contextlib.redirect_stdout(io.StringIO()):
                output=Path(td)/'result'
                @progress.tracked_run
                def run(output):
                    progress.record_source_commit('a'*40)
                    replay.save(output/'result.json',dict(code_commit='a'*40))
                receipt=dict(replay_code_commit='b'*40,replay_tree_clean=clean,checkout_kind='git checkout',export_source_commit=None)
                with patch.object(progress,'checkout_receipt',return_value=receipt):run(output)
                manifest=replay.verify_files(output,'RESULT_MANIFEST.json')
                self.assertEqual(manifest['provenance'],dict(source_code_commit='a'*40,**receipt))
                replay.seal(output,'RESULT_MANIFEST.json')
                self.assertEqual(replay.verify_files(output,'RESULT_MANIFEST.json')['provenance'],manifest['provenance'])

    def test_export_without_git_is_not_misrepresented_as_checkout(self):
        with patch('src.paper2.model.engine._git_state',return_value=dict(commit='a'*40,dirty=False,exported=True)):
            receipt=progress.checkout_receipt()
        self.assertIsNone(receipt['replay_code_commit']);self.assertIsNone(receipt['replay_tree_clean'])
        self.assertEqual(receipt['export_source_commit'],'a'*40)

    def test_same_commit_rule_still_rejects_different_checkout(self):
        with patch.dict(diagnostic.os.environ,{'GITHUB_ACTIONS':'true'}),patch.object(diagnostic,'_git_state',return_value=dict(commit='b'*40)):
            with self.assertRaisesRegex(ValueError,'checkout differs'):diagnostic.verify_checkout(dict(code_commit='a'*40))

    def test_uploads_require_successful_complete_visible_inventory(self):
        for name in ('paper2-g3.yml','paper2-g3-diagnostic.yml'):
            text=Path(runner.__file__).with_name(name).read_text()
            self.assertIn('id: artifact_hashes',text)
            self.assertEqual(text.count("steps.artifact_hashes.outcome == 'success'"),2)
            self.assertNotIn('include-hidden-files: true',text)

    def test_v5_reuses_same_cells_and_timeouts_with_fresh_seeds(self):
        self.assertEqual(v5.RUN_ID,'paper2-g3-diag-v5')
        self.assertEqual(v5.CASES,v4.CASES);self.assertEqual(v5.TIMEOUTS,v4.TIMEOUTS)
        p=v5.parameters(40,.5,.8)
        self.assertNotEqual(derive_seed(p['run_id'],'arrivals',0),derive_seed(v4.RUN_ID,'arrivals',0))
        with patch.object(v4,'collect',return_value='collected') as collect:
            self.assertEqual(v5.collect('output'),'collected')
        self.assertEqual(collect.call_args.kwargs['run_id'],v5.RUN_ID)
        projection=collect.call_args.kwargs['planning_projection']
        self.assertEqual(projection['run_id'],v5.RUN_ID);self.assertEqual(len(projection['runs']),3)
        self.assertLess(projection['projected_seconds'],165*60)
        self.assertTrue(all(60<=r['replay_timeout_minutes']<=330 for r in projection['runs']))


if __name__=='__main__':unittest.main()
