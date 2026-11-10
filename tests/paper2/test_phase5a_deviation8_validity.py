"""Author amendment: explicit drain/load INVALID; one-second dips diagnostic only."""
from pathlib import Path
import tempfile
import unittest
from src.paper2.prototype import measurement_conditions as mc, validation_dryrun as dry, g3_decision


class MeasurementConditions(unittest.TestCase):
    def evaluate(self, records=(), spans=(), events=(), receipt=True, incomplete=False):
        return mc.evaluate(records, spans, events, receipt, incomplete)

    def test_span_union_clipping_and_exact_guard_boundary(self):
        spans=[dict(start_t=20,end_t=45),dict(start_t=40,end_t=60),dict(start_t=42,end_t=44)]
        result=self.evaluate(spans=spans)
        self.assertEqual(result['observed_dispatcher_load']['busy_fraction'],.5)
        self.assertTrue(result['passed'])
        spans.append(dict(start_t=89,end_t=100))
        self.assertFalse(self.evaluate(spans=spans)['passed'])

    def test_drain_census_includes_late_work_and_every_class(self):
        for cls in ('admission','block_tx','block_sig'):
            with self.subTest(cls=cls):
                job=dict(job_class=cls,enqueue_t=100,start_t=104,end_t=106,status='end')
                result=self.evaluate(records=[job])
                self.assertFalse(result['drain']['passed'])
                self.assertEqual(result['drain']['pending_by_class'][cls]['running'],1)
                job.update(start_t=106,end_t=107)
                self.assertEqual(self.evaluate(records=[job])['drain']['pending_by_class'][cls]['waiting'],1)
                job.update(start_t=104,end_t=105)
                self.assertTrue(self.evaluate(records=[job])['passed'])

    def test_receipt_required_and_logical_checks_not_physical_work(self):
        for status in ('drop','cache_hit','coalesced','struct_reject','dup_drop','neg_hit'):
            self.assertTrue(self.evaluate(records=[dict(job_class='admission',enqueue_t=31,status=status)])['passed'])
        self.assertFalse(self.evaluate(receipt=False)['passed'])
        self.assertFalse(self.evaluate(incomplete=True)['passed'])

    def test_dip_only_is_valid_and_empty_bins_are_not_zero_hits(self):
        event=dict(t=30.25,job_class='block_tx',event='cache_miss')
        result=self.evaluate(events=[event])
        self.assertTrue(result['passed'])
        diagnostic=result['cache_bin_diagnostic']
        self.assertFalse(diagnostic['affects_validity'])
        self.assertEqual(diagnostic['minimum_one_second_hit_rate'],0)
        self.assertEqual(diagnostic['first_one_second_below_50'],30)
        self.assertIsNone(diagnostic['one_second_bins']['31']['hit_rate'])
        self.assertEqual(self.evaluate()['cache_bin_diagnostic']['first_one_second_below_50'],'never')

    def test_d2_invariant_survives_either_invalid_condition_without_comparison(self):
        for conditions in (self.evaluate(receipt=False),self.evaluate(spans=[dict(start_t=30,end_t=61)])):
            result=dict(run_id='cell0-r0',cell_id=0,replicate=0,
                prototype=dict(validity=dict(passed=False,measurement_conditions=conditions),violations=['planted']))
            row=g3_decision.repetition(result)
            self.assertFalse(row['valid']);self.assertNotIn('primary',row)
            self.assertEqual(g3_decision.cell_decision(0,{},[row])['verdict'],'FAIL')

    def test_real_synthetic_prepare_matrix_replay_and_sealed_gather(self):
        for scenario in ('drain_only','dispatcher_load_only','dip_only'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as td:
                root=Path(td)
                dry.create(root/'inputs',scenario)
                receipt=dry.exercise(root/'inputs',root/'results',scenario)
                self.assertTrue(receipt['passed'])

    def test_workflow_includes_all_three_new_scenarios(self):
        from src.paper2.prototype.replay import ROOT
        text=(ROOT/'src/paper2/prototype/paper2-g3-validation-dryrun.yml').read_text()
        for scenario in ('drain_only','dispatcher_load_only','dip_only'):
            self.assertIn(scenario,text)
