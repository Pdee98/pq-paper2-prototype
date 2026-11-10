"""Author D1 correction, D2/D3 precedence and independently sealed aggregates."""
import copy
import tempfile
import unittest
from pathlib import Path
from src.paper2.prototype import replay,g3_decision as d
from src.paper2.prototype.analysis import BANDS
from src.paper2.prototype.validation_caps import for_transactions,CALIBRATION


def fixture():
    cell=dict(backend='xmss',k=1,policy='fifo',rho_cold=.5,rate=10,period=12.8,dispatcher_utilisation=.1)
    index=dict(cells=[cell],runs=[dict(run_id=f'cell0-r{r}',cell_id=0,replicate=r,manifest_sha256=str(r)*64) for r in range(3)],excluded_cells=[],code_commit='a'*40,source_run_id='123')
    return index,[record(index,r) for r in index['runs']]


def record(index,r):
    metrics=dict.fromkeys(BANDS,1.);metrics.update(complete=True,block_tx_cache_hit_rate=.99)
    return dict(run_id=r['run_id'],cell_id=r['cell_id'],replicate=r['replicate'],input_sha256=r['manifest_sha256'],code_commit=index['code_commit'],source_run_id=index['source_run_id'],
        **{name:dict(metrics=copy.deepcopy(metrics),violations=[],**({'validity':dict(passed=True)} if name=='prototype' else {})) for name in ('prototype','primary','held_out')})


def invalid(r):r['prototype']['validity']=dict(passed=False,failing_guards=['cycle stationarity']);r.pop('primary');r.pop('held_out')


def replacement(index,records):
    r=dict(run_id='cell0-r3',cell_id=0,replicate=3,manifest_sha256='3'*64);index['runs'].append(r);index['followup_cells']=[0];records.append(record(index,r));return records[-1]


def secondary(index,records):
    index['cells'].append(dict(index['cells'][0],role='secondary'));r=dict(run_id='secondary-regime',cell_id=1,replicate=0,manifest_sha256='f'*64);index['runs'].append(r);records.append(record(index,r));return records[-1]


class Deviation8(unittest.TestCase):
    def test_all_pass_and_held_out_band_exceedance_does_not_gate(self):
        i,r=fixture();r[0]['held_out']['metrics']['mean_block_delay']=100
        self.assertEqual(d.gather_records(i,r)['verdict'],'PASS')

    def test_band_fail_and_invalid_is_fail_and_not_followup(self):
        i,r=fixture();invalid(r[0]);r[1]['primary']['metrics']['mean_block_delay']=2
        result=d.gather_records(i,r);self.assertEqual(result['verdict'],'FAIL');self.assertEqual(result['followup_plan'],[])

    def test_invariant_in_invalid_is_fail(self):
        i,r=fixture();invalid(r[0]);r[0]['prototype']['violations']=[dict(code='planted')]
        self.assertEqual(d.gather_records(i,r)['verdict'],'FAIL')

    def test_one_invalid_is_inconclusive_followup_only_at_three(self):
        i,r=fixture();invalid(r[0]);result=d.gather_records(i,r)
        self.assertEqual(result['verdict'],'INCONCLUSIVE');self.assertEqual(result['followup_plan'][0]['replicate'],3)
        self.assertFalse(result['aggregates'][0]['final']);self.assertEqual(len(result['invalid_runs']),1)

    def test_two_invalid_final_no_followup(self):
        i,r=fixture();invalid(r[0]);invalid(r[1]);result=d.gather_records(i,r)
        self.assertEqual(result['verdict'],'INCONCLUSIVE');self.assertEqual(result['followup_plan'],[]);self.assertTrue(result['aggregates'][0]['final'])

    def test_followup_pass_fail_invalid_and_invalid_invariant(self):
        for case in ('PASS','FAIL','INVALID','INVALID_INVARIANT'):
            i,r=fixture();invalid(r[0]);extra=replacement(i,r)
            if case=='FAIL':extra['primary']['metrics']['p95_block_delay']=2
            if case.startswith('INVALID'):invalid(extra)
            if case=='INVALID_INVARIANT':extra['prototype']['violations']=[dict(code='planted')]
            result=d.gather_records(i,r)
            self.assertEqual(result['verdict'],dict(PASS='PASS',FAIL='FAIL',INVALID='INCONCLUSIVE',INVALID_INVARIANT='FAIL')[case])
            self.assertEqual(result['followup_plan'],[]);self.assertTrue(result['aggregates'][0]['final'])

    def test_no_replicate_four_or_five_or_followup_for_pass_or_two_invalid(self):
        for rep in (4,5):
            i,r=fixture();r[0]['replicate']=rep
            with self.assertRaisesRegex(ValueError,'never permitted'):d.gather_records(i,r)
        i,r=fixture();replacement(i,r)
        with self.assertRaisesRegex(ValueError,'exactly one initial'):d.gather_records(i,r)
        i,r=fixture();invalid(r[0]);invalid(r[1]);replacement(i,r)
        with self.assertRaisesRegex(ValueError,'exactly one initial'):d.gather_records(i,r)

    def test_secondary_missing_error_disagree_and_sim_invariant_are_diagnostic(self):
        for case in ('missing','error','disagree','simulation_invariant'):
            i,r=fixture();s=secondary(i,r)
            if case=='missing':r.pop()
            elif case=='error':s['execution_error']='synthetic error'
            elif case=='disagree':s['primary']['metrics']['block_tx_cache_hit_rate']=.3
            else:s['held_out']['violations']=[dict(code='diagnostic')]
            result=d.gather_records(i,r);self.assertEqual(result['verdict'],'PASS');self.assertEqual(len(result['secondary_regime']),1)

    def test_secondary_prototype_invariant_is_global_fail(self):
        i,r=fixture();s=secondary(i,r);s['prototype']['violations']=[dict(code='correctness')]
        self.assertEqual(d.gather_records(i,r)['verdict'],'FAIL')

    def test_seal_covers_aggregate_and_nested_cell_seals_and_rejects_unsealed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);replay.save(root/'G3_STATUS.json',dict(verdict='PASS'))
            with self.assertRaisesRegex(ValueError,'unsealed'):replay.verify_aggregate(root)
            cell=root/'cells/cell0-r0';replay.save(cell/'result.json',{});replay.seal(cell,'RESULT_MANIFEST.json')
            replay.seal_aggregate(root,'a'*40);manifest=replay.verify_aggregate(root,'a'*40)
            self.assertIn('cells/cell0-r0/RESULT_MANIFEST.json',{r['path'] for r in manifest['files']})
            (root/'G3_STATUS.json').write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'mismatch'):replay.verify_aggregate(root)

    def test_caps_use_exact_count_and_per_backend_caps(self):
        self.assertEqual(CALIBRATION,dict(xmss=1200,ml_dsa_44=1900))
        self.assertEqual(for_transactions(1000),{'preparation':30.,'prototype window':110.,'serialisation':60.})
        self.assertAlmostEqual(for_transactions(1000000)['preparation'],141.4)
        self.assertAlmostEqual(for_transactions(1000000)['serialisation'],416.8)
