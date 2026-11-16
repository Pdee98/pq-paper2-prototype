"""Small local gates; full-size scale/G2 execute only by manual workflow."""
from tests.paper2._provenance import setUpModule,tearDownModule
from pathlib import Path
import csv,json,tempfile,unittest
import hashlib,re
from unittest.mock import patch
import tests.paper2.test_phase5a_deviation9_b as fixtures
from tests.paper2 import _explicit_e50_reference as reference
from src.paper2.verify.invariants import check
from src.paper2.verify.streaming import CSVRows
from src.paper2.verify import explicit
from src.paper2.artifact_stream import Spool,write_arrays,read_arrays


def compare_checker(events,jobs,manifest):
    fast=check(events,jobs,manifest)
    with patch.object(explicit,'inspect',reference.inspect):slow=check(events,jobs,manifest)
    if fast!=slow:raise AssertionError(dict(optimized=fast,reference=slow))
    rows=CSVRows(events)
    with Path(jobs).open(newline='',encoding='utf-8') as f:records=[json.loads(r['record']) for r in csv.DictReader(f)]
    data=json.loads(Path(manifest).read_text())
    a=explicit.inspect(rows,records,data,manifest);b=reference.inspect(rows,records,data,manifest)
    def receipt(context):
        return dict(violations=context.errors,proof_times=context.proof_times,
            unavailable=[sorted(context.unavailable.get(i,())) for i in range(len(rows))],
            owners=[context.owners.get(i) for i in range(len(rows))])
    if receipt(a)!=receipt(b):raise AssertionError('independent replay receipts differ')
    return fast


class Qualification(unittest.TestCase):
    def test_qualification_bundle_roundtrip_inventory_and_privacy(self):
        from src.paper2.verify import qualification_export as exporter
        actual=exporter.git
        def clean(*args):return b'' if args==('status','--porcelain') else actual(*args)
        with tempfile.TemporaryDirectory() as temp,patch.object(exporter,'git',side_effect=clean),patch.object(exporter,'lint_workflow',return_value=dict(returncode=0)):
            root=Path(temp)/'bundle';receipt=exporter.export(root)
            self.assertTrue(exporter.verify(root)['qualification_only'])
            self.assertEqual([p.name for p in (root/'.github/workflows').iterdir()],[exporter.WORKFLOW])
            self.assertTrue((root/'tests/paper2/fixtures/session_a.csv').is_file())
            self.assertTrue(receipt['privacy']['passed'])
            (root/'requirements.txt').write_text('planted')
            with self.assertRaisesRegex(ValueError,'payload mismatch'):exporter.verify(root)

    def test_workflow_sequential_manual_receipt_only(self):
        import inspect
        from src.paper2.verify import qualification
        from src.paper2.verify.qualification_export import ROOT,WORKFLOW
        raw=(ROOT/'src/paper2/verify'/WORKFLOW).read_text()
        # Author-approved D/E structure (notes, 2026-11-15): retain manual,
        # sequential, receipt-only qualification; derive counts from its jobs.
        chain={'scale':None,'phase-c':'scale','g2':'phase-c','de-capture':'g2'}
        timeouts={'scale':120,'phase-c':180,'g2':120,'de-capture':120}
        triggers=re.findall(r'^on:[ \t]*\n(.*?)(?=^\S|\Z)',raw,re.M|re.S)
        self.assertEqual(len(triggers),1)
        self.assertEqual(triggers[0].strip(),'workflow_dispatch:');self.assertNotIn('inputs:',raw)
        # Parse only the plain job mapping used by this workflow; unknown or
        # duplicate jobs and non-scalar needs/runners fail rather than disappear.
        jobs_text=raw.split('\njobs:\n',1)[1]
        headers=list(re.finditer(r'^  ([\w-]+):[ \t]*$',jobs_text,re.M))
        self.assertEqual(len(headers),len(chain))
        jobs={m.group(1):jobs_text[m.end():headers[i+1].start() if i+1<len(headers) else len(jobs_text)]
              for i,m in enumerate(headers)}
        self.assertEqual(set(jobs),set(chain))
        receipt_path='${{ runner.temp }}/receipts/'
        for job,body in jobs.items():
            with self.subTest(job=job):
                self.assertEqual(re.findall(r'^    runs-on: (.+)$',body,re.M),['ubuntu-24.04'])
                self.assertEqual(re.findall(r'^    needs: (.+)$',body,re.M),[chain[job]] if chain[job] else [])
                self.assertEqual(re.findall(r'^    timeout-minutes: (.+)$',body,re.M),[str(timeouts[job])])
                self.assertEqual(re.findall(r'qualification monitor ([\w-]+) --work "\$RUNNER_TEMP/work" --receipts "\$RUNNER_TEMP/receipts"',body),[job])
                step_headers=list(re.finditer(r'^      - ',body,re.M))
                steps=[body[m.start():step_headers[i+1].start() if i+1<len(step_headers) else len(body)]
                       for i,m in enumerate(step_headers)]
                uploads=[step for step in steps if 'uses: actions/upload-artifact@' in step]
                self.assertEqual(len(uploads),1)
                upload=uploads[0]
                self.assertEqual(re.findall(r'^          path: (.+)$',upload,re.M),[receipt_path])
                self.assertEqual(re.findall(r'^          name: (.+)$',upload,re.M),
                                 ['model-qualification-'+job+'-${{ github.run_id }}'])
                self.assertIn('if: always()',upload);self.assertIn('if-no-files-found: error',upload)
                self.assertEqual(re.findall(r'^          path: (.+)$',body,re.M),[receipt_path])
        self.assertEqual(raw.count('path: '+receipt_path),len(jobs))
        for action in re.findall(r'uses: (\S+)',raw):self.assertRegex(action,r'@[0-9a-f]{40}$')
        for name in ('prototype','calibration','replay','matrix:','continue-on-error'):self.assertNotIn(name,raw)
        monitor=inspect.getsource(qualification.monitor)
        self.assertIn("'de-capture':6900",monitor)
        guard=re.search(r"            if name=='de-capture':\n(.*?)(?=^            if reason:)",monitor,re.M|re.S)
        self.assertIsNotNone(guard)
        self.assertIn('MemAvailable:',guard.group(1))
        self.assertIn('any(rss>12*1024**3 for rss,_ in values.values()) or available<2*1024**3',guard.group(1))
        self.assertIn("reason='capture scale memory guard'",guard.group(1))
        self.assertIn('os.killpg(p.pid,signal.SIGTERM)',monitor);self.assertIn('time.sleep(1)',monitor)

    def test_scale_smoke_and_failure_stops(self):
        from src.paper2.verify.qualification_scale import scale
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);value=scale(root/'work',root/'receipts',count=16,smoke=True)
            self.assertEqual([r['transactions'] for r in value['cases']],[2,4,8,16])
            self.assertTrue(all(r['violation_count']==0 for r in value['cases']))
        with tempfile.TemporaryDirectory() as temp,patch('src.paper2.verify.qualification_scale.check',return_value=[dict(code='planted')]):
            root=Path(temp)
            with self.assertRaisesRegex(RuntimeError,'invariant'):scale(root/'work',root/'receipts',count=16,smoke=True)
            self.assertEqual(len(json.loads((root/'receipts/scale.json').read_text())['cases']),1)

    def test_pinned_reference_smoke_and_corruption(self):
        from src.paper2.verify.qualification_export import ROOT,write_reference,unpack_reference
        from src.paper2.verify.qualification_regression import run
        # The actual immutable source is executed, rather than a mirror of current code.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);write_reference(root);reference=unpack_reference(root,root/'reference')
            result=run(reference,root/'work',root/'receipts',smoke=True)
            self.assertEqual(result['status'],'passed');self.assertEqual(result['base_cases'],8)
            self.assertEqual(result['zero_cases'],6);self.assertEqual(result['differences'],[])
            with (root/'qualification_inputs/reference-3538968.tar.gz').open('ab') as f:f.write(b'planted')
            with self.assertRaisesRegex(ValueError,'seal mismatch'):unpack_reference(root,root/'corrupt')

    def test_g2_fail_closed_and_registered_controls(self):
        from src.paper2.verify.qualification import stage
        from src.paper2.verify import gate4b
        with tempfile.TemporaryDirectory() as temp,patch('src.paper2.verify.qualification.subprocess.run') as call:
            root=Path(temp);out=root/'receipts';out.mkdir();(out/'g2.json').write_text(json.dumps(dict(status='stopped: projected CPU budget')))
            with self.assertRaisesRegex(RuntimeError,'failed or stopped'):stage('g2',root/'work',out)
            call.assert_called_once()
        self.assertEqual(gate4b.PLAN,(('fifo',.3,0),('fifo',.6,0),('block_priority',.2,.2),('block_priority',.4,.2)))
        self.assertIn('30*pilot_cpu+4*pilot_cpu',Path(gate4b.__file__).read_text())

    def test_reference_equivalence_F1_F6_and_22_mutations(self):
        with patch.object(fixtures,'check',compare_checker):
            case=fixtures.PhaseB()
            case.test_F1_F6_checker_gate()
            case.test_mutation_gate()
            case.test_additional_dependency_mutations()

    def test_streamed_array_bytes_and_csv_multiline(self):
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp);s=Spool(d/'store.sqlite',by_id=True)
            rows=[dict(id=0,value='a\n"b'),dict(id=1,value='c'*70000)]
            for r in rows:s.append(r)
            rows[0]['value']='changed';s.sync(rows[0])
            write_arrays(d/'data.json','test',dict(rows=s))
            self.assertEqual((d/'data.json').read_bytes(),(json.dumps(dict(schema='test',rows=rows),separators=(',',':'))+'\n').encode())
            values=read_arrays(d/'data.json',d)
            self.assertEqual(list(values['rows']),rows);values['rows'].close();s.close()
            with (d/'events.csv').open('w',newline='') as f:
                w=csv.writer(f);w.writerow(['t','detail']);w.writerow([0,'a\nb']);w.writerow([1,'c'])
            r=CSVRows(d/'events.csv');self.assertEqual(list(r),[dict(t='0',detail='a\nb'),dict(t='1',detail='c')])
            self.assertEqual(r[1]['detail'],'c');self.assertEqual(r[0]['t'],0)


if __name__=='__main__':unittest.main(failfast=True)
