"""Phase D observation, failure preservation and independent partition checks."""
from tests.paper2._provenance import setUpModule,tearDownModule
import csv,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.paper2.prototype import stage_capture as c,corpus,runtime,cycle_calibration
from src.paper2.model.engine import run_model
from src.paper2.verify.invariants import check
from tests.paper2.test_phase5a_deviation5 import Clock,Deviation5
from tests.paper2.test_phase5a_dispatcher import decisions
from src.paper2.prototype.runner import parameters
from src.paper2.workload import generate_workload


class Capture(unittest.TestCase):
    def test_numeric_nested_partition_and_detected_double_count(self):
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,100,dict(window='fixture'));b=c.Boundaries(r)
            b.begin(0,c.F['arrival'],c.S['arrival_pre']);b.begin(2,c.F['send'],c.S['send_pre'])
            b.change(3,c.S['send_tail']);b.end(5);b.end(8);r.finish(True,8)
            a=c.audit(td);self.assertTrue(a['passed'],a);self.assertEqual(a['exclusive_ns'],8);self.assertEqual(a['max_absolute_residual_ns'],0)
            rows=list(c.rows(td));self.assertEqual(len(rows),12)
            # A child starting before the parent's exclusive interval ended
            # must be rejected independently of a numerically balanced sum.
            with tempfile.TemporaryDirectory() as bad:
                x=c.Recorder(bad,100,{})
                for row in rows:
                    if row[1]==c.E['stage_exit'] and row[4]==0 and row[0]==2:continue
                    x.append(*row)
                x.finish(True);self.assertFalse(c.audit(bad)['passed'])

    def test_overflow_partial_and_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,1,{});r.append(0,c.E['release'],c.F['loop'])
            with self.assertRaises(c.CaptureOverflow):r.append(1,c.E['release'],c.F['loop'])
            self.assertIn('INVALID',json.loads((Path(td)/'stages.json').read_text())['status'])
            self.assertEqual(len(list(c.rows(td,True))),1);r.finish(False)
            with self.assertRaises(ValueError):list(c.rows(td))
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,10,{});b=c.Boundaries(r);b.begin(0,c.F['loop'],c.S['loop']);b.end(1);r.finish(True)
            with (Path(td)/'stages.bin').open('r+b') as f:f.seek(c.HEADER.size);f.write(b'corrupt!')
            with self.assertRaisesRegex(ValueError,'hash mismatch'):list(c.rows(td))

    def test_open_mmap_header_prefix_recoverable_before_final_metadata_flush(self):
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,100,{});r.append(1,c.E['release'],c.F['loop'])
            self.assertEqual(json.loads((Path(td)/'stages.json').read_text())['count'],0)
            self.assertEqual(len(list(c.rows(td,True))),1)
            with self.assertRaises(ValueError):list(c.rows(td))
            r.finish(False)

    def test_atomic_spreads_and_inline_send_are_report_only(self):
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,100,dict(backend='fake',k=1,replicate=0),['block:0:tx:0','block:0:sig'],['B']);b=c.Boundaries(r)
            b.begin(0,c.F['block_arrival'],c.S['block_lookups'],block=0,size=1)
            b.record(2,c.E['enqueue'],job=0);b.begin(3,c.F['send'],c.S['send_pre'],job=0)
            b.record(4,c.E['send']);b.end(5);b.record(7,c.E['enqueue'],job=1);b.end(8);r.finish(True)
            a=c.atomic_groups(td);v=a['groups']['final_block_tx_block_sig_enqueue']
            self.assertEqual(v,dict(count=1,mean_ns=5.0,p50_ns=5,p95_ns=5,max_ns=5,inline_sends=1))
            self.assertIsNone(a['threshold']);self.assertFalse(a['affects_rules'])

    def test_capture_on_off_decisions_and_timestamps_fifo_priority_p4_k1_k2(self):
        for k in (1,2):
            for policy in (dict(name='fifo'),dict(name='block_priority'),dict(name='priority_floor',beta=.25,W=.1)):
                with self.subTest(k=k,policy=policy),tempfile.TemporaryDirectory() as td:
                    root=Path(td);doc=corpus.build(Deviation5().fixture(policy,k),'sleep');cp=corpus.write(doc,root/'corpus.json');logs=[]
                    for enabled in (False,True):
                        clock=Clock()
                        with clock.patches():e,m=runtime.run(dict(doc['workload'],stage_capture=enabled,output_dir=str(root/str(enabled))),cp,sleep_seconds=.01)
                        self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
                        logs.append((decisions(e),clock.sends,e.read_bytes(),(e.parent/'jobs.csv').read_bytes()))
                    self.assertEqual(logs[0],logs[1])
                    directory=root/'True';self.assertTrue(c.audit(directory)['passed'])
                    spec=json.loads((directory/'stages.json').read_text());rows=list(c.rows(directory))
                    for event in ('enqueue','send','pipe_return','receive','cache','pool','decision','bind'):
                        self.assertTrue(any(row[1]==c.E[event] for row in rows),event)
                    for identity in {r[6] for r in rows if r[1]==c.E['send']}:
                        self.assertIn(identity,{r[6] for r in rows if r[1]==c.E['receive']})
                    self.assertFalse(spec['context']['calibration_only']);self.assertFalse(spec['overhead_subtracted'])

    def test_memory_stop_preserves_invalid_capture(self):
        from src.paper2.prototype import gc_control as g
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json')
            with Clock().patches(),patch.object(g,'memory_snapshot',return_value=dict(rss_bytes={'1':1},available_bytes=0,total_bytes=32*g.GIB)):
                with self.assertRaises(g.MemoryStop):runtime.run(dict(doc['workload'],output_dir=str(root/'run')),cp)
            spec=json.loads((root/'run/stages.json').read_text());self.assertIn('INVALID',spec['status'])
            for name in ('gc_state.json','progress.jsonl','partial-state.json','stages.bin'):self.assertTrue((root/'run'/name).is_file())

    def test_cycle_capture_same_schema_with_own_job_links_and_atomic_report(self):
        class FineClock(Clock):
            def advance(self,seconds):self.now+=max(1,round(seconds*1e9)) if seconds>0 else 0
            def wait(self,pipes,timeout):
                before=self.now;result=super().wait(pipes,timeout)
                if self.now==before and timeout>0:self.now+=1
                return result
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(generate_workload(parameters(2560,0,.05,horizon=.1)),'sleep');cp=corpus.write(doc,root/'corpus.json')
            with FineClock(duration=100000).patches():cycle_calibration.calibrate_cycle(cp,2,root/'cycle',0,1280,30000,0,.2,False,'-capture')
            directory=root/'cycle';self.assertTrue(c.audit(directory)['passed']);spec=json.loads((directory/'stages.json').read_text())
            self.assertEqual(spec['schema'],c.SCHEMA);self.assertEqual(spec['context']['window'],'representative-cycle')
            sends={spec['jobs'][r[6]] for r in c.rows(directory) if r[1]==c.E['send']}
            with (directory/'cycles.csv').open(newline='') as f:
                for row in csv.DictReader(f):self.assertIn(row['job_id'],sends)
            self.assertTrue((directory/'atomic-groups.json').is_file())
            physical=sum(r[1]==c.E['send'] for r in c.rows(directory))
            idle_rows=sum(r[1]==c.E['idle_interval'] for r in c.rows(directory))
            print('CAPTURE_MEASURED '+json.dumps(dict(rows=spec['count'],physical_sends=physical,
                event_rows=spec['count']-idle_rows,idle_interval_rows=idle_rows,
                event_rows_per_send=(spec['count']-idle_rows)/physical,idle_rows_per_send=idle_rows/physical,
                rows_per_physical_send=spec['count']/physical,allocation=spec['context']['capacity_formula'],
                partition=c.audit(directory))),flush=True)

    def test_timeout_preserves_numeric_prefix_and_names_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json');clock=Clock()
            def fail(message):
                if len(clock.sends)==2:raise TimeoutError('synthetic worker timeout')
            clock.on_send=fail
            with clock.patches():
                with self.assertRaises(TimeoutError):runtime.run(dict(doc['workload'],output_dir=str(root/'run')),cp)
            spec=json.loads((root/'run/stages.json').read_text());self.assertIn('INVALID',spec['status'])
            self.assertGreater(spec['count'],0);self.assertEqual(len(list(c.rows(root/'run',True))),spec['count'])

    def test_occupancy_and_dispatcher_probes_use_capture_and_links(self):
        from src.paper2.prototype import calibration
        # Bounded-repair class A: match the existing representative-cycle fake
        # clock convention. Positive sub-ns idle delays must make progress.
        # Capture bounds/format and the runtime clock are unchanged.
        class FineClock(Clock):
            def advance(self,seconds):self.now+=max(1,round(seconds*1e9)) if seconds>0 else 0
            def wait(self,pipes,timeout):
                before=self.now;result=super().wait(pipes,timeout)
                if self.now==before and timeout>0:self.now+=1
                return result
        clock=FineClock(duration=100000)
        def workers(*args):
            w=clock.workers(*args);w.processes=[];return w
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(generate_workload(parameters(2560,0,.05,horizon=.1)),'sleep');cp=corpus.write(doc,root/'corpus.json')
            with clock.patches(),patch.object(calibration,'Workers',side_effect=workers),patch.object(calibration,'wait',side_effect=clock.wait):
                calibration.calibrate_once(cp,1,root/'occupancy',0,0,.02)
            for name,window in (('','occupancy'),('dispatcher-fifo','dispatcher-probe'),('dispatcher-block_priority','dispatcher-probe')):
                directory=root/'occupancy'/name;self.assertTrue(c.audit(directory)['passed'])
                self.assertEqual(json.loads((directory/'stages.json').read_text())['context']['window'],window)
            spec=json.loads((root/'occupancy/stages.json').read_text());rows=list(c.rows(root/'occupancy'))
            with (root/'occupancy/occupancy.csv').open(newline='') as f:
                for row in csv.DictReader(f):
                    identity=int(row['job_id']);self.assertTrue(any(r[1]==c.E['send'] and r[6]==identity for r in rows))
                    self.assertTrue(any(r[1]==c.E['receive'] and r[6]==identity for r in rows))

    def test_nonadvancing_idle_spin_still_overflows_invalid_with_evidence(self):
        # Authorised design review T: derive gaps from fixture releases, never
        # from recorder counts. Frozen time permits only the t=0 callbacks;
        # worker completions and block C (t=.1) cannot become ready.
        observed=[]
        for capacity in (8192,16384):
            with self.subTest(capacity=capacity),tempfile.TemporaryDirectory() as td:
                root=Path(td);cfg=Deviation5().fixture(dict(name='fifo'));clock=Clock()
                schedule=[(a['arrival_t'],'arrival') for a in cfg['admissions']]
                schedule.extend((t,'block_arrival') for t in cfg['block_times'])
                ready=sorted((t,family) for t,family in schedule if round(t*1e9)<=clock.now)
                expected_intervals=len(ready)+1
                doc=corpus.build(cfg,'sleep');cp=corpus.write(doc,root/'corpus.json')
                clock.wait=lambda pipes,timeout:[]
                with clock.patches():
                    with self.assertRaisesRegex(c.CaptureOverflow,'non-advancing idle spin'):
                        runtime.run(dict(doc['workload'],stage_capture_capacity=capacity,output_dir=str(root/'spin')),cp)
                spec=json.loads((root/'spin/stages.json').read_text());rows=list(c.rows(root/'spin',True))
                self.assertIn('INVALID',spec['status']);self.assertTrue(spec['overflow'])
                self.assertEqual(len(rows),spec['count']);self.assertLess(spec['count'],capacity)
                self.assertEqual(spec['capacity'],capacity)
                self.assertEqual(spec['sha256'],c.sha(root/'spin/stages.bin'))
                idle=[(i,r) for i,r in enumerate(rows) if r[1]==c.E['idle_interval']]
                roots=[(i,r) for i,r in enumerate(rows) if r[1]==c.E['callback_entry'] and r[5]==-1]
                self.assertEqual(len(idle),expected_intervals);self.assertEqual(len(roots),len(ready))
                previous_end=-1
                for n,(index,row) in enumerate(idle):
                    self.assertLessEqual(previous_end,row[6]);self.assertLessEqual(row[6],row[0]);previous_end=row[0]
                    self.assertFalse(any(row[6]<root_row[0]<row[0] for _,root_row in roots))
                    if n<len(ready):
                        root_index,root_row=roots[n]
                        self.assertEqual(root_index,index+1)  # no callback spanned even at equal times
                        self.assertEqual((root_row[0],c.FAMILIES[root_row[2]]),(round(ready[n][0]*1e9),ready[n][1]))
                        self.assertEqual(row[0],root_row[0]);self.assertEqual((row[9],row[10]),(1,0))
                    else:self.assertEqual(index,len(rows)-1)
                final=idle[-1][1]
                self.assertEqual(final[9],c.IDLE_SPIN_LIMIT+1);self.assertEqual(final[10],c.IDLE_SPIN_LIMIT)
                self.assertEqual(spec['idle_spin_guard']['limit'],4096)
                self.assertEqual(spec['idle_spin_guard']['consecutive_no_progress'],4096)
                observed.append((len(rows),len(idle),final))
                for name in ('partial-state.json','progress.jsonl','gc_state.json'):self.assertTrue((root/'spin'/name).is_file())
        self.assertEqual(observed[0],observed[1])

    def test_advancing_long_idle_lead_in_is_one_interval_independent_of_duration(self):
        class AdvancingClock(Clock):
            def advance(self,seconds):self.now+=max(1,round(seconds*1e9)) if seconds>0 else 0
            def wait(self,pipes,timeout):
                before=self.now;result=super().wait(pipes,timeout)
                if self.now==before and timeout>0:self.now+=1
                return result
        counts=[]
        for lead in (60,120):
            with self.subTest(lead=lead),tempfile.TemporaryDirectory() as td:
                root=Path(td);cfg=Deviation5().fixture(dict(name='fifo'))
                cfg['admissions']=[dict(a,arrival_t=a['arrival_t']+lead) for a in cfg['admissions']]
                cfg['block_times']=[lead+t for t in cfg['block_times']]
                doc=corpus.build(cfg,'sleep');cp=corpus.write(doc,root/'corpus.json')
                with AdvancingClock().patches():runtime.run(dict(doc['workload'],output_dir=str(root/'run')),cp)
                spec=json.loads((root/'run/stages.json').read_text());rows=list(c.rows(root/'run'))
                idle=[r for r in rows if r[1]==c.E['idle_interval']]
                self.assertEqual(spec['status'],'COMPLETE');self.assertTrue(c.audit(root/'run')['passed'])
                self.assertEqual(idle[0][6],0);self.assertEqual(idle[0][0],lead*10**9)
                self.assertEqual(idle[0][10],lead*100)
                self.assertLessEqual(len(idle),spec['context']['capacity_formula']['merged_idle_bound'])
                counts.append((len(idle),spec['count'],spec['capacity']))
        self.assertEqual(counts[0],counts[1])

    def test_idle_observation_partition_mutation_detected(self):
        with tempfile.TemporaryDirectory() as td:
            r=c.Recorder(td,100,{});r.idle_interval(0,10,'loop')
            b=c.Boundaries(r);b.begin(10,c.F['arrival'],c.S['arrival_pre']);b.end(12);r.finish(True)
            self.assertTrue(c.audit(td)['passed'])
            original=list(c.rows(td));self.assertEqual(original[0][1],c.E['idle_interval'])
            for label,index,value in (('bad sum',11,1),('overlap',0,11)):
                with self.subTest(label=label),tempfile.TemporaryDirectory() as bad:
                    x=c.Recorder(bad,100,{})
                    for i,row in enumerate(original):
                        changed=list(row)
                        if i==0:changed[index]=value
                        x.append(*changed)
                    x.finish(True);self.assertFalse(c.audit(bad)['passed'])
