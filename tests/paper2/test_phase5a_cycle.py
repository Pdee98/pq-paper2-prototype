"""Cycle calibration, restored dispatcher order and CRN budget checks."""
from tests.paper2._provenance import setUpModule,tearDownModule
import csv,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.paper2.model.engine import run_model
from src.paper2.prototype import corpus,runtime,cycle_calibration,cycle_protocol,cycle_runner,cycle_validity
from src.paper2.verify.invariants import check
from tests.paper2.test_phase5a_deviation5 import Clock
from tests.paper2 import test_phase5a_deviation5 as previous
from tests.paper2.test_phase5a_dispatcher import decisions
from src.paper2.workload import generate_workload
from src.paper2.prototype.runner import parameters

class CycleProtocol(unittest.TestCase):
    def test_calibration_replaces_at_most_once_and_retains_both_windows(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);calls=[]
            def fresh(function,args,timeout,**kwargs):
                path,k,directory,rep=args[:4];directory=Path(directory);directory.mkdir(parents=True)
                cycle=function is cycle_calibration.calibrate_cycle
                iteration=1 if '-i1-' in directory.name else 0
                duration=(200000 if iteration else 100000) if cycle else 1000000
                rows=[dict(backend='sleep:'+c,operation='verify',variant='valid',duration_ns=duration,
                    job_class=c,source=f'concurrency-cycle-k{k}-rep{rep}') for c in cycle_protocol.CLASSES]
                sample=directory/'samples.csv'
                with sample.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=tuple(rows[0]));w.writeheader();w.writerows(rows)
                if cycle:calls.append(dict(k=k,rep=rep,iteration=iteration,traffic_rate=args[4]))
                return dict(k=k,throughput=1000*k,samples=str(sample),dispatcher_per_tx=.00001)
            with patch('src.paper2.prototype.runner.fresh',side_effect=fresh):
                refs=cycle_calibration.calibrate_backend('sleep',root/'unused.json',root)
            self.assertEqual(len(calls),12)
            session=json.loads((root/'calibration/sleep-cycle-session.json').read_text())
            self.assertEqual([w['iteration'] for w in session['windows']],[0,1,0,1])
            for k in (1,2):
                first=next(w for w in session['windows'] if w['k']==k and w['iteration']==0)
                second=next(w for w in session['windows'] if w['k']==k and w['iteration']==1)
                self.assertEqual(second['rate'],.8*first['reference']['B_cold_cycle'])
                self.assertEqual(refs[k]['cycle_means'],dict.fromkeys(cycle_protocol.CLASSES,.0002))
                self.assertIn(f'k{k}-occupancy.csv',refs[k]['occupancy_samples'])

    def test_restored_dispatcher_and_optional_labels_preserve_decisions(self):
        for policy in (dict(name='fifo'),dict(name='block_priority'),dict(name='priority_floor',beta=.25,W=.1)):
            with self.subTest(policy=policy),tempfile.TemporaryDirectory() as td:
                root=Path(td);doc=corpus.build(previous.Deviation5().fixture(policy,2),'sleep');cp=corpus.write(doc,root/'corpus.json');results=[]
                for label,kind,detailed in (('deviation4',runtime.PreDeviation5Model,False),('v6',runtime.CycleRealtimeModel,False),('labels',runtime.CycleRealtimeModel,True)):
                    clock=Clock()
                    with clock.patches():
                        e,m=run_model(dict(doc['workload'],output_dir=str(root/label),diagnostic_instrumentation=detailed),
                            model_type=lambda c:kind(c,cp,.01))
                    self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
                    results.append((decisions(e),clock.sends))
                    if kind is runtime.CycleRealtimeModel:
                        self.assertEqual((root/label/'long_spans.json').exists(),detailed)
                self.assertEqual(results[0],results[1]);self.assertEqual(results[1],results[2])

    def test_cycle_calibration_uses_real_fixed_bytes_and_backlogged_per_worker_cycles(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);pilot=corpus.build(generate_workload(parameters(2560,0,.05,horizon=.1)),'sleep')
            self.assertGreaterEqual(len(pilot['transactions']),128)
            class NanosecondClock(Clock):
                def wait(self,pipes,timeout):
                    before=self.now;result=super().wait(pipes,timeout)
                    if self.now==before and timeout>0:self.now+=1
                    return result
                def advance(self,seconds):
                    self.now+=max(1,round(seconds*1e9)) if seconds>0 else 0
            cp=corpus.write(pilot,root/'pilot.json');clock=NanosecondClock(duration=100_000);sent=[]
            clock.on_send=lambda message:sent.append(tuple(message[2:]))
            with clock.patches():
                result=cycle_calibration.calibrate_cycle(cp,2,root/'cycles',0,1280,30000,warmup=0,measurement=.2)
            genuine={corpus.signed_parts(e) for group in ('transactions','blocks') for e in pilot[group].values()}
            self.assertTrue(sent);self.assertTrue(set(sent)<=genuine)
            self.assertEqual(result['unbacklogged_successors'],0)
            with Path(result['samples']).open(newline='') as f:rows=list(csv.DictReader(f))
            self.assertEqual({r['job_class'] for r in rows},set(cycle_protocol.CLASSES))
            for r in rows:
                self.assertEqual(int(r['duration_ns']),int(r['next_send_ns'])-int(r['send_ns']))
                self.assertGreaterEqual(int(r['duration_ns']),int(r['occupancy_ns']))

    def test_policies_share_workload_but_replicates_do_not_and_budget_counts_one_copy(self):
        ref=cycle_protocol.cold_cycle_reference(1,dict.fromkeys(cycle_protocol.CLASSES,.001),.00001)
        a=dict(ref,backend='xmss',k=1,policy='fifo',rho_cold=.5,rho=.5,rate=10,period=12.8,dispatcher_utilisation=.0001)
        b=dict(a,policy='block_priority')
        self.assertEqual(cycle_runner.group_parameters(a,0),cycle_runner.group_parameters(b,0))
        self.assertNotEqual(cycle_runner.group_parameters(a,0)['run_id'],cycle_runner.group_parameters(a,1)['run_id'])
        sizes=dict(xmss=dict(compressed_bytes_per_tx=100,uncompressed_bytes_per_tx=200))
        p=cycle_protocol.volume_projection([a,b],sizes,secondary=False)
        self.assertEqual(len(p['groups']),3);self.assertAlmostEqual(p['uncompressed_bytes'],3*90*10*1.1*200)
        self.assertTrue(p['passed'])
        for left,right,expected in ((.49,.49,'AGREE-COLLAPSE'),(.9,.99,'AGREE-STABLE'),(.6,.9,'DISAGREE')):
            self.assertEqual(cycle_protocol.regime_category(left,right),expected)

    def test_cycle_guard_observed_empty_censored_and_queued_classes(self):
        def physical(c,n,worker):
            return [dict(job_id=c+str(i),job_class=c,worker_id=worker,send_ns=30_000_000_000+i*100_000_000,
                start_t=30+i*.1,end_t=30+i*.1+.05,enqueue_t=30+i*.1-.01,status='end') for i in range(n)]
        admission=physical('admission',101,0);low=physical('block_sig',3,1)
        logical=dict(job_id='logical',job_class='block_tx',block_id='B',status='cache_hit')
        waiting={j['job_id']:True for j in admission[:-1]+low[:-1]}
        cfg=dict(calibration_cycle_means=dict.fromkeys(cycle_protocol.CLASSES,.1));blocks=dict(B=dict(arrival_t=35))
        records=admission+low+[logical]
        r=cycle_validity.from_records(records,waiting,cfg,blocks)
        self.assertTrue(r['passed']);self.assertEqual(r['class_checks']['admission']['n'],100)
        self.assertEqual([r['class_checks'][c]['status'] for c in cycle_protocol.CLASSES],['TESTED-PASS','NOT OBSERVED','LOW-COUNT'])
        self.assertAlmostEqual(r['class_checks']['admission']['mean'],.1)
        bad=dict(calibration_cycle_means=dict(cfg['calibration_cycle_means'],admission=.2))
        r=cycle_validity.from_records(records,waiting,bad,blocks)
        self.assertFalse(r['passed']);self.assertEqual(r['class_checks']['admission']['status'],'TESTED-FAIL')
        r=cycle_validity.from_records(admission[:-1]+low+[logical],waiting,cfg,blocks)
        self.assertFalse(r['passed']);self.assertEqual(r['class_checks']['admission']['n'],99)
        self.assertEqual(r['class_checks']['admission']['status'],'LOW-COUNT')
        queued=dict(job_id='starved',job_class='block_sig',enqueue_t=35,start_t=None,end_t=None,status='queued')
        r=cycle_validity.from_records(admission+[logical,queued],waiting,cfg,blocks)
        self.assertFalse(r['passed']);self.assertTrue(r['class_checks']['block_sig']['starved'])
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);events=root/'events.csv';jobs=root/'jobs.csv';manifest=root/'manifest.json'
            with jobs.open('w',newline='') as f:
                w=csv.writer(f);w.writerow(['record']);w.writerows([[json.dumps(j)] for j in records])
            with events.open('w',newline='') as f:
                w=csv.writer(f);w.writerow(['event','job_id','q_admission','q_block'])
                w.writerows([['end',j['job_id'],int(waiting.get(j['job_id'],False)),0] for j in admission+low])
            manifest.write_text(json.dumps(dict(blocks=blocks)))
            self.assertEqual(cycle_validity.from_logs(events,jobs,cfg,manifest),cycle_validity.from_records(records,waiting,cfg,blocks))

if __name__=='__main__':unittest.main()
