"""GC lifecycle, fail-closed memory, calibration slots and diagnostic v4."""
from tests.paper2._provenance import setUpModule,tearDownModule
import csv
import gc
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.prototype import gc_control as g, calibration_split, corpus, runtime, cycle_calibration
from src.paper2.prototype import cycle_diagnostic_v4 as v4
from src.paper2.prototype import replay
from src.paper2.prototype.pause_attribution import PauseRecorder
from src.paper2.model.engine import run_model
from src.paper2.verify.invariants import check
from tests.paper2.test_phase5a_deviation5 import Clock
from tests.paper2 import test_phase5a_deviation5 as previous
from tests.paper2.test_phase5a_dispatcher import decisions
from src.paper2.workload import generate_workload
from src.paper2.prototype.runner import parameters


class Deviation7(unittest.TestCase):
    def test_decisions_match_exact_b3d0884_bundle_fixtures(self):
        # Generated independently from git archive b3d0884be69f84a5c964c2152f554421855628d2.
        # SHA-256 covers canonical {decisions, sends}, including job/worker order.
        # Fresh signing keys change opaque digests: map each digest to its tx
        # identity, preserving all equality relationships and cache/pool events.
        references=[('928c22fe77deb7a342d4cb676ebdddfc9cbc570a2b1efbcc03e0348b22d427f5',dict(name='fifo')),
                    ('1ed61ab5555b81851a735751fdfafccfe472fe20166d81e91f0aa3ec8e50f56b',dict(name='block_priority')),
                    ('9f7d8e8af118b29b2a09deab3cbff4e483ba96db9441a9a7ca14c9f23d942916',dict(name='priority_floor',beta=.25,W=.1))]
        for expected,policy in references:
            with self.subTest(policy=policy),tempfile.TemporaryDirectory() as td:
                root=Path(td);doc=corpus.build(previous.Deviation5().fixture(policy,2),'sleep');cp=corpus.write(doc,root/'corpus.json');clock=Clock()
                with clock.patches():e,m=run_model(dict(doc['workload'],output_dir=str(root/'run')),model_type=lambda c:runtime.RealtimeModel(c,cp,.01))
                self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
                mapping={entry['cache_key']:'transaction-key:'+identity for identity,entry in doc['transactions'].items()}
                rows=[tuple(mapping.get(value,value) if i==11 else value for i,value in enumerate(row)) for row in decisions(e)]
                raw=json.dumps(dict(decisions=rows,sends=clock.sends),sort_keys=True,separators=(',',':')).encode()
                self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)

    def test_gc_exact_window_freeze_and_post_drain_pause(self):
        initial=gc.isenabled();thresholds=gc.get_threshold()
        with tempfile.TemporaryDirectory() as td:
            monitor=PauseRecorder(td,detailed=False);control=g.WindowGC(td,monitor)
            try:
                control.enter();self.assertFalse(gc.isenabled());self.assertGreater(gc.get_freeze_count(),0)
                control.leave();self.assertEqual(gc.isenabled(),initial)
            finally:control.leave(partial=True);monitor.finish()
            rows=json.loads((Path(td)/'gc_state.json').read_text())['transitions']
            self.assertEqual([r['phase'] for r in rows],['created','preparation_collect','frozen','loop_entry','drain_end','post_drain_collect','restored'])
            self.assertFalse(next(r for r in rows if r['phase']=='loop_entry')['enabled'])
            self.assertFalse(next(r for r in rows if r['phase']=='drain_end')['enabled'])
            pauses=json.loads((Path(td)/'gc_pauses.json').read_text())['records']
            self.assertEqual(len(pauses),1);self.assertEqual(pauses[0]['generation'],2)
        self.assertEqual(gc.get_threshold(),thresholds)

    def test_memory_strict_boundaries_and_persisted_invalid_evidence(self):
        sample=dict(parent_pid=1,rss_bytes={'1':g.PROCESS_LIMIT,'2':123},available_bytes=g.AVAILABLE_MINIMUM,total_bytes=32*g.GIB)
        self.assertEqual(g.memory_failures(sample),[])
        self.assertTrue(g.memory_failures(dict(sample,rss_bytes={'2':g.PROCESS_LIMIT+1})))
        self.assertTrue(g.memory_failures(dict(sample,available_bytes=g.AVAILABLE_MINIMUM-1)))
        from src.paper2.prototype.progress import Progress
        with tempfile.TemporaryDirectory() as td:
            progress=Progress(td)
            try:
                with patch.object(g,'memory_snapshot',return_value=dict(sample,available_bytes=0)):
                    with self.assertRaises(g.MemoryStop):g.MemorySampler(progress,td,[2]).sample()
                self.assertEqual(json.loads((Path(td)/'memory-stop.json').read_text())['status'],'INVALID')
                self.assertIn('memory_stop',(Path(td)/'progress.jsonl').read_text())
            finally:progress.close()

    def test_gc_control_and_memory_stop_in_runtime_preserve_receipts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(previous.Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json')
            clock=Clock();observed=[];clock.on_send=lambda _:observed.append(gc.isenabled())
            with clock.patches():
                e,m=runtime.run(dict(doc['workload'],output_dir=str(root/'ok')),cp,sleep_seconds=.01)
            self.assertTrue(observed);self.assertFalse(any(observed));self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
            rows=[json.loads(line) for line in (root/'ok/progress.jsonl').read_text().splitlines()]
            self.assertTrue(any(r['phase']=='memory' and 'rss_bytes' in r for r in rows))
            clock=Clock()
            with clock.patches(),patch.object(g,'memory_snapshot',return_value=dict(rss_bytes={'1':1},available_bytes=0,total_bytes=32*g.GIB)):
                with self.assertRaises(g.MemoryStop):runtime.run(dict(doc['workload'],output_dir=str(root/'invalid')),cp)
            for name in ('progress.jsonl','gc_state.json','gc_pauses.json','memory-stop.json'):
                self.assertTrue((root/'invalid'/name).is_file(),name)

    def test_calibration_gc_disabled_and_diagnostic_span_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(generate_workload(parameters(2560,0,.05,horizon=.1)),'sleep');cp=corpus.write(doc,root/'pilot.json')
            class FineClock(Clock):
                def advance(self,seconds):self.now+=max(1,round(seconds*1e9)) if seconds>0 else 0
                def wait(self,pipes,timeout):
                    before=self.now;result=super().wait(pipes,timeout)
                    if self.now==before and timeout>0:self.now+=1
                    return result
            clock=FineClock(duration=100000);states=[];clock.on_send=lambda _:states.append(gc.isenabled())
            with clock.patches():
                result=cycle_calibration.calibrate_cycle(cp,2,root/'cycle',0,1280,30000,0,.2,True,'-v4')
            self.assertTrue(states);self.assertFalse(any(states));self.assertEqual(result['unbacklogged_successors'],0)
            for name in ('events.csv','jobs.csv','dispatcher_spans.json','long_spans.json','gc_pauses.json','gc_state.json','progress.jsonl'):
                self.assertTrue((root/'cycle'/name).is_file(),name)

    def test_split_slots_are_disjoint_deterministic_and_reject_wrong_repetitions(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);paths=[]
            for rep in range(3):
                file=root/f'r{rep}.csv'
                with file.open('w',newline='') as stream:
                    writer=csv.writer(stream);writer.writerow(['source','duration_ns']);writer.writerow([f'concurrency-cycle-k1-rep{rep}',rep+1])
                paths.append(file)
            a=calibration_split.split_samples(paths,root/'a');b=calibration_split.split_samples(paths,root/'b')
            for name in a:self.assertEqual(Path(a[name]).read_bytes(),Path(b[name]).read_bytes())
            calibration_split.verify_slots(a['primary_cycle_samples'],a['held_out_cycle_samples'])
            with self.assertRaises(ValueError):calibration_split.verify_slots(a['primary_cycle_samples'],a['primary_cycle_samples'])
            with self.assertRaises(ValueError):calibration_split.split_samples(paths[::-1],root/'wrong')

    def test_v4_fresh_identity_three_cells_and_projection(self):
        self.assertEqual(v4.RUN_ID,'paper2-g3-diag-v4')
        self.assertEqual(v4.CASES,(('xmss',1),('xmss',2),('ml_dsa_44',1)))
        self.assertNotEqual(v4.parameters(10,12.8)['run_id'],'paper2-g3-diag-v3')
        p=v4.projection();self.assertEqual(len(p['runs']),3)
        self.assertLess(p['projected_seconds'],165*60)
        self.assertEqual(p['stage_timeouts_seconds']['prototype window'],110)
        small=v4.parameters(40,.5,.8);workload=generate_workload(small)
        self.assertEqual(v4.message_counts(small),(len(workload['transactions']),len(workload['blocks'])))

    def test_packet_retains_separate_calibration_slots_and_gc_receipts(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(previous.Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json')
            cfg=dict(doc['workload'],output_dir=str(root/'run'),g3_input_version=6,
                     calibration_cycle_means=dict.fromkeys(('admission','block_tx','block_sig'),.01))
            clock=Clock()
            with clock.patches():e,m=runtime.run(cfg,cp)
            paths=[]
            for rep in range(3):
                path=root/f'r{rep}.csv';paths.append(path)
                with path.open('w',newline='') as stream:
                    writer=csv.writer(stream);writer.writerow(['source','backend','duration_ns','job_class','operation','variant'])
                    for cls in ('admission','block_tx','block_sig'):writer.writerow([f'concurrency-cycle-k1-rep{rep}','sleep:'+cls,10000000,cls,'verify','valid'])
            slots=calibration_split.split_samples(paths,root/'split');packet=root/'packet'
            replay.create_packet(packet,cfg,cp,dict(events=str(e),manifest=str(m)),slots['held_out_cycle_samples'],
                dict(k=1,g3_input_version=6),0,primary=slots['primary_cycle_samples'])
            self.assertEqual((packet/'primary.csv').read_bytes(),Path(slots['primary_cycle_samples']).read_bytes())
            self.assertEqual((packet/'held-out.csv').read_bytes(),Path(slots['held_out_cycle_samples']).read_bytes())
            self.assertTrue((packet/'prototype/gc_state.json').is_file());replay.verify_files(packet,'REPLAY_MANIFEST.json')
            self.assertEqual(replay.read(packet/'info.json')['calibration_slots'],dict(primary=[0,1],held_out=[2],rate_stationarity=[0,1,2]))

    def test_v4_collector_calibrates_both_backends_skips_without_retuning(self):
        from src.paper2.prototype.cycle_protocol import cold_cycle_reference
        from src.paper2.prototype import diagnostic
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);replay.save(root/'conformance.json',{});replay.save(root/'host.json',dict(memory=dict(total_bytes=16*g.GIB)))
            doc=corpus.build(previous.Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'full.json');calls=[];calibrated=[]
            def calibration(backend,*args,**kw):
                calibrated.append((backend,kw))
                return {k:dict(cold_cycle_reference(k,dict.fromkeys(('admission','block_tx','block_sig'),.1),.9 if backend=='ml_dsa_44' else .001),
                               primary_cycle_samples='primary.csv',held_out_cycle_samples='held-out.csv') for k in (1,2)}
            def fresh(function,args,timeout,**kw):
                calls.append((function,args))
                return dict(path=str(cp),sha256='a'*64,transactions=4) if function is v4.presign else dict(events='unused',manifest='unused')
            def packet(directory,*args,**kw):
                replay.save(Path(directory)/'info.json',dict(arm_corpus_audit=dict(checked=4)));return 'b'*64
            with patch.object(diagnostic,'preflight'),patch.object(v4,'calibrate_backend',side_effect=calibration), \
                 patch.object(v4.runner,'fresh',side_effect=fresh),patch.object(v4,'projection',return_value={}), \
                 patch.object(v4.public_corpus,'write_archive',return_value=dict(compressed_bytes=1000,uncompressed_bytes=2000)), \
                 patch.object(v4.public_corpus,'audit_upload',return_value={}),patch.object(replay,'create_packet',side_effect=packet):
                v4.collect(root)
            self.assertEqual([b for b,kw in calibrated],['xmss','ml_dsa_44'])
            self.assertTrue(all(kw['diagnostic'] and kw['seed_tag']=='-'+v4.RUN_ID for b,kw in calibrated))
            state=replay.read(root/'protocol.json');self.assertEqual(len(state['runs']),2);self.assertEqual(len(state['skipped_cells']),1)
            self.assertEqual(state['skipped_cells'][0]['cell']['rho_cold'],.85)
            self.assertIn('pending replay',state['status'])
            for function,args in calls:
                if function is v4.presign:self.assertEqual(args[0]['run_id'],v4.RUN_ID)


if __name__=='__main__':unittest.main()
