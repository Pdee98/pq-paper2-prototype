"""Recorded fake-worker timing, slicing, no-prefetch and independent idle guard."""

from tests.paper2._provenance import setUpModule,tearDownModule

import csv
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.model.engine import run_model
from src.paper2.prototype import analysis,corpus,diagnostic,replay,runtime
CompletionFirstModel=runtime.CompletionFirstModel
from src.paper2.prototype.validity import Validity,from_events
from src.paper2.verify.invariants import check
from tests.paper2._support import config
from tests.paper2.test_phase5a_dispatcher import decisions


class Clock:
    """Exact fake timestamps; no live OS sleeps/worker races in equivalence."""
    def __init__(self,duration=10_000_000):self.now=0;self.sends=[];self.on_send=None;self.duration=duration
    def advance(self,seconds):self.now+=round(seconds*1e9)
    def workers(self,k,*args):
        clock=self
        class Pipe:
            reply=None
            def send(self,message):
                if self.reply is not None:raise AssertionError("worker prefetched")
                if clock.on_send:clock.on_send(message)
                clock.sends.append((message[1],clock.now))
                self.reply=("result",message[1],clock.now,clock.now+clock.duration,True)
            def poll(self):return self.reply is not None and self.reply[3]<=clock.now
            def recv(self):
                if not self.poll():raise AssertionError("early receive")
                result=self.reply;self.reply=None;return result
        class Workers:
            def __init__(self):
                self.pipes=[Pipe() for _ in range(k)];self.metadata=[];self.clock_records=[]
                self.handshake("before")
            def handshake(self,phase):
                for w in range(k):self.clock_records.append(dict(worker_id=w,phase=phase,
                    probes=[dict(dispatcher_before_ns=clock.now,dispatcher_after_ns=clock.now,
                    worker_ns=clock.now,offset_ns=0,uncertainty_ns=0)]))
            def close(self):pass
        return Workers()
    def wait(self,pipes,timeout):
        target=min(self.now+round(timeout*1e9),min(p.reply[3] for p in pipes))
        self.now=target;return [p for p in pipes if p.poll()]
    def patches(self):
        from contextlib import ExitStack
        stack=ExitStack()
        for obj,name,value in ((runtime,"Workers",self.workers),(runtime.time,"monotonic_ns",lambda:self.now),
                               (runtime.time,"sleep",self.advance),(runtime,"wait",self.wait)):
            stack.enter_context(patch.object(obj,name,side_effect=value))
        return stack


class Deviation5(unittest.TestCase):
    def fixture(self,policy,k=1):
        return config(k=k,policy=policy,
            admissions=[dict(tx_id=x,arrival_t=0) for x in ("a","b","c","d")],
            blocks=[dict(block_id="B",tx_ids=["a","b"]),dict(block_id="C",tx_ids=["c","d"])],
            block_times=[0,.1],cache=dict(capacity=32,ttl=100),
            pool=dict(enabled=True,capacity_bytes=100000))

    def test_recorded_timings_decisions_old_and_simulator_fifo_p2_p4(self):
        for policy in (dict(name="fifo"),dict(name="block_priority"),dict(name="priority_floor",beta=.25,W=.1)):
            with self.subTest(policy=policy),tempfile.TemporaryDirectory() as td:
                root=Path(td);doc=corpus.build(self.fixture(policy,2),"sleep");cp=corpus.write(doc,root/"corpus.json")
                logs=[]
                for label,kind in (("old",runtime.PreDeviation5Model),("new",runtime.CompletionFirstModel)):
                    clock=Clock()
                    with clock.patches():
                        e,m=run_model(dict(doc["workload"],output_dir=str(root/label)),
                            model_type=lambda cfg:kind(cfg,cp,.01))
                    self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
                    logs.append((e,m,clock.sends))
                self.assertEqual(decisions(logs[0][0]),decisions(logs[1][0]))
                self.assertEqual(logs[0][2],logs[1][2])
                sample=analysis.samples_from_jobs(logs[1][0].parent/"jobs.csv",root/"samples.csv","sleep","fixture")
                e,m=analysis.paired(dict(doc["workload"],output_dir=str(root/"sim")),cp,sample,"sleep",0,0)
                self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
                self.assertEqual(decisions(logs[1][0]),decisions(e))
                self.assertEqual(json.loads(logs[1][1].read_text())["prototype"]["validity"],
                                 from_events(logs[1][0],doc["workload"]))

    def test_successor_sent_before_evidence_commits_and_no_prefetch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(dict(name="fifo")),"sleep");cp=corpus.write(doc,root/"corpus.json")
            clock=Clock();holder=[];observed=[]
            def create(cfg):
                m=runtime.CompletionFirstModel(cfg,cp,.01);holder.append(m);return m
            def sending(message):
                m=holder[0]
                if m.completion_evidence is not None:
                    self.assertTrue(any(x[0]=="row" and x[1][2]=="end" for x in m.completion_evidence))
                    self.assertNotIn("end",[m.event_writer.records[i][2] for i in range(m.event_writer.count)])
                    observed.append(message[1]);clock.on_send=None
            clock.on_send=sending
            with clock.patches():e,m=run_model(dict(doc["workload"],output_dir=str(root/"run")),model_type=create)
            self.assertTrue(observed);self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
            model=holder[0];job=next(iter(model.jobs.values()));model.pending_sends.add(0)
            with self.assertRaisesRegex(AssertionError,"no prefetch"):model._start(job,0)

    def test_slices_service_results_without_exposing_unprocessed_block_jobs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(dict(name="fifo")),"sleep");cp=corpus.write(doc,root/"corpus.json")
            clock=Clock(duration=100_000);audit=[];eligible={}
            class Sliced(CompletionFirstModel):
                SLICE_NS=100_000
                def _new_job(self,*args,**kw):
                    if self.epoch is not None:clock.now+=80_000
                    job=super()._new_job(*args,**kw)
                    audit.append((job.job_id,clock.now));return job
                def _enqueue(self,job):
                    # No job is eligible until its per-item processing finished.
                    self_test.assertNotIn(job.job_id,self.pool.waiting.items)
                    self_test.assertNotIn(job.job_id,{j.job_id for j in self.pool.running.values()})
                    eligible[job.job_id]=clock.now
                    super()._enqueue(job)
            self_test=self
            with clock.patches():e,m=run_model(dict(doc["workload"],output_dir=str(root/"run")),
                model_type=lambda cfg:Sliced(cfg,cp,.01))
            self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
            with e.open(newline="") as stream:rows=list(csv.DictReader(stream))
            created=dict(audit)
            for r in rows:
                if r["event"]=="enqueue":
                    self.assertGreaterEqual(int(r["monotonic_ns"]),created[r["job_id"]])
                    self.assertEqual(int(r["monotonic_ns"]),eligible[r["job_id"]])
            spans=json.loads((e.parent/"dispatcher_spans.json").read_text())
            self.assertGreater(sum(s["kind"]=="_block" for s in spans),2)
            self.assertEqual([s["id"] for s in spans],list(range(len(spans))))
            self.assertTrue(all(a["end_ns"]<=b["start_ns"] for a,b in zip(spans,spans[1:])))
            block_arrive=int(next(r for r in rows if r["event"]=="block_arrive")["monotonic_ns"])
            last_create=created["block:0:sig"]
            self.assertTrue(any(s["kind"]=="_receive" and block_arrive<s["start_ns"]<last_create for s in spans))

    def test_guard_hand_calculated_gap_idle_fraction_censor_and_split(self):
        v=Validity(1,window=(0,10))
        v.observe(0,"start",0,0,1,0,0)
        v.observe(1,"enqueue",1,0,1)
        v.observe(2,"end",1,0,0,0,receive_ns=2_000_000_000)
        v.observe(2.0005,"start",0,0,1,0,2_000_500_000)
        v.observe(4,"end",0,0,0,0,receive_ns=4_000_000_000)
        r=v.report(10,final=True)
        self.assertAlmostEqual(r["idle_while_waiting_worker_seconds"],.0005,places=12)
        self.assertAlmostEqual(r["idle_fraction"],.00005,places=12)
        self.assertEqual(r["p99_dispatch_gap_ns"],500000);self.assertTrue(r["passed"])
        v=Validity(1,window=(0,10));v.observe(0,"start",0,0,1,0,0)
        v.observe(1,"end",1,0,0,0,receive_ns=1_000_000_000)
        self.assertFalse(v.report(10,final=True)["passed"])
        v.observe(1.6,"start",0,0,1,0,1_600_000_000)
        r=v.report(10,final=True);self.assertAlmostEqual(r["idle_fraction"],.06)
        self.assertEqual(r["p99_dispatch_gap_ns"],600000000);self.assertFalse(r["passed"])
        s=Validity(2,"split",1,(0,10));s.observe(0,"start",0,1,1,1,0)
        self.assertEqual(s.report(10,final=True)["idle_fraction"],0)

    def test_invalid_repetition_is_not_compared(self):
        index=dict(runs=[dict(run_id="r0",cell_id=0,replicate=0,manifest_sha256="a")],
            cells=[dict(dispatcher_utilisation=.1)],excluded_cells=[],code_commit="b",source_run_id="1")
        result=dict(run_id="r0",cell_id=0,replicate=0,input_sha256="a",code_commit="b",source_run_id="1",
            prototype=dict(validity=dict(passed=False,idle_fraction=.06,p99_dispatch_gap_ns=2000000)))
        from src.paper2.prototype import g3_decision
        with patch.object(g3_decision,"compare",side_effect=AssertionError("invalid run compared")) as comparison:
            r=replay.gather_records(index,[result])
        comparison.assert_not_called()
        # Deviation 8 D2: no invariant/band failures; fewer than three valid comparisons is INCONCLUSIVE.
        self.assertEqual(r["status"],"inconclusive");self.assertEqual(r["invalid_runs"],["r0"])
        self.assertEqual(r["failures"],[])
        self.assertNotIn("primary",r["per_repetition"][0])

    def test_diagnostic_v2_retains_workload_identity_and_stop_rules(self):
        self.assertEqual(diagnostic.PURPOSE,"DIAGNOSTIC v5")
        self.assertEqual(diagnostic.RUN_ID,"paper2-g3-diag-v5")
        self.assertEqual(diagnostic.CELL0["rate"],1115.433019832252)
        self.assertFalse(diagnostic.may_prepare_validation(True,.2,.3,.95,1,[]))
        p=diagnostic.projection_historical()
        self.assertEqual(p["paired_with_run"],"41717858838")
        self.assertAlmostEqual(p["v2_projection"]["projected_seconds_to_prototype_exit"],968.87858563125)
        self.assertEqual(p["diagnostic_stage_timeouts_seconds"],diagnostic.TIMEOUTS)

    def test_helper_import_order_without_site_packages(self):
        r=subprocess.run([sys.executable,"-B","-S","-c",
            "import src.paper2.prototype.dispatch_runtime; import src.paper2.prototype.runtime"],
            capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_progress_reports_guard_and_online_equals_csv(self):
        from src.paper2.prototype.progress import read_progress
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);cfg=self.fixture(dict(name="fifo"));cfg["block_times"]=[0,1.1]
            doc=corpus.build(cfg,"sleep");cp=corpus.write(doc,root/"corpus.json");clock=Clock()
            with clock.patches(),patch.object(runtime,'RealtimeModel',runtime.CompletionFirstModel):e,m=runtime.run(dict(doc["workload"],output_dir=str(root/"run")),cp)
            phases=read_progress(e.parent/"progress.jsonl")
            self.assertTrue(all("prototype_validity" in r for r in phases if r["phase"]=="second"))
            guard=next(r for r in phases if r["phase"]=="prototype_validity")
            expected=from_events(e,doc["workload"])
            for name,value in expected.items():self.assertEqual(guard[name],value)

    def test_ttl_slices_publish_removals_before_yield(self):
        from src.paper2.prototype.dispatch_runtime import SlicedCache
        from src.paper2.state import SignatureCache
        class Owner:
            completion_evidence=None;t=1.;maintenance_context=(None,"positive")
            events=[];checkpoints=[]
            def _log(self,event,job,**extra):self.events.append((event,extra["cache_key"]))
            def _checkpoint(self,reason):self.checkpoints.append(len(self.events))
        owner=Owner();cache=SignatureCache(100,ttl=.1)
        for i in range(5):cache.insert(str(i),str(i),0,("domain","param"))
        cache.__class__=SlicedCache;cache.owner=owner
        entry,removed=cache.lookup("missing",1,("domain","param"))
        self.assertIsNone(entry);self.assertEqual(removed,[])
        self.assertEqual(owner.checkpoints,[1,2,3,4,5])
        self.assertEqual(owner.events,[("cache_evict",str(i)) for i in range(5)])
