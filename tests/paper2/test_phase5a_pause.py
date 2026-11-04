"""GC observer receipts, exact overlap arithmetic and killed-process recovery."""

from tests.paper2._provenance import setUpModule,tearDownModule

import gc
import json
from pathlib import Path
import statistics
import tempfile
import time
import unittest
from unittest.mock import patch

from src.paper2.prototype import pause_attribution as pa
from src.paper2.prototype import progress,runner


def callback_benchmark(directory,batches=5,per_batch=5000):
    """Synthetic direct start+stop pairs; includes both timestamp/buffer writes.

    Excludes collection work and buffer allocation/serialization. No GC control
    setting changes. These are benchmark records, not observed collections.
    """
    monitor=pa.PauseRecorder(directory,gc_capacity=batches*per_batch+1,span_capacity=1,step_capacity=1)
    info=dict(generation=0,collected=0,uncollectable=0);rows=[]
    for batch in range(batches):
        wall=time.perf_counter_ns();cpu=time.process_time_ns()
        for _ in range(per_batch):monitor.callback("start",info);monitor.callback("stop",info)
        rows.append(dict(batch=batch,wall_us_per_collection=(time.perf_counter_ns()-wall)/per_batch/1000,
                         cpu_us_per_collection=(time.process_time_ns()-cpu)/per_batch/1000))
    monitor.finish()
    return dict(purpose="SYNTHETIC callback overhead benchmark; not GC pause measurements",
        batches=rows,collections_per_batch=per_batch,callback_invocations_per_collection=2,
        median_wall_us=statistics.median(r["wall_us_per_collection"] for r in rows),
        mean_wall_us=statistics.fmean(r["wall_us_per_collection"] for r in rows),
        max_batch_wall_us=max(r["wall_us_per_collection"] for r in rows),
        passed=statistics.median(r["wall_us_per_collection"] for r in rows)<5)


def timeout_during_step(directory):
    p=progress.Progress(directory)
    recorder=pa.PauseRecorder(directory,gc_capacity=64,span_capacity=32,step_capacity=256)
    recorder.register();recorder.begin_span(0,"_receive",time.monotonic_ns())
    recorder.step(pa.CODES["completion_state"]);gc.collect(0)
    p.phase("workers_ready",workers=1)
    time.sleep(60)


class PauseAttribution(unittest.TestCase):
    def test_forced_collection_fields_callback_cleanup_and_settings_unchanged(self):
        thresholds=gc.get_threshold();enabled=gc.isenabled();callbacks=tuple(gc.callbacks)
        with tempfile.TemporaryDirectory() as td:
            monitor=pa.PauseRecorder(td,gc_capacity=64,span_capacity=16,step_capacity=64)
            with patch.object(gc,"set_threshold",side_effect=AssertionError("GC setting changed")), \
                 patch.object(gc,"disable",side_effect=AssertionError("GC disabled")), \
                 patch.object(gc,"freeze",side_effect=AssertionError("GC frozen")):
                monitor.register();cycle=[];cycle.append(cycle);del cycle
                gc.collect(0);monitor.finish()
            records=json.loads((Path(td)/"gc_pauses.json").read_text())["records"]
            self.assertTrue(any(r["generation"]==0 and r["complete"] for r in records))
            for r in records:
                self.assertEqual(set(r),{"start_ns","end_ns","generation","collected","uncollectable","complete"})
                self.assertGreaterEqual(r["end_ns"],r["start_ns"])
                self.assertGreaterEqual(r["collected"],0);self.assertGreaterEqual(r["uncollectable"],0)
            self.assertTrue((Path(td)/"long_spans.json").is_file())
            self.assertFalse(any((Path(td)/n).exists() for n in pa.FILES))
        self.assertEqual(gc.get_threshold(),thresholds);self.assertEqual(gc.isenabled(),enabled)
        self.assertEqual(tuple(gc.callbacks),callbacks)

    def test_callback_storage_is_preallocated_and_serializes_every_direct_pair(self):
        with tempfile.TemporaryDirectory() as td:
            monitor=pa.PauseRecorder(td,gc_capacity=16,span_capacity=1,step_capacity=1)
            original=monitor.gc.memory;size=len(original);info=dict(generation=1,collected=2,uncollectable=0)
            for _ in range(10):monitor.callback("start",info);monitor.callback("stop",info)
            self.assertIs(monitor.gc.memory,original);self.assertEqual(len(original),size)
            monitor.finish();r=json.loads((Path(td)/"gc_pauses.json").read_text())
            self.assertEqual(len(r["records"]),10)
            self.assertTrue(all(x["collected"]==2 and x["complete"] for x in r["records"]))

    def test_long_span_labels_and_exact_gc_first_partition(self):
        now=[100]
        with tempfile.TemporaryDirectory() as td,patch.object(pa.time,"monotonic_ns",side_effect=lambda:now[0]):
            monitor=pa.PauseRecorder(td,gc_capacity=16,span_capacity=16,step_capacity=64)
            monitor.register();monitor.begin_span(0,"_receive",now[0])
            now[0]=200;monitor.step(pa.CODES["cache_insert_evidence"])
            now[0]=300;monitor.callback("start",dict(generation=2))
            now[0]=500;monitor.callback("stop",dict(generation=2,collected=3,uncollectable=0))
            now[0]=600;monitor.step(pa.CODES["select_dispatch"])
            now[0]=2000100;monitor.end_span(now[0]);monitor.finish()
            g=json.loads((Path(td)/"gc_pauses.json").read_text());l=json.loads((Path(td)/"long_spans.json").read_text())
            self.assertEqual(len(l["spans"]),1);span=l["spans"][0]
            self.assertEqual(span["kind"],"_receive");self.assertEqual(span["duration_ns"],2000000)
            self.assertEqual([s["label"] for s in span["steps"]],["handler:_receive","cache_insert_evidence","select_dispatch"])
            result=pa.summarise(g,l,[],[(100,2000100)])
            self.assertEqual(result["gc_by_generation"]["2"]["total_ns"],200)
            self.assertEqual(result["gc_by_generation"]["2"]["collected"],3)
            self.assertEqual(result["gaps_over_1ms"]["gc_ns"],200)
            self.assertEqual(result["gaps_over_1ms"]["identified_step_ns"],1999800)
            self.assertEqual(result["gaps_over_1ms"]["unattributed_ns"],0)

    def test_overlap_shares_include_unattributed_without_double_counting(self):
        g=dict(records=[dict(start_ns=4000000,end_ns=6000000,generation=0,collected=0,uncollectable=0,complete=True)])
        l=dict(spans=[dict(steps=[dict(start_ns=2000000,end_ns=8000000,label="block_state")])])
        r=pa.summarise(g,l,[],[(0,10000000)])["gaps_over_1ms"]
        self.assertEqual((r["gc_share"],r["identified_step_share"],r["unattributed_share"]),(.2,.4,.4))
        self.assertEqual(r["gc_ns"]+r["identified_step_ns"]+r["unattributed_ns"],r["total_ns"])

    def test_killed_process_outputs_recovered_before_partial_copy(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/"source";evidence=root/"evidence"
            with self.assertRaisesRegex(TimeoutError,"last phase: workers_ready"):
                runner.fresh(timeout_during_step,(source,),20,progress_path=source/"progress.jsonl",
                    phase_timeouts={"preparation":.5,"prototype window":110,"serialisation":2},partial_dir=evidence)
            for directory in (source,evidence):
                g=json.loads((directory/"gc_pauses.json").read_text())
                l=json.loads((directory/"long_spans.json").read_text())
                self.assertTrue(g["partial"]);self.assertTrue(g["records"])
                self.assertTrue(l["partial"]);self.assertEqual(l["open_spans"][0]["kind"],"_receive")
                self.assertIsNone(l["open_spans"][0]["end_ns"])
                self.assertTrue(any(s["label"]=="handler:_receive" for s in l["open_spans"][0]["steps"]))

    def test_overflow_is_explicit_not_silent_collection_loss(self):
        with tempfile.TemporaryDirectory() as td:
            monitor=pa.PauseRecorder(td,gc_capacity=1,span_capacity=1,step_capacity=1)
            info=dict(generation=0,collected=0,uncollectable=0)
            for _ in range(2):monitor.callback("start",info);monitor.callback("stop",info)
            with self.assertRaisesRegex(BufferError,"overflow"):monitor.finish()
            self.assertTrue(json.loads((Path(td)/"gc_pauses.json").read_text())["overflow"])

    def test_early_timeout_without_initialized_buffers_is_not_zero_observations(self):
        with tempfile.TemporaryDirectory() as td:
            pa.recover(td,write_missing=True)
            g=json.loads((Path(td)/"gc_pauses.json").read_text())
            l=json.loads((Path(td)/"long_spans.json").read_text())
            self.assertTrue(g["partial"]);self.assertIn("error",g)
            self.assertEqual(pa.summarise(g,l,[],[])["status"],"UNAVAILABLE")

    def test_completed_snapshots_survive_timeout_during_buffer_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            monitor=pa.PauseRecorder(td,gc_capacity=16,span_capacity=16,step_capacity=64)
            monitor.register();gc.collect(0);monitor.finish()
            g=Path(td)/"gc_pauses.json";l=Path(td)/"long_spans.json";before=(g.read_bytes(),l.read_bytes())
            # Simulate a kill after unlinking only the first of three buffers.
            (Path(td)/pa.FILES[-1]).write_bytes(b"partially cleaned buffer")
            pa.recover(td,write_missing=True)
            self.assertEqual((g.read_bytes(),l.read_bytes()),before)

    def test_target_callback_cost_counts_and_dispatcher_share_by_hand(self):
        g=dict(records=[dict(start_ns=a,end_ns=b,complete=True) for a,b in ((110,120),(190,210),(90,105))])
        r=pa.estimate_overhead(g,dict(mean_per_call_ns=10),100,200,1000)
        self.assertEqual(r["total_capture_invocations"],6)
        self.assertEqual(r["timed_dispatcher_invocations"],4)
        self.assertEqual(r["estimated_timed_callback_ns"],40)
        self.assertEqual(r["estimated_dispatcher_share"],.04)

    def test_post_window_cost_calibration_is_reported_without_registering_callback(self):
        callbacks=tuple(gc.callbacks);thresholds=gc.get_threshold();enabled=gc.isenabled()
        r=pa.measure_callback_cost(batches=2,per_batch=10)
        self.assertEqual(len(r["batches"]),2);self.assertEqual(sum(x["callback_invocations"] for x in r["batches"]),40)
        self.assertGreaterEqual(r["mean_per_call_ns"],0);self.assertFalse(r["timing_assertion"])
        self.assertEqual(tuple(gc.callbacks),callbacks);self.assertEqual(gc.get_threshold(),thresholds)
        self.assertEqual(gc.isenabled(),enabled)
