"""Literal decisions and safety checks, using finite unit workloads only."""

from tests.paper2._provenance import setUpModule, tearDownModule

import dataclasses
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.paper2.model import run_model
from src.paper2.model.engine import Model, _git_state
from src.paper2.policies import (Policy, View, WaitingJob, RunningJob, PendingBlock,
                                  immutable_estimates, slack)
from src.paper2.workload import generate_workload
from tests.paper2._phase2_support import generator_parameters
from tests.paper2.test_phase1_service_times import selector
from tests.paper2._support import config, check_trace


SPECS = [dict(name="fifo"), dict(name="block_priority"), dict(name="static_split", k_a=1, k_b=1),
         dict(name="priority_floor", beta=0.4, W=5),
         dict(name="deadline_slack", beta=0.2, W=5, m=1)]


def waiting(jid, cls="admission", t=0, bid="", fee=1):
    return WaitingJob(jid, cls, bid, t, 10-t, fee if cls == "admission" else None,
                      249 if cls == "admission" else None)


def view(jobs, blocks=(), running=(), k=1, admission_busy=0, total_busy=0, estimates=None):
    return View(tuple(jobs), tuple(blocks), k, (0,), ("shared",) * k, tuple(running),
                immutable_estimates(estimates or dict(admission=1, block_tx=2, block_sig=4)),
                admission_busy, total_busy)


class Phase3Policies(unittest.TestCase):
    def run_case(self, settings):
        with tempfile.TemporaryDirectory(prefix="paper2-policies-") as directory:
            settings = dict(settings, output_dir=directory)
            paths = run_model(settings)
            full = run_model(dict(settings, policy_view="full", output_dir=str(Path(directory)/"full")))
            self.assertEqual(paths[0].read_bytes(), full[0].read_bytes())
            self.assertEqual((paths[0].parent/"jobs.csv").read_bytes(), (full[0].parent/"jobs.csv").read_bytes())
            return check_trace(self, *paths, settings["k"])

    def test_p2_literal_starvation_during_continuous_block_work(self):
        rows, _ = self.run_case(config(policy=dict(name="block_priority"),
            admissions=[dict(tx_id="busy", arrival_t=0), dict(tx_id="a", arrival_t=0.1)],
            service=dict(mode="constant", seconds=dict(admission=2, block_tx=1, block_sig=1)),
            block_start=0.5, block_period=1, blocks=[dict(block_id=f"B{i}", tx_ids=[]) for i in range(4)]))
        self.assertEqual([(float(r["t"]), r["job_id"]) for r in rows if r["event"] == "start"],
                         [(0, "admission:0"), (2, "block:0:sig"), (3, "block:1:sig"),
                          (4, "block:2:sig"), (5, "block:3:sig"), (6, "admission:1")])

    def test_p3_no_lending_both_directions_literal(self):
        spec = dict(name="static_split", k_a=1, k_b=1)
        for admissions, blocks, expected in [
            ([dict(tx_id=str(i), arrival_t=0) for i in range(3)], [],
             [(0, "admission:0", 0), (1, "admission:1", 0), (2, "admission:2", 0)]),
            ([], [dict(block_id=str(i), tx_ids=[]) for i in range(3)],
             [(0, "block:0:sig", 1), (1, "block:1:sig", 1), (2, "block:2:sig", 1)])]:
            rows, _ = self.run_case(config(k=2, policy=spec, admissions=admissions, blocks=blocks, block_period=0.01))
            self.assertEqual([(float(r["t"]), r["job_id"], int(r["worker_id"])) for r in rows if r["event"] == "start"], expected)
        with self.assertRaises(ValueError):
            Model(config(k=1, policy=spec))

    def test_p4_literal_floor_decisions_and_logged_share(self):
        rows, _ = self.run_case(config(policy=dict(name="priority_floor", beta=0.5, W=10),
            admissions=[dict(tx_id=str(i), arrival_t=0.1) for i in range(3)],
            blocks=[dict(block_id=f"B{i}", tx_ids=[]) for i in range(4)], block_period=0.1))
        decisions = [r for r in rows if r["event"] == "dispatch"]
        self.assertEqual([(float(r["t"]), r["chosen_job_id"]) for r in decisions],
                         [(0, "block:0:sig"), (1, "admission:0"), (2, "block:1:sig"),
                          (3, "admission:1"), (4, "block:2:sig"), (5, "admission:2"), (6, "block:3:sig")])
        self.assertEqual([float(r["share"]) for r in decisions], [0, 0, 0.5, 1/3, 0.5, 0.4, 0.5])
        for r in decisions:
            self.assertAlmostEqual(float(r["deficit"]), max(0, 0.5-float(r["share"])))

    def test_window_edge_and_running_work_hand_computed(self):
        model = Model(config(k=3, policy=dict(name="priority_floor", beta=0.7, W=5)))
        # At t=10 the window is (5,10]. Completed admission [1,7] contributes 2;
        # running admission [8,10] contributes 2; running block [9,10] contributes 1.
        model.t = 10
        for t, a, total in [(1,1,1),(2,0,1),(4,0,-1),(7,-1,-1),(8,1,1),(9,0,1)]:
            model.window.change(t,a,total)
        a = model._new_job("a", "admission", next(iter(Model(config(admissions=[dict(tx_id="a", arrival_t=0)])).transactions.values())))
        b = model._new_job("b", "block_sig")
        a.start_t, b.start_t = 8, 9
        model.pool.running = {0: a, 1: b}
        snapshot = model._view()
        self.assertEqual((snapshot.admission_busy, snapshot.total_busy, snapshot.share), (4, 5, 0.8))
        # A completed long admission alone straddles the edge: overlap is 2, not 6.
        model.window.change(10,-1,-1)
        # Remove the [8,10] admission contribution for this separate hand case.
        from src.paper2.model.dispatch_state import BusyWindow
        model.window = BusyWindow(5)
        for t,a,total in [(1,1,1),(7,-1,-1),(9,0,1)]: model.window.change(t,a,total)
        model.pool.running = {1: b}
        snapshot = model._view()
        self.assertEqual((snapshot.admission_busy, snapshot.total_busy, snapshot.share), (2, 3, 2/3))

    def test_p5_class_specific_slack_boundary_two_blocks_and_fee(self):
        a = waiting("a", fee=1)
        x, y, sig = waiting("x", "block_tx", bid="B"), waiting("y", "block_tx", bid="B"), waiting("sig", "block_sig", bid="B")
        running = RunningJob("r", "block_tx", "B", 1, 0.5)
        # k=2, est_tx=2, est_sig=4: waiting_work=8, residual=1.5.
        # now=10: deadline 16.51 => slack 1.01; 16.49 => .99; m=1.
        p = Policy(dict(name="deadline_slack", beta=0, W=5, m=1), 2)
        for deadline, expected, expected_slack in [(16.51, "a", 1.01), (16.49, "x", 0.99), (16.5, "a", 1)]:
            block = PendingBlock("B", 0, deadline, (x, y, sig), (running,))
            v = view([a, x, y, sig], [block], [running], k=2)
            self.assertAlmostEqual(slack(block, 10, v), expected_slack)
            self.assertEqual(p.choose(10, v), expected)
        z = waiting("z", "block_sig", bid="C")
        b = PendingBlock("B", 0, 16.49, (x, y, sig), (running,))
        c = PendingBlock("C", 1, 11, (z,), ())  # slack=-1, smallest.
        self.assertEqual(p.choose(10, view([a, x, y, sig, z], [b, c], k=2)), "z")
        fee = Policy(dict(name="deadline_slack", beta=0, W=5, m=1, admission_order="fee"), 1)
        self.assertEqual(fee.choose(10, view([a, waiting("rich", t=1, fee=9), waiting("tie", t=2, fee=9)])), "rich")
        settings = config(policy=dict(name="deadline_slack", beta=0, W=5, m=1, admission_order="fee"),
            admissions=[dict(tx_id="busy", arrival_t=0), dict(tx_id="low", arrival_t=0.1),
                        dict(tx_id="rich", arrival_t=0.2), dict(tx_id="tie", arrival_t=0.3)])
        for name, rate in (("low",1),("rich",9),("tie",9)):
            settings["transactions"][name]["fee_rate"] = rate
        rows, _ = self.run_case(settings)
        self.assertEqual([(float(r["t"]),r["job_id"]) for r in rows if r["event"] == "start"],
                         [(0,"admission:0"),(1,"admission:2"),(2,"admission:3"),(3,"admission:1")])
        with self.assertRaises(ValueError):
            Model(config(k=2, pool_mode="split", k_a=1, k_b=1, policy=dict(name="deadline_slack", beta=0, W=5, m=1)))

    def test_hidden_fields_absent_and_view_immutable(self):
        model = Model(config(admissions=[dict(tx_id="a", arrival_t=0)]))
        model.run()
        v = view([waiting("a")])
        for obj in (v, v.waiting[0], RunningJob("r", "block_tx", "B", 0, 0)):
            for attribute in ("service_time", "outcome", "sig_label", "future_arrivals"):
                with self.assertRaises(AttributeError):
                    getattr(obj, attribute)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            v.waiting[0].job_id = "changed"
        with self.assertRaises(TypeError):
            v.estimates["admission"] = 99
        class CheatingPolicy:
            def choose(self, now, snapshot):
                return snapshot.waiting[0].service_time
        with self.assertRaises(AttributeError):
            CheatingPolicy().choose(0, v)

    def test_completed_only_ewma_and_promoted_class(self):
        settings = config(admissions=[dict(tx_id="busy", arrival_t=0), dict(tx_id="a", arrival_t=0.1)],
            block_start=0.5, blocks=[dict(block_id="B", tx_ids=["a"])], coalesce_inflight=True,
            ewma_alpha=0.5, initial_estimates=dict(admission=10, block_tx=20, block_sig=30),
            service=dict(mode="constant", seconds=dict(admission=2, block_tx=7, block_sig=1)))
        _, data = self.run_case(settings)
        self.assertEqual(data["final_estimates"], dict(admission=6, block_tx=11, block_sig=15.5))

    def test_p5_dispatch_estimates_and_slack_are_logged(self):
        rows, _ = self.run_case(config(policy=dict(name="deadline_slack", beta=0, W=5, m=1),
            deadline=10, initial_estimates=dict(admission=1, block_tx=2, block_sig=4), ewma_alpha=0.5,
            blocks=[dict(block_id="B", tx_ids=["a"])]))
        first, second = [r for r in rows if r["event"] == "dispatch"]
        self.assertEqual((float(first["est_block_tx"]), float(first["est_block_sig"]),
                          float(first["min_slack"]), first["min_slack_block_id"]), (2, 4, 8, "B"))
        self.assertEqual((float(second["est_block_tx"]), float(second["est_block_sig"])), (1.5, 4))
        self.assertNotIn("choose_overhead_ns", first)

    def test_parameter_validation(self):
        for spec in (dict(name="priority_floor", beta=0.1, W=0),
                     dict(name="priority_floor", beta=1.1, W=1),
                     dict(name="deadline_slack", beta=0, W=1, m=1, admission_order="unknown")):
            with self.assertRaises(ValueError):
                Model(config(policy=spec))
        for settings in (dict(coalesce_inflight=1), dict(ewma_alpha=0),
                         dict(initial_estimates=dict(admission=1))):
            with self.assertRaises(ValueError):
                Model(config(**settings))

    def test_reproducible_logs_and_cross_policy_service_draws(self):
        workload = generate_workload(generator_parameters(horizon=2, arrivals_valid=dict(kind="poisson", rate=3)))
        common = config(**workload, k=2, coalesce_inflight=False)
        common["service"] = dict(mode="calibration", selectors={c: dict(valid=selector(),
            bit_flip=selector(operation="verify_invalid", variant="single_bit_flip"),
            random_bytes=selector(operation="verify_invalid", variant="random_bytes"))
            for c in ("admission", "block_tx", "block_sig")})
        draws = {}
        for spec in SPECS:
            a, adata = self.run_case(dict(common, policy=spec))
            b, _ = self.run_case(dict(common, policy=spec))
            self.assertEqual(a, b)
            self.assertEqual(adata["schema_version"], 4)
            self.assertEqual(adata["choose_overhead_ns"]["count"], sum(r["event"] == "dispatch" for r in a))
            for j in adata["jobs"]:
                if j["service_time"] is not None:
                    if j["job_id"] in draws:
                        self.assertEqual(draws[j["job_id"]], j["service_time"])
                    draws[j["job_id"]] = j["service_time"]

    def test_50_randomized_workloads_all_eligible_policies_both_coalescing_modes(self):
        rng = random.Random(48153)
        # Capture actual provenance once for these unit runs; git state is constant
        # throughout the loop, avoiding hundreds of duplicate subprocess checks.
        git = _git_state()
        runs = 0
        with tempfile.TemporaryDirectory(prefix="paper2-random-checks-") as root, patch(
                "src.paper2.model.engine._git_state", return_value=git):
            for i in range(50):
                k = 1 + i % 4
                workload = generate_workload(generator_parameters(run_id=f"random-{i}", horizon=2,
                    arrivals_valid=dict(kind="poisson", rate=rng.uniform(1, 5)),
                    arrivals_invalid=dict(kind="poisson", rate=rng.uniform(0, 3)), block_size=3, p_seen=rng.random()))
                for on in (False, True):
                    for spec in SPECS:
                        if spec["name"] == "static_split" and k == 1:
                            continue
                        spec = dict(spec)
                        if spec["name"] == "static_split":
                            spec.update(k_a=1, k_b=k-1)
                        settings = config(**workload, k=k, policy=spec, coalesce_inflight=on,
                            q_max=5, output_dir=str(Path(root) / str(runs)), cache=dict(capacity=4, ttl=2),
                            pool=dict(enabled=True, capacity_bytes=1000),
                            service=dict(mode="constant", seconds={c: dict(valid=0.15, bit_flip=0.12, random_bytes=0.1)
                                         for c in ("admission", "block_tx", "block_sig")}))
                        with self.subTest(workload=i, k=k, coalesce=on, policy=spec["name"]):
                            paths = run_model(settings)
                            full = run_model(dict(settings, policy_view="full", output_dir=str(Path(root)/f"{runs}-full")))
                            self.assertEqual(paths[0].read_bytes(), full[0].read_bytes())
                            self.assertEqual((paths[0].parent/"jobs.csv").read_bytes(), (full[0].parent/"jobs.csv").read_bytes())
                            check_trace(self, *paths, k)
                        runs += 1
        self.assertEqual(runs, 474)
