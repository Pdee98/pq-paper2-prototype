"""Locked Phase A tables from DEVIATION9_PLAN.md; no Phase B checker changes."""
from tests.paper2._provenance import setUpModule, tearDownModule
import json
from pathlib import Path
import tempfile
import unittest

from src.paper2.model import run_model
from src.paper2.model.engine import Model
from src.paper2.model.explicit import ExplicitModel
from src.paper2.model.dispatcher import SCHEMA, LiteralCosts
from tests.paper2._support import config, tx


def schema(**costs):
    return dict(schema=SCHEMA, mode="explicit", costs=costs)


def settings(**changes):
    return config(cache=dict(capacity=100, ttl=100),
                  pool=dict(enabled=True, capacity_bytes=1000000), deadline=100, **changes)


def fixture1():
    return settings(admissions=[dict(tx_id="A", arrival_t=0), dict(tx_id="B", arrival_t=1)],
        blocks=[dict(block_id="block", tx_ids=["A", "B"])], block_start=8,
        service=dict(mode="constant", seconds=dict(admission=4, block_tx=4, block_sig=2)),
        dispatcher=schema(arrival_pre=1, send_pre=1, complete_admission=1,
                          block_build=3, complete_block_tx=1, complete_block_sig=1, accept=3))


def fixture2():
    return settings(k=2, admissions=[dict(tx_id="A", arrival_t=0),dict(tx_id="B", arrival_t=0)],
        service=dict(mode="constant", seconds=dict(admission=4, block_tx=4, block_sig=2)),
        dispatcher=schema(arrival_pre=1, send_pre=1, complete_admission=1))


def milestone_rows(m):
    # Every lifecycle/eligibility/pool/decision milestone, not a timing value
    # derived from the cost schema. Stage chronology is checked separately.
    names={"tx_arrive", "block_arrive", "enqueue", "start", "end", "pool_insert",
           "block_accept", "block_reject", "dup_drop"}
    return [(r["t"],r["event"],r.get("job_id") or r.get("block_id") or "")
            for r in m.rows if r["event"] in names]


def intervals(m):
    return [(s["kind"],s["start_t"],s["end_t"]) for s in m.dispatcher.stages if s["duration"]]


def totals(m):
    # Direct interval arithmetic on the fixture record; this is not a general
    # invariant checker (Phase B). Worker-time overlap sums separately per worker.
    busy=[(s["start_t"],s["end_t"]) for s in m.dispatcher.stages if s["duration"]]
    workers=[(j.start_t,j.end_t) for j in m.jobs.values() if j.start_t is not None]
    overlap=sum(max(0,min(b,d)-max(a,c)) for a,b in busy for c,d in workers)
    return sum(b-a for a,b in busy),sum(d-c for c,d in workers),overlap


def waits(m):
    return {j.job_id:j.start_t-j.enqueue_t for j in m.jobs.values()
            if j.job_class=="admission" and j.start_t is not None}


def idle_while_waiting_one_worker(m):
    physical=[j for j in m.jobs.values() if j.start_t is not None]
    edges=sorted({t for j in physical for t in (j.enqueue_t,j.start_t,j.end_t)})
    return sum(b-a for a,b in zip(edges,edges[1:])
        if any(j.enqueue_t<=a<j.start_t for j in physical)
        and not any(j.start_t<=a<j.end_t for j in physical))


def components(m,bid):
    b=m.blocks[bid]
    critical=max((j for j in m.jobs.values() if j.block_id==bid and j.end_t is not None),key=lambda j:j.end_t)
    return (critical.enqueue_t-b["arrival_t"],critical.start_t-critical.enqueue_t,
            critical.end_t-critical.start_t,b["accept_t"]-critical.end_t)


class PhaseA(unittest.TestCase):
    def check_model(self,m):
        m.run()
        self.assertEqual([r["t"] for r in m.rows],sorted(r["t"] for r in m.rows))
        positive=intervals(m)
        self.assertTrue(all(a<=b for _,a,b in positive))
        self.assertTrue(all(x[2]<=y[1] for x,y in zip(positive,positive[1:])))
        self.assertEqual(m.pool.reserved,{})
        self.assertEqual(m.pool.completion_pending,{})
        self.assertIsNone(m.dispatcher.active)
        for j in m.jobs.values():
            if j.start_t is not None:
                self.assertEqual(sum(r["event"]=="start" and r["job_id"]==j.job_id for r in m.rows),1)
                self.assertEqual(sum(r["event"]=="end" and r["job_id"]==j.job_id for r in m.rows),1)
        return m

    def test_F1_locked_admission_block_chronology(self):
        m=self.check_model(ExplicitModel(fixture1()))
        self.assertEqual(milestone_rows(m),[
            (0,"tx_arrive","admission:0"),(1,"enqueue","admission:0"),(2,"start","admission:0"),
            (2,"tx_arrive","admission:1"),(3,"enqueue","admission:1"),(6,"end","admission:0"),
            (7,"pool_insert","admission:0"),(8,"start","admission:1"),(8,"block_arrive","block"),
            (11,"enqueue","block:0:tx:1"),(11,"enqueue","block:0:sig"),(12,"end","admission:1"),
            (13,"pool_insert","admission:1"),(14,"start","block:0:tx:1"),
            (18,"end","block:0:tx:1"),(20,"start","block:0:sig"),(22,"end","block:0:sig"),
            (26,"block_accept","block")])
        self.assertEqual(intervals(m),[("arrival_pre",0,1),("send_pre",1,2),("arrival_pre",2,3),
            ("complete_admission",6,7),("send_pre",7,8),("block_build",8,11),
            ("complete_admission",12,13),("send_pre",13,14),("complete_block_tx",18,19),
            ("send_pre",19,20),("complete_block_sig",22,23),("block_accept",23,26)])
        self.assertEqual(waits(m),{"admission:0":1,"admission:1":5})
        self.assertEqual(components(m,"block"),(3,9,2,4))
        self.assertEqual(m.blocks["block"]["accept_t"]-m.blocks["block"]["arrival_t"],18)
        self.assertEqual(totals(m),(16,14,4))
        # Interval union, not a sum per queued job or a dispatcher-marker exemption.
        self.assertEqual(idle_while_waiting_one_worker(m),7)
        self.assertEqual([(r["t"],r["event"],r["tx_id"]) for r in m.rows
            if r["job_class"]=="block_tx" and r["event"] in ("cache_hit","cache_miss")],
            [(11,"cache_hit","A"),(11,"cache_miss","B")])
        release=[r for r in m.control_rows if r["event"]=="release" and r["identity"]=="admission:1"][0]
        self.assertEqual(release["t"]-release["offered_t"],1)

    def test_F2_locked_parallel_workers_serial_sends(self):
        m=self.check_model(ExplicitModel(fixture2()))
        self.assertEqual(milestone_rows(m),[(0,"tx_arrive","admission:0"),(1,"enqueue","admission:0"),
            (2,"start","admission:0"),(2,"tx_arrive","admission:1"),(3,"enqueue","admission:1"),
            (4,"start","admission:1"),(6,"end","admission:0"),(7,"pool_insert","admission:0"),
            (8,"end","admission:1"),(9,"pool_insert","admission:1")])
        self.assertEqual(intervals(m),[("arrival_pre",0,1),("send_pre",1,2),("arrival_pre",2,3),
            ("send_pre",3,4),("complete_admission",6,7),("complete_admission",8,9)])
        self.assertEqual(waits(m),{"admission:0":1,"admission:1":1})
        self.assertEqual([(j.worker_id,j.start_t,j.end_t) for j in m.jobs.values()],[(0,2,6),(1,4,8)])
        self.assertEqual(totals(m),(6,8,3))

    def test_F3_locked_pending_completion_no_preemption(self):
        c=settings(transactions={"A":tx("A"), "B":tx("B")},
            admissions=[dict(tx_id="A",arrival_t=2)],
            dispatcher=dict(schema=SCHEMA,mode="explicit",costs=dict(send_pre=1,complete_admission=1),
                            jobs={"admission:0":dict(arrival_pre=4)}))
        m=ExplicitModel(c)
        a=m._new_job("A","admission",m.transactions["A"])
        a.enqueue_t=0;a.service_time=3;a.outcome="valid"
        m.pending_admissions.add(a.cache_key);m.inflight_admissions[a.cache_key]=a
        m._start(a,0)  # F3's explicitly declared already-sent initial job.
        def queue_b():
            b=m._new_job("B","admission",m.transactions["B"])
            Model._admit_ready(m,b);b.service_time=2
            yield from m._dispatch_jobs()
        m._schedule(1,2,lambda:m.dispatcher.submit("fixture_enqueue","B",queue_b()))
        self.check_model(m)
        self.assertEqual(milestone_rows(m),[(0,"start","A"),(1,"enqueue","B"),
            (2,"tx_arrive","admission:0"),(3,"end","A"),(6,"dup_drop","admission:0"),
            (7,"pool_insert","A"),(8,"start","B"),(10,"end","B"),(11,"pool_insert","B")])
        self.assertEqual(intervals(m),[("arrival_pre",2,6),("complete_admission",6,7),
                                      ("send_pre",7,8),("complete_admission",10,11)])
        self.assertEqual(waits(m)["B"],7)
        self.assertEqual(idle_while_waiting_one_worker(m),5)
        self.assertEqual(totals(m),(7,5,1))
        self.assertEqual([(r["t"],r["job_id"]) for r in m.rows if r["event"]=="cache_insert"],[(7,"A"),(11,"B")])

    def test_F4_locked_acceptance_from_last_block_tx(self):
        c=settings(blocks=[dict(block_id="block",tx_ids=["A"])],k=2,
            service=dict(mode="constant",seconds=dict(admission=1,block_tx=4,block_sig=2)),
            dispatcher=schema(send_pre=1,complete_block_tx=1,complete_block_sig=1,accept=3))
        m=ExplicitModel(c);m.events.clear()
        Model._block(m,0,c["blocks"][0],[m.transactions["A"]])
        _,jobs,_=m.prepared_block;m.prepared_block=None
        # F4 explicitly declares signature-first prepared queue, not construction order.
        for j in reversed(jobs):m._enqueue(j)
        m.dispatcher.submit("fixture_dispatch","F4",m._dispatch_jobs())
        self.check_model(m)
        self.assertEqual(milestone_rows(m),[(0,"block_arrive","block"),(0,"enqueue","block:0:sig"),
            (0,"enqueue","block:0:tx:0"),(1,"start","block:0:sig"),(2,"start","block:0:tx:0"),
            (3,"end","block:0:sig"),(6,"end","block:0:tx:0"),(10,"block_accept","block")])
        self.assertEqual(intervals(m),[("send_pre",0,1),("send_pre",1,2),
            ("complete_block_sig",3,4),("complete_block_tx",6,7),("block_accept",7,10)])
        self.assertEqual(totals(m),(7,6,2))
        self.assertEqual(components(m,"block"),(0,2,4,4))
        triggers=[r for r in m.control_rows if r["event"]=="acceptance_trigger"]
        self.assertEqual([(r["t"],r["job_class"]) for r in triggers],[(7,"block_tx")])

    def test_F5_locked_send_suffix_overlap(self):
        c=settings(transactions={name:tx(name) for name in ("A","B")},
            service=dict(mode="constant",seconds=dict(admission=2,block_tx=1,block_sig=1)),
            dispatcher=schema(send_pre=1,send_tail=4,complete_admission=1))
        m=ExplicitModel(c)
        for name in ("A","B"):Model._admit_ready(m,m._new_job(name,"admission",m.transactions[name]))
        m.dispatcher.submit("fixture_dispatch","F5",m._dispatch_jobs())
        self.check_model(m)
        self.assertEqual(milestone_rows(m),[(0,"enqueue","A"),(0,"enqueue","B"),(1,"start","A"),
            (3,"end","A"),(6,"pool_insert","A"),(7,"start","B"),(9,"end","B"),(12,"pool_insert","B")])
        self.assertEqual(intervals(m),[("send_pre",0,1),("send_tail",1,5),("complete_admission",5,6),
            ("send_pre",6,7),("send_tail",7,11),("complete_admission",11,12)])
        self.assertEqual(waits(m),{"A":1,"B":7})
        self.assertEqual(totals(m),(12,4,4))

    def test_F6_locked_incremental_ttl(self):
        c=config(cache=dict(capacity=100,ttl=5),pool=dict(enabled=True,capacity_bytes=1000000),deadline=100,
            transactions={"C":tx("C")},
            admissions=[dict(tx_id="A",arrival_t=8),dict(tx_id="B",arrival_t=8)],
            blocks=[dict(block_id="block",tx_ids=["A","B"])],block_start=10,
            service=dict(mode="constant",seconds=dict(admission=0,block_tx=2,block_sig=1)),
            dispatcher=dict(schema=SCHEMA,mode="explicit",blocks={"block":dict(build=1,lookups=[1,2])}))
        m=ExplicitModel(c)
        def background():
            j=m._new_job("background","admission",m.transactions["C"])
            j.enqueue_t=9;j.service_time=7;j.outcome="valid"
            m.pending_admissions.add(j.cache_key);m.inflight_admissions[j.cache_key]=j
            m._start(j,0)  # F6's declared already-sent background job.
        m._schedule(9,2,background)
        self.check_model(m)
        self.assertEqual(milestone_rows(m),[(8,"tx_arrive","admission:0"),(8,"enqueue","admission:0"),
            (8,"start","admission:0"),(8,"end","admission:0"),(8,"pool_insert","admission:0"),
            (8,"tx_arrive","admission:1"),(8,"enqueue","admission:1"),(8,"start","admission:1"),
            (8,"end","admission:1"),(8,"pool_insert","admission:1"),(9,"start","background"),
            (10,"block_arrive","block"),(14,"enqueue","block:0:tx:1"),(14,"enqueue","block:0:sig"),
            (16,"end","background"),(16,"pool_insert","background"),(16,"start","block:0:tx:1"),
            (18,"end","block:0:tx:1"),(18,"start","block:0:sig"),(19,"end","block:0:sig"),
            (19,"block_accept","block")])
        self.assertEqual(intervals(m),[("block_build",10,11),("block_lookups",11,12),("block_lookups",12,14)])
        self.assertEqual([(r["t"],r["event"],r["tx_id"]) for r in m.rows if r["job_class"]=="block_tx"
            and r["event"] in ("cache_hit","cache_miss")],[(12,"cache_hit","A"),(14,"cache_miss","B")])
        self.assertEqual(totals(m),(4,10,4))
        self.assertEqual(components(m,"block"),(4,4,1,0))
        self.assertEqual(m.blocks["block"]["accept_t"],19)

    def test_F1_F2_zero_references_and_legacy_routing(self):
        for factory,starts,ends,adwait,decision in (
                (fixture1,[0,4,8],[4,8,10],[0,3],10),
                (fixture2,[0,0],[4,4],[0,0],None)):
            c=factory();c.pop("dispatcher")
            reference=Model(c);reference.run()
            self.assertEqual([j.start_t for j in reference.jobs.values() if j.start_t is not None],starts)
            self.assertEqual([j.end_t for j in reference.jobs.values() if j.start_t is not None],ends)
            self.assertEqual(list(waits(reference).values()),adwait)
            if decision is not None:
                self.assertEqual(reference.blocks["block"]["accept_t"],decision)
                self.assertEqual(reference.blocks["block"]["accept_t"]-reference.blocks["block"]["arrival_t"],2)
            with tempfile.TemporaryDirectory() as temp:
                base,_=run_model(dict(c,output_dir=str(Path(temp)/"legacy")))
                zero,_=run_model(dict(c,dispatcher=schema(),output_dir=str(Path(temp)/"zero")))
                self.assertEqual(base.read_bytes(),zero.read_bytes())
                self.assertEqual((base.parent/"jobs.csv").read_bytes(),(zero.parent/"jobs.csv").read_bytes())
                s1,_=run_model(dict(c,output="summary",output_dir=str(Path(temp)/"s1")))
                s2,_=run_model(dict(c,dispatcher=schema(),output="summary",output_dir=str(Path(temp)/"s2")))
                self.assertEqual(s1.read_bytes(),s2.read_bytes())

    def test_literal_schema_validation(self):
        for bad in (-1,float('nan'),float('inf'),-float('inf'),True,"1"):
            with self.subTest(value=repr(bad)),self.assertRaises(ValueError):
                LiteralCosts(schema(send_pre=bad))
            with self.subTest(block=repr(bad)),self.assertRaises(ValueError):
                LiteralCosts(dict(schema=SCHEMA,mode="explicit",blocks={"B":dict(lookups=[bad])}))
        for field in ("structural_cost","state_cost"):
            with tempfile.TemporaryDirectory() as temp,self.assertRaisesRegex(ValueError,"legacy"):
                run_model(dict(fixture2(),**{field:1},output_dir=temp))
        for value in (None,dict(schema="unknown",mode="explicit"),dict(schema=SCHEMA,mode="bad"),
                      schema(unknown=1),dict(schema=SCHEMA,mode="legacy",costs=dict(send_pre=1))):
            with self.subTest(value=value),self.assertRaises(ValueError):LiteralCosts(value)
        with self.assertRaisesRegex(ValueError,"lookup count"):
            ExplicitModel(dict(fixture1(),dispatcher=dict(schema=SCHEMA,mode="explicit",costs=dict(send_pre=1),
                blocks={"block":dict(lookups=[1])})))

    def test_tied_receives_precede_arrival_at_callback_boundary(self):
        c=settings(k=2, admissions=[dict(tx_id="C",arrival_t=2)],
            transactions={name:tx(name) for name in ("A","B","C")},
            dispatcher=schema(complete_admission=1))
        m=ExplicitModel(c)
        for worker,name in enumerate(("A","B")):
            j=m._new_job(name,"admission",m.transactions[name])
            j.enqueue_t=0;j.service_time=2;j.outcome="valid"
            m.pending_admissions.add(j.cache_key);m.inflight_admissions[j.cache_key]=j
            m._start(j,worker)
        self.check_model(m)
        callbacks=[(r["family"],r["identity"],r["start_t"]) for r in m.dispatcher.callbacks]
        self.assertEqual(callbacks[:3],[("completion_admission","A",2),
            ("completion_admission","B",3),("arrival","admission:0",4)])

    def test_positive_cost_policy_views_and_coalesced_acceptance(self):
        specs=[dict(name="fifo"),dict(name="block_priority"),
            dict(name="static_split",k_a=1,k_b=1),
            dict(name="priority_floor",beta=0.4,W=5),
            dict(name="deadline_slack",beta=0.2,W=5,m=1)]
        for policy in specs:
            c=settings(k=2,policy=policy,coalesce_inflight=True,
                admissions=[dict(tx_id="A",arrival_t=0),dict(tx_id="B",arrival_t=0.1)],
                blocks=[dict(block_id="block",tx_ids=["A","B"])],block_start=0.2,
                dispatcher=schema(send_pre=0.01,complete_admission=0.1,
                                  complete_block_sig=0.1,accept=0.2))
            with self.subTest(policy=policy):
                m=self.check_model(ExplicitModel(c))
                other=self.check_model(ExplicitModel(dict(c,policy_view="full")))
                self.assertEqual(m.rows,other.rows)
                self.assertEqual(sum(r["event"]=="acceptance_trigger" for r in m.control_rows),1)
                self.assertEqual(sum(r["event"]=="block_accept" for r in m.rows),1)
                self.assertEqual(m.blocks["block"]["valid"],True)

    def test_explicit_artifact_schema_and_positive_legacy_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            log,manifest=run_model(dict(fixture1(),output_dir=str(Path(temp)/"explicit")))
            data=json.loads(manifest.read_text())
            self.assertEqual(data["dispatcher"]["schema"],SCHEMA)
            self.assertTrue((log.parent/"dispatcher.json").is_file())
            self.assertEqual(data["dispatcher"]["independent_checker"],"independent-explicit-v1")
            c=config(structural_cost=2,state_cost=1,admissions=[dict(tx_id="A",arrival_t=0)])
            base,_=run_model(dict(c,output_dir=str(Path(temp)/"base")))
            old,_=run_model(dict(c,dispatcher=dict(schema=SCHEMA,mode="legacy"),output_dir=str(Path(temp)/"old")))
            self.assertEqual(base.read_bytes(),old.read_bytes())
            self.assertEqual((base.parent/"jobs.csv").read_bytes(),(old.parent/"jobs.csv").read_bytes())


if __name__ == "__main__":
    unittest.main()
