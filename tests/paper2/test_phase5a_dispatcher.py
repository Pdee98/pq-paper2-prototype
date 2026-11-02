"""Decision/reference and occupancy replay checks, independent of wall clocks."""

from tests.paper2._provenance import setUpModule, tearDownModule

import copy
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.paper2.model.engine import run_model
from src.paper2.prototype import analysis, corpus, runtime
from src.paper2.verify.invariants import check
from tests.paper2._support import config


def decisions(path):
    """Only wall-clock-derived fields are omitted; queue/worker identities remain."""
    fields=("event","job_id","job_class","tx_id","block_id","worker_id",
            "q_admission","q_block","busy_workers","outcome","sig_label",
            "cache_key","reject_reason","reject_reasons","detail","policy","chosen_job_id")
    with path.open(newline="") as stream:
        return [tuple(row[name] for name in fields) for row in csv.DictReader(stream)
                if not row["event"].startswith("dispatcher_busy_")]


class Dispatcher(unittest.TestCase):
    def workload(self,policy="fifo",k=1):
        return config(k=k,policy=dict(name=policy),
            admissions=[dict(tx_id=name,arrival_t=0) for name in ("a","b","c","d","a")],
            blocks=[dict(block_id="B",tx_ids=["a","b"]),dict(block_id="C",tx_ids=["c","d"]),
                    dict(block_id="D",tx_ids=["c","d"])],
            block_times=[0,2,3],cache=dict(capacity=2,ttl=100),
            pool=dict(enabled=True,capacity_bytes=100000))

    def exercise(self,root,policy,k):
        data=corpus.build(self.workload(policy,k),"sleep")
        cp=corpus.write(data,root/"corpus.json")
        outputs=[]
        for label,kind in (("reference",runtime.LegacyRealtimeModel),("optimized",runtime.RealtimeModel)):
            c=dict(data["workload"],output_dir=str(root/label))
            e,m=run_model(c,model_type=lambda cfg:kind(cfg,cp,.15))
            self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
            with e.open(newline="") as stream:rows=list(csv.DictReader(stream))
            # The entire simultaneous burst precedes completion. Assert this
            # condition rather than silently assuming live OS timing is fixed.
            first_end=min(float(r["t"]) for r in rows if r["event"]=="end")
            releases=[float(r["t"]) for r in rows if r["event"]=="tx_arrive"]
            self.assertLess(max(releases),first_end)
            outputs.append((e,m))
        self.assertEqual(decisions(outputs[0][0]),decisions(outputs[1][0]))
        reference=json.loads(outputs[0][1].read_text());optimized=json.loads(outputs[1][1].read_text())
        for field in ("ledger","pool","accepted_transactions"):
            self.assertEqual(reference[field],optimized[field])
        return data,cp,outputs[1]

    def test_fake_reference_decisions_and_occupancy_replay(self):
        for policy in ("fifo","block_priority"):
            with self.subTest(policy=policy),tempfile.TemporaryDirectory() as root:
                root=Path(root);data,cp,(e,m)=self.exercise(root,policy,1)
                rows=decisions(e)
                self.assertTrue(any(r[0]=="dup_drop" for r in rows))
                self.assertTrue(any(r[0]=="pool_insert" for r in rows))
                self.assertTrue(any(r[0]=="cache_hit" for r in rows))
                self.assertTrue(any(r[0]=="cache_evict" for r in rows))
                self.assertTrue(any(r[0]=="block_accept" for r in rows))
                self.assertTrue(any(r[0]=="block_reject" for r in rows))
                sample=analysis.samples_from_jobs(e.parent/"jobs.csv",root/"samples.csv","sleep","test")
                se,sm=analysis.paired(dict(data["workload"],output_dir=str(root/"replay")),cp,sample,"sleep",0,0)
                self.assertEqual(check(se,se.parent/"jobs.csv",sm),[])
                self.assertEqual(rows,decisions(se))

    def test_two_worker_assignment_reference(self):
        # A controlled transport/clock forces equal-duration concurrent work,
        # avoiding an assertion about OS reply races between two live runs.
        # Actual Workers/Pipes/backend calls are exercised by Prototype tests.
        clock=[0];duration=10_000_000
        def advance(seconds):clock[0]+=max(1,round(seconds*1e9)) if seconds else 0
        class Pipe:
            reply=None
            def send(self,message):self.reply=("result",message[1],clock[0],clock[0]+duration,True)
            def poll(self):return self.reply is not None and self.reply[3]<=clock[0]
            def recv(self):
                self.assert_ready();result=self.reply;self.reply=None;return result
            def assert_ready(self):
                if not self.poll():raise AssertionError("virtual result received before completion")
        class VirtualWorkers:
            def __init__(self,k,*args):
                self.pipes=[Pipe() for _ in range(k)];self.metadata=[];self.clock_records=[]
                self.handshake("before")
            def handshake(self,phase):
                for worker in range(len(self.pipes)):
                    self.clock_records.append(dict(worker_id=worker,phase=phase,probes=[dict(
                        dispatcher_before_ns=clock[0],dispatcher_after_ns=clock[0],worker_ns=clock[0],
                        offset_ns=0,uncertainty_ns=0)]))
            def close(self):pass
        def wait(pipes,timeout):
            target=min(clock[0]+round(timeout*1e9),min(p.reply[3] for p in pipes))
            clock[0]=target
            return [p for p in pipes if p.poll()]
        c=self.workload(k=2)
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);data=corpus.build(c,"sleep");cp=corpus.write(data,root/"corpus.json")
            logs=[]
            for name,kind in (("reference",runtime.LegacyRealtimeModel),("optimized",runtime.RealtimeModel)):
                clock[0]=0
                with patch.object(runtime,"Workers",VirtualWorkers), \
                     patch.object(runtime.time,"monotonic_ns",side_effect=lambda:clock[0]), \
                     patch.object(runtime.time,"sleep",side_effect=advance), \
                     patch.object(runtime,"wait",side_effect=wait):
                    e,m=run_model(dict(data["workload"],output_dir=str(root/name)),
                                  model_type=lambda cfg:kind(cfg,cp,.01))
                self.assertEqual(check(e,e.parent/"jobs.csv",m),[]);logs.append(e)
                with e.open(newline="") as stream:
                    starts=[r for r in csv.DictReader(stream) if r["event"]=="start"]
                self.assertEqual({r["worker_id"] for r in starts},{"0","1"})
                self.assertEqual([(r["job_id"],r["worker_id"]) for r in starts[:2]],
                                 [("admission:0","0"),("admission:1","1")])
            self.assertEqual(decisions(logs[0]),decisions(logs[1]))
            sample=analysis.samples_from_jobs(logs[1].parent/"jobs.csv",root/"samples.csv","sleep","test")
            se,sm=analysis.paired(dict(data["workload"],output_dir=str(root/"replay")),cp,sample,"sleep",0,0)
            self.assertEqual(check(se,se.parent/"jobs.csv",sm),[])
            self.assertEqual(decisions(logs[1]),decisions(se))

    def test_bounded_buffer_is_deferred_and_fails_closed(self):
        target=io.StringIO();writer=csv.writer(target)
        buffer=runtime.BufferedEventWriter(writer,2)
        first=["first",1];buffer.writerow(first);first[1]=99
        buffer.writerow(("second",2))
        self.assertEqual(target.getvalue(),"")
        with self.assertRaisesRegex(BufferError,"event buffer capacity"):
            buffer.writerow(("third",3))
        buffer.flush()
        self.assertEqual(list(csv.reader(io.StringIO(target.getvalue()))),[["first","1"],["second","2"]])
        buffer.flush()  # idempotent; no duplicate records
        self.assertEqual(len(target.getvalue().splitlines()),2)

    def test_prepared_keys_are_bound_to_validated_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);data=corpus.build(self.workload(),"sleep")
            cp=corpus.write(data,root/"corpus.json")
            model=runtime.RealtimeModel(data["workload"],cp)
            for tx in model.transactions.values():
                self.assertEqual(model._key(tx),data["transactions"][tx["tx_id"]]["cache_key"])
            for section in ("transactions","admissions"):
                changed=copy.deepcopy(data["workload"])
                tx=changed[section]["a"] if section=="transactions" else changed[section][0]
                tx["amount"]+=1
                with self.assertRaisesRegex(ValueError,"metadata|commitment"):
                    runtime.RealtimeModel(changed,cp)

    def test_guard_exclusion_preserves_nominal_cells(self):
        from src.paper2.prototype.runner import partition_cells
        rows=[dict(backend="xmss",rho=.5,dispatcher_utilisation=.5),
              dict(backend="xmss",rho=.85,dispatcher_utilisation=.85)]
        original=copy.deepcopy(rows);eligible,excluded=partition_cells(rows)
        self.assertEqual(rows,original)
        self.assertEqual(eligible,[rows[0]])
        self.assertEqual(excluded,[dict(cell=rows[1],reason="dispatcher-bound, not a valid worker-contention test")])
        self.assertEqual(partition_cells(rows[1:])[0],[])
