"""Real Ed25519 and deterministic-sleep workers; full file-only invariants."""

from tests.paper2._provenance import setUpModule, tearDownModule

import copy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from src.paper2.prototype import corpus
from src.paper2.prototype.backends import Verifier
from src.paper2.prototype.runtime import run
from src.paper2.verify.invariants import check
from tests.paper2._support import config,tx


class Prototype(unittest.TestCase):
    def make(self,root,backend="ed25519",k=1,policy="fifo"):
        c=config(k=k,policy=dict(name=policy),cache=dict(capacity=32),pool=dict(enabled=True,capacity_bytes=100000),
            admissions=[dict(tx_id="a",arrival_t=0),dict(tx_id="b",arrival_t=.001)],
            blocks=[dict(block_id="B",tx_ids=["a","b"])],block_start=.05,
            service=dict(mode="constant",seconds=dict(admission=0,block_tx=0,block_sig=0)))
        data=corpus.build(c,backend)
        path=corpus.write(data,Path(root)/"corpus.json")
        events,manifest=run(dict(data["workload"],output_dir=str(Path(root)/"out")),path,
                            sleep_seconds=.003 if backend=="sleep" else 0)
        return data,events,manifest

    def test_real_ed25519_logs_and_cache_hits(self):
        with tempfile.TemporaryDirectory() as root:
            data,e,m=self.make(root)
            corpus.validate(data,primitive_checks=True)
            self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
            with e.open(newline="") as f:rows=list(csv.DictReader(f))
            self.assertTrue(any(r["event"]=="cache_hit" and r["job_class"]=="block_tx" for r in rows))
            self.assertEqual(json.loads(m.read_text())["schema_version"],4)

    def test_sleep_backend_occupancy_and_p2_two_workers(self):
        with tempfile.TemporaryDirectory() as root:
            _,e,m=self.make(root,"sleep",2,"block_priority")
            self.assertEqual(check(e,e.parent/"jobs.csv",m),[])
            with (e.parent/"jobs.csv").open(newline="") as f:jobs=[json.loads(r["record"]) for r in csv.DictReader(f)]
            physical=[j for j in jobs if j["status"]=="end"]
            for j in physical:
                self.assertGreaterEqual(j["primitive_ns"],3_000_000)
                self.assertGreaterEqual(j["occupancy_ns"],j["primitive_ns"])
                self.assertEqual(j["occupancy_ns"],j["receive_ns"]-j["send_ns"])
            # Upper bounds are not tight timing assertions on a shared Windows host.
            self.assertTrue(physical)

    def test_key_mutations_and_real_invalid_signatures(self):
        c=config(transactions={label:tx(label,sig_label=label if label!="valid" else "valid")
                               for label in ("valid","bit_flip","random_bytes")},
                 admissions=[dict(tx_id=label,arrival_t=i*.01) for i,label in enumerate(("valid","bit_flip","random_bytes"))])
        data=corpus.build(c)
        corpus.validate(data,primitive_checks=True)
        e=data["transactions"]["valid"];payload,signature,public=corpus.signed_parts(e)
        context=data["context"];nonce=data["workload"]["transactions"]["valid"]["nonce"]
        key=corpus.cache_key(context,public,payload,nonce,signature)
        for index,value in enumerate((public,payload,signature)):
            for i in range(len(value)):
                parts=[public,payload,signature];parts[index]=value[:i]+bytes([value[i]^1])+value[i+1:]
                self.assertNotEqual(key,corpus.cache_key(context,parts[0],parts[1],nonce,parts[2]))
        for field in context:
            changed=dict(context);changed[field]+="x"
            self.assertNotEqual(key,corpus.cache_key(changed,public,payload,nonce,signature))
        self.assertNotEqual(key,corpus.cache_key(context,public,payload,nonce+1,signature))

    def test_checker_rejects_real_key_and_forged_dispatcher_span(self):
        with tempfile.TemporaryDirectory() as root:
            _,e,m=self.make(root)
            jobsfile=e.parent/"jobs.csv";original=jobsfile.read_bytes()
            with jobsfile.open(newline="") as f:rows=list(csv.DictReader(f))
            record=json.loads(rows[0]["record"]);record["cache_key"]="0"*64;rows[0]["record"]=json.dumps(record)
            with jobsfile.open("w",newline="") as f:
                writer=csv.DictWriter(f,fieldnames=("job_id","record"));writer.writeheader();writer.writerows(rows)
            self.assertIn("real_cache_key",{x["code"] for x in check(e,jobsfile,m)})
            jobsfile.write_bytes(original)
            meta=json.loads(m.read_text());spans=e.parent/meta["prototype"]["spans"]["path"]
            values=json.loads(spans.read_text());values[0]["end_ns"]+=1000000
            spans.write_text(json.dumps(values))
            self.assertIn("dispatcher_span",{x["code"] for x in check(e,jobsfile,m)})

    def delayed_start(self,job_class):
        with tempfile.TemporaryDirectory() as root:
            _,e,m=self.make(root,"sleep",1,"block_priority")
            with e.open(newline="") as f:rows=list(csv.DictReader(f));fields=list(rows[0])
            jobsfile=e.parent/"jobs.csv"
            with jobsfile.open(newline="") as f:jobs=list(csv.DictReader(f))
            selected=next(r for r in rows if r["event"]=="start" and r["job_class"]==job_class)
            # A fixed 1 ms mutation can fit inside a slow host's busy span.
            # Exceed even the sum of ALL physical services and busy spans, an
            # upper bound on residual/ahead work plus allowed dispatcher overlap.
            meta=json.loads(m.read_text())
            spans=json.loads((e.parent/meta["prototype"]["spans"]["path"]).read_text())
            known=sum((json.loads(r["record"])["service_time"] or 0) for r in jobs)
            known+=sum(s["end_t"]-s["start_t"] for s in spans)
            delta_ns=int((known+.001)*1e9)+1;delta=delta_ns/1e9
            for row in rows:
                if row["job_id"]==selected["job_id"] and row["event"] in ("start","end"):
                    row["t"]=str(float(row["t"])+delta)
                    row["monotonic_ns"]=str(int(row["monotonic_ns"])+delta_ns)
            for r in jobs:
                j=json.loads(r["record"])
                if j["job_id"]==selected["job_id"]:
                    j["start_t"]+=delta;j["end_t"]+=delta;r["record"]=json.dumps(j)
            with e.open("w",newline="") as f:
                w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
            with jobsfile.open("w",newline="") as f:
                w=csv.DictWriter(f,fieldnames=("job_id","record"));w.writeheader();w.writerows(jobs)
            return {x["code"] for x in check(e,jobsfile,m)}

    def test_checker_rejects_unexplained_idle_gap(self):
        self.assertIn("work_conservation",self.delayed_start("admission"))

    def test_checker_rejects_priority_wait_beyond_residual_and_busy_bound(self):
        self.assertIn("H0",self.delayed_start("block_sig"))
