"""Pinned-source byte regression. Runs no native backend or prototype."""
from contextlib import ExitStack
import hashlib
import csv
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PIN='3538968f79be0996cf2cc572fa33339fadf1d25f'


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(input_file,output_file):
    from src.paper2.model import run_model
    from src.paper2.model.engine import Model,EVENT_FIELDS
    from src.paper2.model.service_times import derive_seed,job_draw_integer
    rows=json.loads(Path(input_file).read_text());results=[]
    def factory(kind):
        if not kind:return Model
        class Prepared(Model):
            def __init__(self,c):
                super().__init__(c)
                if kind==3:
                    a=self._new_job('A','admission',self.transactions['A']);a.enqueue_t=0;a.service_time=3;a.outcome='valid'
                    self.pending_admissions.add(a.cache_key);self.inflight_admissions[a.cache_key]=a;self._start(a,0)
                    self._schedule(1,2,lambda:self._admit_ready(self._new_job('B','admission',self.transactions['B'])))
                elif kind==4:
                    prepared=[];self._block_ready=lambda *args:prepared.append(args)
                    self.events.clear();self._block(0,c['blocks'][0],[self.transactions['A']])
                    for j in reversed(prepared[0][1]):self._enqueue(j)
                elif kind==5:
                    for name in ('A','B'):self._admit_ready(self._new_job(name,'admission',self.transactions[name]))
                elif kind==6:
                    def background():
                        j=self._new_job('background','admission',self.transactions['C']);j.enqueue_t=9;j.service_time=7;j.outcome='valid'
                        self.pending_admissions.add(j.cache_key);self.inflight_admissions[j.cache_key]=j;self._start(j,0)
                    self._schedule(9,2,background)
                self.prelude=list(self.rows);self.rows=[]
            def run(self):
                if self.event_writer is not None:
                    for r in self.prelude:self.event_writer.writerow([r.get(k) for k in EVENT_FIELDS])
                super().run()
        return Prepared
    with tempfile.TemporaryDirectory(prefix='qualification-reference-') as temp,patch('src.paper2.model.engine._git_state',return_value=dict(commit=PIN,dirty=False)):
        for i,row in enumerate(rows):
            c=dict(row['config']);zero=c.pop('_zero',False);kind=c.pop('_prepared',None)
            if zero:
                from src.paper2.model.dispatcher import route
                c,_=route(dict(c,dispatcher=dict(schema='paper2-dispatcher-literal-v1',mode='explicit')),Model)
            c['output_dir']=str(Path(temp)/f'{i}-full');e,m=run_model(c,model_type=factory(kind))
            c.update(output='summary',output_dir=str(Path(temp)/f'{i}-summary'));s,_=run_model(c,model_type=factory(kind))
            metadata=json.loads(m.read_text())
            with (e.parent/'jobs.csv').open(newline='',encoding='utf-8') as f:jobs=[json.loads(r['record']) for r in csv.DictReader(f)]
            draws=[(j['job_id'],j['service_time'],j['outcome']) for j in jobs if j['start_t'] is not None]
            results.append(dict(events=digest(e),jobs=digest(e.parent/'jobs.csv'),summary=digest(s),seeds=metadata['seeds'],draws=draws,
                stream_probe=[derive_seed(c.get('run_id','phase2'),n,c.get('replicate',0)) for n in ('arrivals','labels','service_admission')],
                job_probe=job_draw_integer(c.get('run_id','phase2'),c.get('replicate',0),'service_admission',['admission','probe'])))
    Path(output_file).write_text(json.dumps(results))


def literal_configs():
    from tests.paper2.test_phase5a_deviation9_a import fixture1,fixture2
    from tests.paper2._support import config,tx
    rows=[]
    for f in (fixture1,fixture2):
        c=f();c.pop('dispatcher');rows.append(c)
    rows.extend([
        config(transactions={n:tx(n) for n in ('A','B')},admissions=[dict(tx_id='A',arrival_t=2)],cache=dict(capacity=100,ttl=100),
            service=dict(mode='constant',seconds=dict(admission=2,block_tx=1,block_sig=1)),_prepared=3),
        config(k=2,blocks=[dict(block_id='block',tx_ids=['A'])],service=dict(mode='constant',seconds=dict(admission=1,block_tx=4,block_sig=2)),_prepared=4),
        config(transactions={n:tx(n) for n in ('A','B')},service=dict(mode='constant',seconds=dict(admission=2,block_tx=1,block_sig=1)),_prepared=5),
        config(transactions={'C':tx('C')},admissions=[dict(tx_id='A',arrival_t=8),dict(tx_id='B',arrival_t=8)],
            blocks=[dict(block_id='block',tx_ids=['A','B'])],block_start=10,cache=dict(capacity=100,ttl=5),
            service=dict(mode='constant',seconds=dict(admission=0,block_tx=2,block_sig=1)),_prepared=6)])
    return rows


def capture_existing():
    from src.paper2.model import run_model
    captures=[]
    def observed(c):
        paths=run_model(c)
        if c.get('policy_view','incremental')=='incremental':
            clean=json.loads(json.dumps(c));clean.pop('output_dir',None);captures.append(dict(config=clean))
        return paths
    modules=[importlib.import_module('tests.paper2.'+n) for n in ('test_phase1_handchecks','test_phase2_state','test_phase3_corrections','test_phase3_policies')]
    with ExitStack() as stack:
        for module in modules:stack.enter_context(patch.object(module,'run_model',observed))
        suite=unittest.TestSuite()
        for module in modules:
            for cls in vars(module).values():
                if isinstance(cls,type) and issubclass(cls,unittest.TestCase):
                    for name in unittest.defaultTestLoader.getTestCaseNames(cls):
                        if name!='test_50000_overloaded_pool_admissions_with_500_prefix_reference':suite.addTest(cls(name))
        result=unittest.TextTestRunner(verbosity=1,failfast=True).run(suite)
    if not result.wasSuccessful():raise RuntimeError('current literal/random gate failed')
    return captures


def run(reference,work,receipts,smoke=False):
    from tests.paper2._support import config
    work=Path(work);work.mkdir(parents=True,exist_ok=True);receipts=Path(receipts);receipts.mkdir(parents=True,exist_ok=True)
    captures=[] if smoke else capture_existing()
    if not smoke:
        from tests.paper2.test_phase5a_deviation9_b import randomized_configs
        for original in randomized_configs(20):
            c=dict(original);c.pop('dispatcher');captures.append(dict(config=c))
    captures.extend(dict(config=c) for c in literal_configs())
    # Positive historical charges remain on the untouched legacy route.
    captures.extend(dict(config=config(k=k,structural_cost=.01,state_cost=.02,admissions=[dict(tx_id='A',arrival_t=0)],
        blocks=[dict(block_id='B',tx_ids=['A'])],block_start=2)) for k in (1,2))
    # Only dispatcher-zero requests set legacy charges to zero. Positive legacy
    # cases are checked separately, never silently reinterpreted as new costs.
    zeros=[]
    for row in captures:
        c=row['config']
        if not c.get('structural_cost',0) and not c.get('state_cost',0):zeros.append(dict(config=dict(c,_zero=True)))
    all_rows=captures+zeros
    source=Path(__file__).resolve();input_file=work/'configs.json';input_file.write_text(json.dumps(all_rows))
    outputs=[]
    for label,cwd,rows in (('reference',Path(reference),captures),('current',Path.cwd(),all_rows)):
        path=work/(label+'-configs.json');path.write_text(json.dumps(rows));target=work/(label+'-output.json')
        env=dict(__import__('os').environ,PYTHONPATH=str(cwd))
        command=[sys.executable,'-B','-c',"import sys;from pathlib import Path;sys.argv=sys.argv[1:];exec(compile(Path(sys.argv[0]).read_text(),sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})",str(source),'worker',str(path),str(target)]
        subprocess.run(command,cwd=cwd,env=env,check=True);outputs.append(json.loads(target.read_text()))
    old,current=outputs;differences=[]
    for i,(a,z) in enumerate(zip(old,current[:len(captures)])):
        if a!=z:differences.append(dict(case=i,route='legacy'))
    base_indices=[i for i,r in enumerate(captures) if not r['config'].get('structural_cost',0) and not r['config'].get('state_cost',0)]
    for i,base in enumerate(base_indices):
        if current[len(captures)+i]!=old[base]:differences.append(dict(case=base,route='explicit-zero'))
    receipt=dict(reference_commit=PIN,status='passed' if not differences else 'failed',smoke=smoke,
        base_cases=len(captures),zero_cases=len(zeros),differences=differences,byte_fields=['events','jobs','summary'],
        stream_fields=['seeds','draws','stream_probe','job_probe'],config_sha256=digest(input_file),
        comparison_sha256=hashlib.sha256(json.dumps([old,current],sort_keys=True).encode()).hexdigest())
    receipt['coverage']=[dict(case=i,k=r['config']['k'],policy=r['config'].get('policy',dict(name='fifo')),
        run_id=r['config'].get('run_id'),replicate=r['config'].get('replicate'),
        config_sha256=hashlib.sha256(json.dumps(r['config'],sort_keys=True).encode()).hexdigest()) for i,r in enumerate(captures)]
    (receipts/'phase-c.json').write_text(json.dumps(receipt,indent=2))
    if differences:raise RuntimeError('pinned byte/stream regression failed')
    return receipt


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='worker':worker(sys.argv[2],sys.argv[3])
    else:raise SystemExit('worker-only entry; use qualification orchestration')
