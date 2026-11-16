"""Phase B: independent explicit resource replay, mutations and observations."""
from tests.paper2._provenance import setUpModule,tearDownModule
from pathlib import Path
from unittest.mock import patch
import collections
import copy
import csv
import hashlib
import json
import random
import tempfile
import unittest

import tests.paper2.test_phase5a_deviation9_a as phase_a
from tests.paper2.test_phase5a_deviation9_a import fixture1,fixture2,schema
from tests.paper2._support import config,tx
from tests.paper2._phase2_support import generator_parameters
from tests.paper2.test_phase3_policies import SPECS
from src.paper2.model import run_model
from src.paper2.model.engine import EVENT_FIELDS
from src.paper2.verify.invariants import check
from src.paper2.verify.summary import recompute,differences
from src.paper2.workload import generate_workload


def locked_model(number):
    PhaseA=phase_a.PhaseA
    seen=[];original=PhaseA.check_model
    def capture(case,m):
        result=original(case,m);seen.append(m);return result
    name=next(n for n in dir(PhaseA) if n.startswith(f'test_F{number}_locked'))
    with patch.object(PhaseA,'check_model',capture):
        getattr(PhaseA(name),name)()
    return seen[0]


def save_model(m,directory,number):
    """Fixture exporter, no checker/engine decision helper used as an oracle."""
    directory.mkdir(parents=True)
    with (directory/'events.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=EVENT_FIELDS);w.writeheader();w.writerows(m.rows)
    with (directory/'jobs.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['job_id','record'])
        for j in m.jobs.values():w.writerow([j.job_id,json.dumps(vars(j))])
    d=dict(config=m.config,blocks=m.blocks,verification_history=m.verification_history,
        accepted_transactions=m.accepted_transactions,admission_checks=m.admission_checks,ledger=m.ledger.record())
    d.update(m.extra_manifest(directory))
    # Explicitly declared prepared states from the locked tables, not guessed
    # by the checker from missing events or inferred from a source model helper.
    if number==3:d['dispatcher'].update(prepared_jobs={'A':0},fixture_callbacks=['fixture_enqueue'])
    if number in (4,5):d['dispatcher']['fixture_callbacks']=['fixture_dispatch']
    if number==6:d['dispatcher']['prepared_jobs']={'background':9}
    (directory/'manifest.json').write_text(json.dumps(d),encoding='utf-8')
    return directory/'events.csv',directory/'jobs.csv',directory/'manifest.json'


def read_artifact(directory):
    with (directory/'events.csv').open(newline='',encoding='utf-8') as f:rows=list(csv.DictReader(f))
    return rows,json.loads((directory/'dispatcher.json').read_text()),json.loads((directory/'manifest.json').read_text())


def mutate(directory,rows,evidence,data):
    # Re-seal deliberately, so a semantic mutation cannot pass just because
    # the tests stopped at the outer digest. Both copies of control rows agree.
    for i,r in enumerate(rows):r['seq']=str(i)
    evidence['transitions']=[json.loads(r['detail']) for r in rows if r['event'].startswith('dispatcher_')]
    raw=(json.dumps(evidence)+'\n').encode();(directory/'dispatcher.json').write_bytes(raw)
    data['dispatcher']['evidence']['sha256']=hashlib.sha256(raw).hexdigest()
    (directory/'manifest.json').write_text(json.dumps(data),encoding='utf-8')
    with (directory/'events.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=EVENT_FIELDS);w.writeheader();w.writerows(rows)


def randomized_configs(count=20):
    rng=random.Random(9132026)
    for seed in range(count):
        for k in (1,2):
            for policy in SPECS:
                if k==1 and policy['name']=='static_split':continue
                p=generator_parameters(run_id=f'd9-b-{seed}-{k}-{policy["name"]}',horizon=1.5,
                    arrivals_valid=dict(kind='poisson' if seed%2 else 'mmpp',**(
                        dict(rate=8) if seed%2 else dict(rates=[2,12],switching_rates=[2,3]))),
                    arrivals_invalid=dict(kind='poisson',rate=2),block_period=.3,block_size=2,p_seen=.7)
                w=generate_workload(p)
                costs={name:rng.choice([0,.01,.025]) for name in ('arrival_pre','arrival_tail','block_build',
                    'block_lookup','block_tail','send_tail','complete_admission','complete_block_tx',
                    'complete_block_sig','complete_tail','accept','accept_tail')};costs['send_pre']=.005
                yield config(**w,k=k,policy=copy.deepcopy(policy),coalesce_inflight=bool(seed%2),
                    q_max=seed%5,cache=dict(capacity=4 if seed%3 else 0,ttl=.3),
                    pool=dict(enabled=True,capacity_bytes=10000),
                    service=dict(mode='constant',seconds={c:dict(valid=.06,bit_flip=.02,random_bytes=.03)
                        for c in ('admission','block_tx','block_sig')}),
                    dispatcher=schema(**costs),summary=dict(analysis_window=[.15,1.5],window_width=.1))


class PhaseB(unittest.TestCase):
    def test_F1_F6_checker_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            for n in range(1,7):
                with self.subTest(fixture=n):self.assertEqual(check(*save_model(locked_model(n),Path(temp)/str(n),n)),[])

    def test_mutation_gate(self):
        expected={
            'overlap':'dispatcher_partition','double_count':'dispatcher_partition',
            'nested_mismatch':'dispatcher_causality','missing_busy':'dispatcher_partition',
            'idle':'dispatcher_work_conservation','cache':'dispatcher_publication',
            'pool':'dispatcher_publication','decision':'dispatcher_acceptance',
            'decrement':'dispatcher_decrement','final_class':'dispatcher_acceptance',
            'reservation':'dispatcher_reservation','queue':'queue_recount',
            'deadline':'block_deadline','state':'dispatcher_state'}
        for kind,code in expected.items():
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'case';save_model(locked_model(1),path,1)
                rows,e,d=read_artifact(path)
                if kind in ('cache','pool','decision'):
                    event={'cache':'cache_insert','pool':'pool_insert','decision':'block_accept'}[kind]
                    r=next(r for r in rows if r['event']==event);r['t']=str(float(r['t'])-.5)
                elif kind=='queue':next(r for r in rows if r['event']=='enqueue')['q_admission']='99'
                elif kind=='deadline':next(r for r in rows if r['event']=='block_arrive')['deadline_t']='999'
                elif kind=='state':d['blocks']['block']['state_checks'][0]['passed']=False
                elif kind=='double_count':e['stages'].append(copy.deepcopy(e['stages'][0]))
                elif kind in ('overlap','nested_mismatch'):
                    s=e['stages'][1]
                    if kind=='overlap':s['start_t']-=.5
                    else:s['callback_id']=999
                elif kind=='missing_busy':
                    sid=e['stages'][0]['id'];e['stages']=e['stages'][1:]
                    rows=[r for r in rows if not (r['event'] in ('dispatcher_stage_start','dispatcher_stage_end') and json.loads(r['detail'])['id']==sid)]
                elif kind=='idle':
                    r=next(r for r in rows if r['event']=='dispatcher_callback_start' and json.loads(r['detail'])['family']=='completion_admission')
                    control=json.loads(r['detail']);control['t']+=.1;r['t']=str(control['t']);r['detail']=json.dumps(control)
                else:
                    event={'decrement':'dispatcher_block_check_complete','final_class':'dispatcher_acceptance_trigger',
                        'reservation':'dispatcher_reserve'}[kind]
                    ix=next(i for i,r in enumerate(rows) if r['event']==event)
                    if kind=='final_class':
                        control=json.loads(rows[ix]['detail']);control['job_class']='admission';rows[ix]['detail']=json.dumps(control)
                    else:rows.insert(ix+1,copy.deepcopy(rows[ix]))
                mutate(path,rows,e,d)
                violations=check(path/'events.csv',path/'jobs.csv',path/'manifest.json')
                self.assertIn(code,{x['code'] for x in violations},violations)

    def test_small_observer_and_independence_development_checks(self):
        # The final randomized gate uses 180 configurations externally. This
        # small repeatable slice remains in the ordinary full suite.
        with tempfile.TemporaryDirectory() as temp:
            for i,c in enumerate(randomized_configs(1)):
                with self.subTest(case=i):
                    e,m=run_model(dict(c,output_dir=str(Path(temp)/f'f{i}')))
                    with patch('src.paper2.model.engine.Model._view',side_effect=AssertionError('engine oracle')):
                        self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
                    s,_=run_model(dict(c,output='summary',output_dir=str(Path(temp)/f's{i}')))
                    self.assertEqual(differences(json.loads(s.read_text()),recompute(e,e.parent/'jobs.csv',c)),[])

    def test_all_fixture_online_observers(self):
        from src.paper2.model.engine import Model,JOB_CLASSES
        from src.paper2.model.summary import OnlineSummary
        original=Model._log
        for n in range(1,7):
            collectors={}
            def tee(m,event,job=None,block_id='',**extra):
                if m not in collectors:collectors[m]=OnlineSummary(m.config)
                counts=[m.pool.waiting_counts[c] for c in JOB_CLASSES]
                if 'q_admission' in extra and job:counts[JOB_CLASSES.index(job.job_class)]-=1
                bid=job.block_id if job else block_id
                collectors[m].observe(m.t,event,counts,job,bid,m.blocks.get(bid),extra)
                return original(m,event,job,block_id,**extra)
            with self.subTest(fixture=n),tempfile.TemporaryDirectory() as temp:
                with patch.object(Model,'_log',tee):m=locked_model(n)
                e,j,_=save_model(m,Path(temp)/'case',n)
                self.assertEqual(differences(collectors[m].finish(),recompute(e,j,m.config)),[])

    def test_additional_dependency_mutations(self):
        expected={'prefetch':'dispatcher_prefetch','missing_reservation':'dispatcher_prefetch',
            'early_completion':'dispatcher_completion','missing_commit':'dispatcher_completion',
            'unpublished_hit':'dispatcher_publication','missing_state':'dispatcher_acceptance',
            'double_decision':'dispatcher_acceptance','wrong_release':'dispatcher_release'}
        for kind,code in expected.items():
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'case';save_model(locked_model(1),path,1)
                rows,e,d=read_artifact(path)
                if kind=='prefetch':
                    ix=next(i for i,r in enumerate(rows) if r['event']=='start' and r['job_id']=='admission:1')
                    r=rows.pop(ix);r['t']='6'
                    end=next(i for i,r in enumerate(rows) if r['event']=='end');rows.insert(end+1,r)
                elif kind=='early_completion':
                    ix=next(i for i,r in enumerate(rows) if r['event']=='dispatcher_callback_start' and json.loads(r['detail'])['family']=='completion_admission')
                    r=rows.pop(ix);end=next(i for i,r in enumerate(rows) if r['event']=='end');rows.insert(end,r)
                elif kind in ('missing_reservation','missing_commit','missing_state'):
                    event={'missing_reservation':'dispatcher_reserve','missing_commit':'dispatcher_completion_commit','missing_state':'state_check'}[kind]
                    rows.pop(next(i for i,r in enumerate(rows) if r['event']==event))
                elif kind=='unpublished_hit':
                    ix=next(i for i,r in enumerate(rows) if r['event']=='cache_hit')
                    r=rows.pop(ix);r['t']='3';end=next(i for i,r in enumerate(rows) if r['event']=='end');rows.insert(end,r)
                elif kind=='double_decision':
                    ix=next(i for i,r in enumerate(rows) if r['event']=='block_accept');rows.insert(ix+1,copy.deepcopy(rows[ix]))
                elif kind=='wrong_release':e['callbacks'][0]['release_t']=1
                mutate(path,rows,e,d)
                violations=check(path/'events.csv',path/'jobs.csv',path/'manifest.json')
                self.assertIn(code,{x['code'] for x in violations},violations)

    def test_H0_explicit_obstruction_hand_check(self):
        from src.paper2.verify.explicit import inspect
        with tempfile.TemporaryDirectory() as temp:
            c=fixture1();c['policy']=dict(name='block_priority');c['output_dir']=temp
            e,manifest=run_model(c);jobs_path=e.parent/'jobs.csv'
            self.assertEqual(check(e,jobs_path,manifest),[])
            with e.open(newline='') as f:rows=list(csv.DictReader(f))
            with jobs_path.open(newline='') as f:records=[json.loads(r['record']) for r in csv.DictReader(f)]
            context=inspect(rows,records,json.loads(manifest.read_text()),manifest)
            self.assertEqual(context.errors,[])
            # F1: txB wait 3 = residual 1 + control-only obstruction 2;
            # sig wait 9 = residual 1 + preceding tx work 4 + obstruction 4.
            self.assertEqual(context.obstruction(11,14,records,1),2)
            self.assertEqual(context.obstruction(11,20,records,1),4)


if __name__=='__main__':unittest.main()
