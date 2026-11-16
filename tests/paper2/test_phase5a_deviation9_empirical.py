"""Locked F7, calibration/source integrity and synthetic dual-model replay."""
from tests.paper2._provenance import setUpModule,tearDownModule
import copy,csv,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.paper2.prototype import stage_capture as c,dispatcher_tables as t,empirical_replay as e,replay,transport,corpus,runtime
from src.paper2.model.service_times import job_draw_integer
from tests.paper2 import test_phase5a_deviation5 as old

def calibration(directory,rep,k=1):
    """Literal engineering fixture, seconds scaled to integer ns; never ARM data."""
    directory=Path(directory);r=c.Recorder(directory,1024,dict(window='representative-cycle',calibration_only=True,
        replicate=rep,backend='sleep',k=k,host='synthetic-host',epoch_ns=0,warmup=0,measurement=1000),
        jobs=['A','X','S'],blocks=['B']);b=c.Boundaries(r)
    ns=lambda v:round(v*1e9)
    for start,cost in ((0,1),(1,3)):
        b.begin(ns(start),c.F['arrival'],c.S['arrival_pre'],job=0);b.end(ns(start+cost))
    b.begin(ns(4),c.F['block_arrival'],c.S['block_build'],block=0,size=2)
    b.change(ns(5),c.S['block_lookups']);b.record(ns(5.2),c.E['lookup'],job=1)
    b.change(ns(5.2),c.S['block_lookups']);b.record(ns(5.5),c.E['lookup'],job=1)
    b.change(ns(5.5),c.S['block_tail']);b.end(ns(5.6))
    for start,cost in ((6,4),(10,6)):
        b.begin(ns(start),c.F['acceptance'],c.S['block_accept'],block=0,size=2);b.end(ns(start+cost))
    samples=[]
    for i,cls in enumerate(('admission','block_tx','block_sig')):
        start=20+i*10
        b.begin(ns(start),c.F['send'],c.S['send_pre'],job=i,block=-1 if not i else 0,worker=0)
        b.record(ns(start+1),c.E['send']);b.change(ns(start+1),c.S['send_tail']);b.record(ns(start+1),c.E['pipe_return']);b.end(ns(start+1))
        b.begin(ns(start+3),c.F['completion_'+cls],c.S['complete_'+cls],job=i,block=-1 if not i else 0,worker=0)
        b.record(ns(start+3),c.E['receive']);b.end(ns(start+6))
        samples.append(dict(backend='sleep:'+cls,operation='verify',variant='valid',job_id=['A','X','S'][i],job_class=cls,
            duration_ns=ns(6),occupancy_ns=ns(2),primitive_ns=ns(1),send_ns=ns(start+1),receive_ns=ns(start+3),
            source=f'concurrency-cycle-k{k}-rep{rep}'))
    r.finish(True)
    with (directory/'cycles.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=tuple(samples[0]));w.writeheader();w.writerows(samples)
    return directory

def inputs(root,k=1):
    root=Path(root);paths=[calibration(root/f'r{r}',r,k) for r in range(3)]
    out={}
    for slot,reps in t.SLOTS.items():
        out[slot]=root/slot;t.build([paths[r] for r in reps],slot,out[slot])
    return out

class Empirical(unittest.TestCase):
    def test_f7_locked_support_fallback_values_and_paired_tuple(self):
        with tempfile.TemporaryDirectory() as td:
            roots=inputs(td);table=t.verify(roots['primary']);s=t.Sampler(table,'F7',0)
            self.assertEqual([s.select('arrival',-1,'invalid',str(i),i)['costs']['arrival_pre']/1e9 for i in (0,1)],[1,3])
            self.assertEqual(s.select('acceptance',2,'rejected','B',1)['costs']['block_accept']/1e9,6)
            self.assertEqual(s.receipt()['fallback_count'],3)
            with self.assertRaises(ValueError):s.select('acceptance',3,'rejected','bad',0)
            with self.assertRaises(ValueError):s.select('absent',-1,'valid','empty',0)
            self.assertEqual(s.receipt()['fallback_count'],3)
            row=s.physical('admission','valid',0)
            self.assertEqual((row['occupancy_ns']/1e9,row['send']['costs']['send_pre']/1e9,row['completion']['costs']['complete_admission']/1e9),(2,1,3))
            self.assertEqual({r['source']['replicate'] for r in table['tuples']['admission']},{0,1})
            self.assertEqual({r['source']['replicate'] for r in t.verify(roots['held_out'])['tuples']['admission']},{2})
            with self.assertRaises(ValueError):s.physical('admission','random_bytes',0)

    def test_sealed_tuple_support_slot_stage_hash_mutations_fail(self):
        for change in ('tuple','support','slot','stage'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as td:
                roots=inputs(td);root=roots['primary'];v=t.read(root/'tables.json')
                if change=='tuple':v['tuples']['admission'][0]['id']='0'*64
                elif change=='support':v['support']['acceptance']['3']=['valid']
                elif change=='slot':v['slot']='held_out'
                else:
                    path=root/'sources/0/stages.bin'
                    with path.open('r+b') as f:f.seek(c.HEADER.size);f.write(b'altered!')
                t.write(root/'tables.json',v);replay.seal(root,'COST_MANIFEST.json')
                with self.assertRaises((ValueError,FileNotFoundError)):t.verify(root)

    def test_prototype_or_probe_cannot_supply_calibration_tables(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);p=calibration(root/'r0',0)
            spec=t.read(p/'stages.json');spec['context']['window']='prototype';spec['context']['calibration_only']=False;t.write(p/'stages.json',spec)
            with self.assertRaisesRegex(ValueError,'never prototype/proxy'):t.build([p], 'primary',root/'wrong')

    def test_unlinked_marginal_named_deterministic_and_old_streams_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            roots=inputs(td);table=t.verify(roots['primary']);table=copy.deepcopy(table)
            table['tuples']['admission'][0]['linked']=False;table['tuples']['admission'][0]['send']=None
            old_draw=job_draw_integer('F7',0,'service_admission',['admission','A'])
            s=t.Sampler(table,'F7',0);s.physical('admission','valid',0)
            self.assertEqual(s.receipt()['unlinked_count'],1)
            self.assertEqual(s.marginal('admission','send','A'),t.Sampler(table,'F7',0).marginal('admission','send','A'))
            self.assertEqual(t.draw('F7',0,'unlinked_send_admission','A'),t.draw('F7',0,'unlinked_send_admission','A'))
            self.assertEqual(old_draw,job_draw_integer('F7',0,'service_admission',['admission','A']))
            self.assertNotEqual(t.draw('F7',0,'unlinked_send_admission','A'),t.draw('F7',0,'arrival','A'))

    def test_capture_tables_transport_roundtrip_and_both_replay_models(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);costs=inputs(root/'costs')
            doc=corpus.build(old.Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json')
            cfg=dict(doc['workload'],output_dir=str(root/'prototype'))
            clock=old.Clock()
            with clock.patches():events,manifest=runtime.run(cfg,cp)
            primary=root/'primary.csv';held=root/'held.csv'
            # Historical legacy adapter still consumes cycles; explicit consumes
            # the occupancy column of the same calibration tuples.
            for p,reps in ((primary,(0,1)),(held,(2,))):
                rows=[]
                for rep in reps:
                    with (root/'costs'/f'r{rep}'/'cycles.csv').open(newline='') as f:rows.extend(csv.DictReader(f))
                with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=tuple(rows[0]));w.writeheader();w.writerows(rows)
            packet=root/'packet';cell=dict(backend='sleep',k=1,policy='fifo',g3_input_version=6)
            # New cycle primary/held-out procedure, without inventing production data.
            replay.create_packet(packet,cfg,cp,dict(events=str(events),manifest=str(manifest)),held,cell,0,window=(0,.1),primary=primary)
            e.bind(packet,costs)
            for directory in (packet,*costs.values()):
                encoded=root/('encoded-'+directory.name);transport.pack(directory,encoded)
                restored=root/('restored-'+directory.name);transport.verify(encoded,output=restored)
                originals={p.relative_to(directory).as_posix():p.read_bytes() for p in directory.rglob('*') if p.is_file()}
                self.assertEqual(originals,{p.relative_to(restored).as_posix():p.read_bytes() for p in restored.rglob('*') if p.is_file()})
            # Rehearsal path always computes all four combinations and full checkers.
            result=e.execute(packet,costs,root/'rehearsal',purpose='rehearsal-v2')
            self.assertEqual(set(result['models']),{'legacy','explicit'})
            for model in result['models'].values():
                self.assertEqual(set(model),{'primary','held_out'})
                for slot in model.values():self.assertEqual(slot['violations'],[])
            replay.verify_files(root/'rehearsal','RESULT_MANIFEST.json')
            gather=e.gather([root/'rehearsal'],root/'gather')
            self.assertEqual(gather['reading'],'NOT SUPPORTED')  # missing second cell
            self.assertEqual(e.selection(root/'gather',result['code_commit']),'legacy')
            with self.assertRaises(ValueError):e.execute(packet,costs,root/'without-receipt',purpose='production')
            with patch.object(replay,'postprocess_prototype',return_value=dict(validity=dict(passed=False),metrics={},violations=[])),patch('src.paper2.prototype.measurement_conditions.apply'):
                production=e.execute(packet,costs,root/'production',purpose='production',mechanism=root/'gather')
            self.assertEqual(production['models'],{})  # invalid -> no comparisons
            proto=copy.deepcopy(result['prototype']);proto['validity']['passed']=True
            with patch.object(replay,'postprocess_prototype',return_value=proto),patch('src.paper2.prototype.measurement_conditions.apply'):
                production=e.execute(packet,costs,root/'production-valid',purpose='production',mechanism=root/'gather')
            self.assertEqual(set(production['models']),{'legacy'})
            positives=[]
            for k in (1,2):
                p=root/f'positive-{k}';p.mkdir();positives.append(p)
                metrics=dict.fromkeys(replay.BANDS,10);metrics['complete']=True
                value=dict(namespace='rehearsal-v2',cell=dict(backend='sleep',k=k),code_commit=result['code_commit'],
                    prototype=dict(metrics=metrics,validity=dict(passed=True),violations=[]),models={})
                for mode,offset in (('legacy',10),('explicit',1)):
                    m=dict(metrics,mean_block_delay=10+offset,mean_admission_wait=10+offset)
                    value['models'][mode]={s:dict(metrics=m,violations=[]) for s in ('primary','held_out')}
                replay.save(p/'result.json',value);replay.seal(p,'RESULT_MANIFEST.json')
            supported=e.gather(positives,root/'supported')
            self.assertEqual(supported['reading'],'MECHANISM SUPPORTED');self.assertEqual(e.selection(root/'supported',result['code_commit']),'explicit')
            with patch.object(replay,'postprocess_prototype',return_value=proto),patch('src.paper2.prototype.measurement_conditions.apply'):
                production=e.execute(packet,costs,root/'production-explicit',purpose='production',mechanism=root/'supported')
            self.assertEqual(set(production['models']),{'explicit'})
            # Corruption rejected before replay, even if another cost slot exists.
            with (costs['primary']/'sources/0/stages.bin').open('ab') as f:f.write(b'bad')
            with self.assertRaises(ValueError):e.verified_inputs(packet,costs)

    def test_mechanism_four_way_rule_missing_zero_baseline_strict_admission(self):
        def record(backend,k):
            rest=dict(p95_block_delay=20,admission_throughput=1,deadline_miss_rate=0,complete=True)
            p=dict(rest,mean_block_delay=10,mean_admission_wait=10)
            oldm=dict(rest,mean_block_delay=20,mean_admission_wait=20)
            newm=dict(rest,mean_block_delay=12,mean_admission_wait=11)
            return dict(cell=dict(backend=backend,k=k),prototype=dict(metrics=p,violations=[],validity=dict(passed=True)),models={
                mode:{slot:dict(metrics=copy.deepcopy(metrics),violations=[]) for slot in ('primary','held_out')}
                for mode,metrics in (('legacy',oldm),('explicit',newm))})
        records=[record('xmss',2),record('ml_dsa_44',1)]
        self.assertEqual(e.mechanism(records)['reading'],'MECHANISM SUPPORTED')
        v=copy.deepcopy(records);v[1]['models']['explicit']['held_out']['metrics']['mean_admission_wait']=20
        self.assertEqual(e.mechanism(v)['reading'],'NOT SUPPORTED')
        v=copy.deepcopy(records);v[1]['models']['legacy']['primary']['metrics']['mean_block_delay']=10
        self.assertEqual(e.mechanism(v)['reading'],'NOT SUPPORTED')
        self.assertFalse(e.mechanism(records)['affects_D1_D3'])

    def test_projection_uses_full_explicit_checker_both_slots_and_refuses_ceiling(self):
        from src.paper2.prototype.deviation9_budget import replay_projection,stage_volume,REFERENCE
        p=replay_projection(REFERENCE)
        self.assertEqual(p['components_seconds']['explicit_simulations'],429)
        self.assertEqual(p['components_seconds']['explicit_full_checks'],1043.6)
        both=replay_projection(REFERENCE,('legacy','explicit'));self.assertGreater(both['seconds'],p['seconds'])
        self.assertEqual(p['timeout_minutes'],max(60,__import__('math').ceil(2*p['seconds']/60)))
        with self.assertRaises(ValueError):replay_projection(10_000_000)
        self.assertEqual(stage_volume([dict(transactions=100)],200,112)['stage_raw_bytes'],11200)

    def test_remote_capture_table_qualification_smoke_and_failure_evidence_rejection(self):
        from src.paper2.verify.qualification_capture import scale
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);receipts=root/'receipts';receipts.mkdir()
            value=scale(root/'work',receipts,count=12,smoke=True)
            self.assertFalse(value['full_size_confirmation']);self.assertEqual(value['rows'][0]['violations'],0)
            failed=root/'failed-attempt-evidence-synthetic';failed.mkdir()
            (failed/'UNVERIFIED').write_text('not consumable')
            with self.assertRaisesRegex(ValueError,'UNVERIFIED'):t.verify(failed)
            with self.assertRaisesRegex(ValueError,'UNVERIFIED'):e.selection(failed,'0'*40)
