"""Transport byte identity, constrained orchestration and retained gate."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from src.paper2.prototype import transport as t, production as p, replay, production_replay as pr
from src.paper2.prototype.cycle_protocol import cold_cycle_reference
from src.paper2.prototype.replay_budget import timeout_minutes


class Completion(unittest.TestCase):
    def test_metadata_is_lossless_deduplicated_and_reference_shaped_input_is_safe(self):
        tx=dict(sender='s',nonce=0,amount=7,tx_id='t',signature_id='a'*64)
        raw=t.canonical(dict(config=dict(transactions={'t':tx}),accepted=[tx,tx],
                             planted=['ref','absent'],other={'$transport_ref':'absent'}))
        table={};encoded=t.split_metadata(raw,table)
        self.assertEqual(len(table),1)
        self.assertEqual(t.join_metadata(encoded,table),raw)
        table[next(iter(table))]['amount']=8
        with self.assertRaisesRegex(ValueError,'metadata hash'):t.join_metadata(encoded,table)

    def test_round_trip_all_files_and_corruption_and_strict_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);src=root/'source';src.mkdir()
            (src/'events.csv').write_bytes(b'a,b\r\n1,2\r\n')
            (src/'manifest.json').write_bytes(t.canonical({'transactions':{'t':dict(sender='s',nonce=2)}}))
            (src/'odd.json').write_bytes(b'{ "preserve": true }')
            (src/'pause_gc.bin').write_bytes(bytes(range(128)))
            replay.seal(src,'REPLAY_MANIFEST.json')
            original={f.name:f.read_bytes() for f in src.iterdir()}
            t.pack(src,root/'upload');t.verify(root/'upload',output=root/'restored')
            self.assertEqual(original,{f.name:f.read_bytes() for f in (root/'restored').iterdir()})
            replay.verify_files(root/'restored','REPLAY_MANIFEST.json')
            doc=replay.read(root/'upload/TRANSPORT.json')
            blob=root/'upload/objects'/(next(iter(doc['objects']))+'.gz')
            blob.write_bytes(blob.read_bytes()+b'bad')
            with self.assertRaisesRegex(ValueError,'SHA-256'):t.verify(root/'upload')

    def test_upload_acknowledgement_before_raw_deletion(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);src=root/'source';src.mkdir();(src/'events.csv').write_bytes(b'x\n1\n')
            t.pack(src,root/'upload');shutil.copytree(root/'upload',root/'download')
            artifact=dict(id='123',digest='a'*64)
            (root/'download/extra').write_bytes(b'bad')
            with self.assertRaises(ValueError):t.acknowledge(src,root/'upload',root/'download',artifact)
            self.assertTrue((src/'events.csv').is_file())
            (root/'download/extra').unlink()
            receipt=t.acknowledge(src,root/'upload',root/'download',artifact)
            self.assertTrue(receipt['verified']);self.assertFalse((src/'events.csv').exists())

    def test_uploaded_archive_digest_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'upload.zip'
            with zipfile.ZipFile(path,'w') as z:z.writestr('file',b'bytes')
            self.assertTrue(t.verify_uploaded_zip(path,hashlib.sha256(path.read_bytes()).hexdigest()))
            with self.assertRaisesRegex(ValueError,'digest mismatch'):t.verify_uploaded_zip(path,'0'*64)

    def test_cross_packet_canonical_objects_not_uploaded_twice(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for i in (1,2):
                src=root/str(i);src.mkdir();(src/'events.csv').write_bytes(b'identical,content\n')
            first=t.pack(root/'1',root/'a')
            known={key:'artifact1' for key in first['objects']}
            t.pack(root/'2',root/'b',known)
            self.assertFalse((root/'b/objects').exists())
            t.verify(root/'b',{'artifact1':root/'a'},root/'restored')
            self.assertEqual((root/'restored/events.csv').read_bytes(),b'identical,content\n')

    def test_disk_guard_margin_is_exact_and_fails_closed(self):
        with patch.object(t.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(500,351,149)):
            with self.assertRaisesRegex(RuntimeError,'insufficient disk'):t.disk_guard('.',100)
        with patch.object(t.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(500,350,150)):
            self.assertEqual(t.disk_guard('.',100)['threshold_bytes'],150)

    def test_gate_cannot_start_validation_and_rehearsal_has_own_seeds(self):
        with patch.object(p,'calibrate_backend',side_effect=AssertionError('must not calibrate')):
            with self.assertRaisesRegex(RuntimeError,'Run #7 blocked'):p.prepare(Path('unused'),'7X')
        c=dict(backend='xmss',k=2,policy='fifo',rho_cold=.85,rate=10,period=12.8)
        old=p.group_parameters(c,0)
        self.assertEqual(p.parameters(c,0,'validation'),old)
        self.assertNotEqual(p.parameters(c,0,p.REHEARSAL)['run_id'],old['run_id'])

    def test_global_ids_do_not_depend_on_calibration_dictionary_order(self):
        ref={k:cold_cycle_reference(k,dict(admission=.1,block_tx=.1,block_sig=.1),.0001,1) for k in (1,2)}
        cells,rows,_=p.plan({'ml_dsa_44':ref,'xmss':ref},'7M')
        self.assertEqual(set(cells),set(range(8,16)))
        self.assertTrue(all(r['cell']['backend']=='ml_dsa_44' for r in rows))

    def test_only_one_operational_rerun_and_one_authorized_replacement(self):
        previous=dict(part='7X',attempt=1,mode='initial',operational_status='failed',preserved=True)
        self.assertIsNone(p.authorize('7X',2,previous=previous))
        for attempt in (0,3):
            with self.assertRaises(ValueError):p.authorize('7X',attempt,previous=previous)
        aggregate=dict(verdict='INCONCLUSIVE',aggregates=[dict(cell_id=0,verdict='INCONCLUSIVE',followup_eligible=True,initial_invalid_count=1)])
        self.assertEqual(p.authorize('7X',1,'followup',aggregate=aggregate,selected=[0]),[0])
        for change in ('FAIL','PASS','two_invalid'):
            bad=copy.deepcopy(aggregate)
            if change=='two_invalid':bad['aggregates'][0]['initial_invalid_count']=2
            else:bad['aggregates'][0].update(verdict=change,followup_eligible=False)
            with self.assertRaises(ValueError):p.authorize('7X',1,'followup',aggregate=bad,selected=[0])

    def test_attempt_registry_refuses_a_second_operational_rerun(self):
        from src.paper2.prototype import remote_authorization as remote
        current=dict(id=200,workflow_id=10,display_title='Paper2 G3 7X/initial/attempt-2 previous-100 ',run_attempt=1)
        earlier=dict(current,id=150)
        env=dict(GITHUB_RUN_ID='200',GITHUB_REPOSITORY='example/repo',GITHUB_SHA='a'*40)
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,env),patch.object(remote,'run_info',return_value=current),patch.object(remote,'api',return_value=dict(workflow_runs=[earlier])):
            with self.assertRaisesRegex(ValueError,'already been used'):
                remote.authorize(Path(td),'7X',2,'initial','100','',[])

    def test_missing_control_after_upload_failure_keeps_logs_and_allows_one_retry(self):
        from src.paper2.prototype import remote_authorization as remote
        current=dict(id=200,workflow_id=10,display_title='Paper2 G3 7X/initial/attempt-2 previous-100 ',run_attempt=1)
        previous=dict(id=100,display_title='Paper2 G3 7X/initial/attempt-1 previous- ',status='completed',conclusion='failure',head_sha='a'*40,run_attempt=1)
        def api(path,output=None):
            if output is not None:
                with zipfile.ZipFile(output,'w') as z:z.writestr('log.txt','SYNTHETIC infrastructure failure')
                return
            return dict(workflow_runs=[])
        env=dict(GITHUB_RUN_ID='200',GITHUB_REPOSITORY='example/repo',GITHUB_SHA='a'*40)
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,env),patch.object(remote,'run_info',side_effect=[current,previous]),patch.object(remote,'api',side_effect=api),patch.object(remote,'artifacts',return_value=[]):
            remote.authorize(Path(td),'7X',2,'initial','100','',[])
            receipt=replay.read(Path(td)/'authorization/previous.json')
            self.assertTrue(receipt['preserved']);self.assertEqual(receipt['available_artifacts'],[])
            self.assertIn('NOT RECORDED',receipt['evidence_scope'])

    def test_rehearsal_cannot_be_used_as_G3_and_timeout_rule(self):
        with tempfile.TemporaryDirectory() as td:
            replay.save(Path(td)/'INDEX.json',dict(purpose='DIAGNOSTIC rehearsal'))
            with self.assertRaisesRegex(ValueError,'excluded from G3'):replay.verify_index(td)
        self.assertEqual(timeout_minutes(600),60)
        self.assertEqual(timeout_minutes(1801),61)
        with self.assertRaises(ValueError):timeout_minutes(9901)

    def test_transport_checker_equivalence_on_deterministic_fixture(self):
        from src.paper2.prototype.validation_dryrun import create
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            original_initialize=replay.initialize
            def one_packet(*args,**kwargs):
                index=original_initialize(*args,**kwargs)
                # This test needs one full physical trace, not a G3 cohort.
                index['runs']=index['runs'][:1]
                return index
            with patch.object(replay,'initialize',side_effect=one_packet):
                create(root/'fixture','pass')
            packet=next((root/'fixture').rglob('REPLAY_MANIFEST.json')).parent
            # Existing full checker and metrics see exactly the same restored bytes.
            before=replay.postprocess_prototype(packet,root/'before')
            t.pack(packet,root/'transport');t.verify(root/'transport',output=root/'restored')
            after=replay.postprocess_prototype(root/'restored',root/'after')
            self.assertEqual(before['violations'],after['violations'])
            self.assertEqual(before['metrics'],after['metrics'])
            self.assertEqual(before['validity'],after['validity'])
            e1,_=replay.simulate(packet,packet/'primary.csv',root/'sim-original')
            e2,_=replay.simulate(root/'restored',root/'restored/primary.csv',root/'sim-restored')
            self.assertEqual(e1.read_bytes(),e2.read_bytes())
            self.assertEqual((e1.parent/'jobs.csv').read_bytes(),(e2.parent/'jobs.csv').read_bytes())

    def test_rehearsal_uses_existing_drain_dispatcher_and_one_second_stop_rules(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'prototype').mkdir()
            replay.save(root/'prototype/manifest.json',dict(prototype=dict(incomplete=False)))
            replay.save(root/'info.json',dict(cell=dict(dispatcher_utilisation=.2)))
            replay.save(root/'prototype/dispatcher_spans.json',[dict(start_t=30,end_t=30.5)])
            # Deviation 8 explicit drain census needs the same evidence as a sealed packet.
            (root/'prototype/progress.jsonl').write_text('{"phase":"drain_end","drain_complete":true,"q_admission":0,"q_block":0,"running":0}\n')
            (root/'prototype/jobs.csv').write_text('job_id,record\n')
            events=root/'prototype/events.csv';events.write_text('t,job_class,event\n31,block_tx,cache_hit\n')
            proto=dict(validity=dict(passed=True),violations=[])
            self.assertTrue(pr.rehearsal_stop_rules(root,proto)['passed'])
            events.write_text('t,job_class,event\n31,block_tx,cache_hit\n31,block_tx,cache_miss\n31,block_tx,cache_miss\n')
            result=pr.rehearsal_stop_rules(root,proto)
            self.assertFalse(result['passed']);self.assertEqual(result['sub_50_seconds'],[31])
            self.assertEqual(result['measurement_dispatcher_busy_fraction'],.5/60)

    def test_real_controller_seals_uploads_acknowledges_and_releases_one_group(self):
        from src.paper2.prototype import corpus
        from tests.paper2._support import config
        from tests.paper2.test_phase5a_deviation5 import Clock
        import csv,time
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);control=root/'control';control.mkdir();private=root/'private';private.mkdir()
            cfg=config(admissions=[dict(tx_id='a',arrival_t=30),dict(tx_id='b',arrival_t=30)],
                       blocks=[dict(block_id='B',tx_ids=['a','b'])],block_start=31)
            cp=corpus.write(corpus.build(cfg,'sleep'),private/'g.json')
            cell=dict(backend='sleep',k=1,policy='fifo',rho_cold=.85,rate=10,period=1,
                      dispatcher_utilisation=.1,cycle_means=dict.fromkeys(('admission','block_tx','block_sig'),.001),g3_input_version=6)
            refs={}
            for slot,reps in [('primary',(0,1)),('held_out',(2,))]:
                path=private/(slot+'.csv')
                with path.open('w',newline='') as f:
                    w=csv.writer(f);w.writerow(['backend','operation','variant','duration_ns','primitive_ns','job_class','source'])
                    for rep in reps:
                        for cls in ('admission','block_tx','block_sig'):
                            w.writerow(['sleep:'+cls,'verify','valid',1000000,1000000,cls,f'concurrency-cycle-k1-rep{rep}'])
                refs[slot+'_cycle_samples']=str(path)
            row=dict(run_id='cell5-r0',cell_id=5,cell=cell,replicate=0,group='g',transactions=2)
            state=dict(rows=[row],completed=[],known_objects={},uploads=[],signing_seconds={},
                       refs={'sleep':{'1':refs}},projection={'signing':{'sleep':{'cap_seconds':100}}},purpose=p.REHEARSAL)
            replay.save(control/'production-state.json',state)
            replay.save(control/'watchdog.json',dict(monotonic_ns=time.monotonic_ns()))
            clock=Clock(duration=1000000)
            def memory(pids=()):return dict(parent_pid=os.getpid(),rss_bytes={str(os.getpid()):100*1024**2},available_bytes=8*1024**3,total_bytes=16*1024**3)
            with clock.patches(),patch('src.paper2.prototype.gc_control.memory_snapshot',side_effect=memory),patch.object(p.runner,'fresh',side_effect=lambda fn,args,*a,**kw:fn(*args)):
                self.assertTrue(p.run_slot(control,0))
            pending=p.load(control)['pending'];shutil.copytree(pending['upload'],root/'verified/0')
            self.assertTrue(p.acknowledge(control,root/'verified/0',dict(id='123',digest='a'*64))['verified'])
            self.assertFalse(cp.exists());self.assertFalse(list((root/'working').rglob('events.csv')))
            p.finalize(control)
            self.assertEqual(p.load(control)['operational_status'],'complete')
            p.seal_control(control)
            bootstrap=replay.read(root/'control-upload/CONTROL.json')
            self.assertEqual(bootstrap['part_sha256'],replay.sha256_file(control/'PART.json'))
            self.assertEqual(t.read_file(root/'control-upload','PART.json'),(control/'PART.json').read_bytes())

    def test_synthetic_rehearsal_transport_matrix_and_sealed_gather(self):
        from src.paper2.prototype.validation_dryrun import create
        from src.paper2.prototype import artifact_integrity,replay_progress
        from src.paper2.model.engine import _git_state
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);original_initialize=replay.initialize
            def two_packets(*args,**kwargs):
                index=original_initialize(*args,**kwargs)
                index['runs']=[r for r in index['runs'] if r['replicate']==0 and r['cell_id'] in (0,2)]
                return index
            with patch.object(replay,'initialize',side_effect=two_packets):create(root/'fixture','pass')
            downloads=root/'downloads';downloads.mkdir();cells={};rows=[];known={}
            for old,new,aid in [(2,5,'101'),(0,9,'102')]:
                packet=root/'fixture'/f'cell{old}-r0';info=replay.read(packet/'info.json');cells[new]=info['cell']
                destination=downloads/('packet-'+aid);doc=t.pack(packet,destination,known)
                for key,value in doc['objects'].items():
                    if value['artifact'] is None:known[key]=aid
                rows.append(dict(run_id=f'cell{new}-r0',cell_id=new,replicate=0,cell=info['cell'],transactions=240,
                    info=info,manifest_sha256=replay.sha256_file(packet/'REPLAY_MANIFEST.json'),
                    transport_sha256=replay.sha256_file(destination/'TRANSPORT.json'),artifact=dict(id=aid,digest='a'*64)))
            control=downloads/'control';control.mkdir();code=_git_state()['commit']
            replay.save(control/'PART.json',dict(purpose=p.REHEARSAL,mode='initial',part='7X',attempt=1,
                operational_status='complete',code_commit=code,source_run_id='123',cells=cells,rows=rows,completed=rows))
            artifact_integrity.write_checksums(control)
            receipt=dict(replay_code_commit=code,replay_tree_clean=True,host=dict(runner_label='SYNTHETIC',os_image='SYNTHETIC',cpu_model='SYNTHETIC'))
            # Simulate a clean GitHub checkout receipt; all data are fake-clock
            # fixtures and can never be admitted to a production G3 gather.
            with pr.diagnostic_context(True),patch.object(replay_progress,'checkout_receipt',return_value=receipt):
                for row in rows:
                    rid=row['run_id'];restored=root/(rid+'-restored')
                    pr.restore(downloads,restored,rid,True)
                    out=root/(rid+'-replay');result=replay.execute(restored,rid,out)
                    self.assertNotIn('execution_error',result)
                    replay.save(out/'REHEARSAL_STOP_RULES.json',pr.rehearsal_stop_rules(restored/rid,result['prototype']))
                    replay.seal(out,'RESULT_MANIFEST.json')
                    pr.result_capsule(out,root/'results'/rid,'SYNTHETIC-evidence-'+rid)
                report=pr.gather(downloads,root/'results',root/'gather',True)
                self.assertTrue(report['passed'])
                self.assertIn('DIAGNOSTIC',report['purpose']);replay.verify_aggregate(root/'gather')


if __name__=='__main__':unittest.main()
