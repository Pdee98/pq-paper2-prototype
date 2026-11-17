"""Pre-dispatch v2 requirements; expected Q7 arithmetic is handwritten."""
from tests.paper2._provenance import setUpModule,tearDownModule
import copy,csv,hashlib,json,os,re,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from src.paper2.prototype import rehearsal_v2 as v2,rehearsal_v2_q7 as q7
from src.paper2.prototype import production,replay,empirical_replay as empirical
from src.paper2.prototype import measurement_conditions as mc,stage_capture as capture
from tests.paper2.test_phase5a_phasef_preparation import cleanup

ROOT=Path(__file__).resolve().parents[2]


def records():
    # Prototype block/wait 10/10, legacy 20/14, explicit 12/11:
    # closure=(10-2)/10=.8; admission magnitude 1 < 4, in all four.
    rest=dict(p95_block_delay=20,admission_throughput=100,deadline_miss_rate=0,complete=True)
    p=dict(rest,mean_block_delay=10,mean_admission_wait=10)
    return [dict(cell=dict(backend=b,k=k),prototype=dict(metrics=copy.deepcopy(p),validity=dict(passed=True),violations=[]),
        models={mode:{slot:dict(metrics=dict(rest,mean_block_delay=delay,mean_admission_wait=wait),violations=[])
            for slot in ('primary','held_out')} for mode,delay,wait in (('legacy',20,14),('explicit',12,11))})
        for b,k in (('xmss',2),('ml_dsa_44',1))]


class RehearsalV2(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ,{'ATTEMPT':'1','PREVIOUS_RUN':''}))

    def test_attempt_requires_sealed_first_failure_and_never_allows_three(self):
        from src.paper2.prototype import rehearsal_v2_attempts as attempts
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError,'attempt 2 requires'):
                attempts.authorize(Path(td),2,'')
            for prior in (None,dict(namespace=v2.NAMESPACE,attempt=1,source_run_id='100',status='complete',retryable=False)):
                with self.assertRaisesRegex(ValueError,'sealed failure/INVALID'):attempts.validate(2,'100',prior)
            for status in ('failure','INVALID'):
                self.assertEqual(attempts.validate(2,'100',dict(namespace=v2.NAMESPACE,attempt=1,source_run_id='100',status=status,retryable=True)),2)
            with self.assertRaisesRegex(ValueError,'only attempts'):attempts.validate(3,'100')
            artifact=Path(td)/'sealed';artifact.mkdir();replay.save(artifact/'result.json',dict(attempt=1,status='INVALID'))
            replay.seal(artifact,'RESULT_MANIFEST.json')
            with patch.object(attempts.remote,'artifacts',return_value=[dict(name='evidence',id=1)]),patch.object(attempts.remote,'download',return_value=artifact):
                self.assertEqual(attempts.sealed_download('100','evidence',Path(td)/'unused')['attempt'],1)
                replay.save(artifact/'result.json',dict(attempt=1,status='tampered'))
                with self.assertRaisesRegex(ValueError,'SHA-256'):attempts.sealed_download('100','evidence',Path(td)/'unused')

    def test_attempt_ledger_and_results_have_sealed_attempt_identity(self):
        from src.paper2.prototype import rehearsal_v2_attempts as attempts
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);authorization=root/'attempt-authorization';authorization.mkdir()
            prior=dict(namespace=v2.NAMESPACE,attempt=1,source_run_id='100',status='failure',retryable=True)
            replay.save(authorization/'result.json',dict(namespace=v2.NAMESPACE,attempt=2,attempt_1_run_id='100',prior_outcome=prior,accepted=True))
            replay.seal(authorization,'RESULT_MANIFEST.json')
            with patch.dict(os.environ,{'ATTEMPT':'2','PREVIOUS_RUN':'100'}):
                ledger=v2.write_ledger(root)
            self.assertEqual(v2.verify_ledger(root)['attempt'],2);self.assertEqual(ledger['attempt_1_run_id'],'100')
            self.assertEqual(attempts.load(root,2)['attempt'],2)

    def test_attempt2_repository_authorisation_and_duplicate_refusal(self):
        from src.paper2.prototype import rehearsal_v2_attempts as a
        current=dict(id=200,workflow_id=7,display_title=a.PREFIX+'2 previous-100',run_attempt=1)
        previous=dict(head_sha='a'*40,status='completed',run_attempt=1,display_title=a.PREFIX+'1 previous-')
        prior=dict(namespace=v2.NAMESPACE,attempt=1,source_run_id='100',status='INVALID',retryable=True,repository='owner/repo',code_commit='a'*40)
        env=dict(GITHUB_RUN_ID='200',GITHUB_SHA='a'*40,GITHUB_REPOSITORY='owner/repo')
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,env):
            with patch.object(a.remote,'run_info',side_effect=[current,previous]),patch.object(a.remote,'api',return_value=dict(workflow_runs=[])),patch.object(a,'sealed_download',return_value=dict(prior,retryable=False)):
                with self.assertRaisesRegex(ValueError,'sealed failure/INVALID'):a.authorize(Path(td)/'bad',2,'100')
            with patch.object(a.remote,'run_info',side_effect=[current,previous]),patch.object(a.remote,'api',return_value=dict(workflow_runs=[])),patch.object(a,'sealed_download',return_value=prior):
                accepted=a.authorize(Path(td)/'good',2,'100')
            self.assertEqual(accepted['attempt'],2);self.assertEqual(a.load(Path(td)/'good',2)['attempt_1_run_id'],'100')
            with patch.object(a.remote,'run_info',return_value=current),patch.object(a.remote,'api',return_value=dict(workflow_runs=[dict(id=199,display_title=a.PREFIX+'2 previous-100')])):
                with self.assertRaisesRegex(ValueError,'already used'):a.authorize(Path(td)/'third',2,'100')

    def test_attempt_failure_receipt_is_separate_sealed_and_retryable_once(self):
        from src.paper2.prototype import rehearsal_v2_attempts as a
        env=dict(GITHUB_RUN_ID='200',GITHUB_SHA='a'*40,GITHUB_REPOSITORY='owner/repo')
        auth=dict(namespace=v2.NAMESPACE,attempt=1,source_run_id='200',code_commit='a'*40,repository='owner/repo',accepted=True)
        def download(run,name,destination):
            destination=Path(destination);destination.mkdir(parents=True)
            replay.save(destination/'result.json',auth);replay.seal(destination,'RESULT_MANIFEST.json');return auth
        needs=dict(g3=dict(result='failure'),**{'prepare-replay':dict(result='skipped'),'replay':dict(result='skipped'),'q7':dict(result='skipped')})
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,env),patch.object(a,'sealed_download',side_effect=download),patch.object(a.remote,'artifacts',return_value=[]),patch.object(a.remote,'api',return_value=dict(jobs=[])):
            result=a.outcome(Path(td)/'outcome',1,'',needs)
            self.assertEqual(result['status'],'failure');self.assertTrue(result['retryable']);self.assertEqual(result['attempt'],1)
            replay.verify_files(Path(td)/'outcome','RESULT_MANIFEST.json')
            self.assertFalse((Path(td)/'outcome/UNVERIFIED').exists())

    def test_both_rehearsal_backends_use_their_own_caps_despite_7x_label(self):
        from src.paper2.prototype.cycle_protocol import cold_cycle_reference
        from src.paper2.prototype import rehearsal_v2_attempts
        refs={b:{k:cold_cycle_reference(k,dict(admission=.1,block_tx=.1,block_sig=.1),.001) for k in (1,2)} for b in ('xmss','ml_dsa_44')}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'control';root.mkdir();replay.save(root/'conformance.json',dict(fixture=True));v2.write_ledger(root)
            with patch.object(production.runner.platform,'machine',return_value='aarch64'),patch.object(production.os,'sched_getaffinity',return_value=set(range(4)),create=True),patch.object(rehearsal_v2_attempts,'load',return_value=dict(attempt=1)),patch.object(production,'require_budget'),patch.object(production.runner,'fresh',return_value={}),patch.object(production.transport,'disk_guard',return_value={}),patch.object(production,'calibrate_backend',side_effect=lambda backend,*args:refs[backend]) as calibration:
                state=production.prepare(root,'7X',purpose=v2.NAMESPACE)
            self.assertEqual(set(state['cells']),{5,9})
            self.assertEqual({r['cell']['backend'] for r in state['rows']},{'xmss','ml_dsa_44'})
            self.assertEqual([(c.args[0],c.args[4]) for c in calibration.call_args_list],[('xmss',1200),('ml_dsa_44',1900)])
            self.assertEqual(set(state['projection']['signing']),{'xmss','ml_dsa_44'})

    def test_run_output_path_contract_and_attempt_in_sealed_capsule(self):
        with tempfile.TemporaryDirectory() as td:
            temp=Path(td);destination=temp/'v2-inputs';control=destination/'control';control.mkdir(parents=True);v2.write_ledger(control)
            part=dict(attempt=1,source_run_id='77',code_commit='a'*40,completed=[dict(run_id='cell5',cell_id=5,cell=dict(dispatcher_utilisation=.2))])
            def execute(packet,inputs,output,**kwargs):
                output=Path(output);output.mkdir();value=dict(kwargs['identity'],prototype=dict(validity=dict(passed=True)))
                replay.save(output/'result.json',value);(output/'replay-progress.jsonl').write_text('{}\n')
                replay.seal(output,'RESULT_MANIFEST.json');return value
            with patch.object(v2,'fetch_current',return_value=part),patch.object(empirical,'execute',side_effect=execute),patch('src.paper2.prototype.measurement_conditions.apply'),patch.dict(os.environ,{'GITHUB_RUN_ID':'88'}):
                v2.run(destination,'cell5',temp/'result')
            self.assertTrue((temp/'evidence/TRANSPORT.json').is_file());self.assertTrue((temp/'capsule/RESULT_MANIFEST.json').is_file())
            replay.verify_files(temp/'capsule','RESULT_MANIFEST.json')
            self.assertEqual(replay.read(temp/'capsule/result.json')['attempt'],1)

    def test_failure_evidence_missing_source_and_job_specific_paths(self):
        from src.paper2.prototype import failure_evidence
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);existing=root/'result';existing.mkdir();(existing/'progress.jsonl').write_text('public partial evidence')
            retained=failure_evidence.preserve(root/'failed',[root/'absent',existing])
            self.assertEqual(len(retained),1);self.assertTrue((root/'failed/UNVERIFIED').is_file())
        text=(ROOT/'src/paper2/prototype/paper2-g3-rehearsal-v2.yml').read_text()
        replay_job=text.split('\n  replay:\n')[1].split('\n  q7:\n')[0]
        q7_job=text.split('\n  q7:\n')[1].split('\n  attempt-outcome:\n')[0]
        for name in ('result','v2-inputs','evidence','capsule'):
            self.assertIn('"$RUNNER_TEMP/'+name+'"',replay_job)
        self.assertIn('"$RUNNER_TEMP/results"',q7_job);self.assertIn('"$RUNNER_TEMP/q7"',q7_job)
        self.assertNotIn('"$RUNNER_TEMP/v2-inputs"',q7_job)

    def test_production_selector_only_accepts_sealed_reproducible_q7_reader(self):
        from src.paper2.prototype.production_replay import result_capsule
        from src.paper2.prototype import rehearsal_v2_q7
        code='a'*40
        reader=hashlib.sha256(Path(rehearsal_v2_q7.__file__).read_bytes()).hexdigest()
        self.assertEqual(reader,'b499e9d566af491816fa8ac9d80ddcc30b3a0422becb60259e9746adc7262180')
        def sealed(root,values):
            inputs=root/'inputs';inputs.mkdir(parents=True)
            for i,record in enumerate(values):
                raw=root/('raw'+str(i));raw.mkdir()
                record=dict(record,namespace=v2.NAMESPACE,run_id='fixture-'+str(i),code_commit=code,reader_source_sha256=reader,attempt=1)
                replay.save(raw/'result.json',record);(raw/'replay-progress.jsonl').write_text('{}\n')
                replay.seal(raw,'RESULT_MANIFEST.json',dict(provenance=dict(source_code_commit=code,replay_code_commit=code,replay_tree_clean=True)))
                result_capsule(raw,inputs/str(i),'fixture-evidence-'+str(i))
            with patch.dict(os.environ,{'GITHUB_SHA':code}):v2.gather(inputs,root/'gather')
            return root/'gather'
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            good=sealed(root/'supported',records())
            self.assertEqual(empirical.selection(good,code),'explicit')
            r=records();r[0]['models']['explicit']['primary']['metrics']['mean_block_delay']=13.01
            unsupported=sealed(root/'unsupported',r)
            self.assertEqual(empirical.selection(unsupported,code),'legacy')
            r=records();del r[0]['models']['explicit']['primary']
            invalid=sealed(root/'invalid',r)
            with self.assertRaisesRegex(ValueError,'INVALID.*no model selection'):empirical.selection(invalid,code)
            value=replay.read(good/'result.json');value['reader_source_sha256']='0'*64
            replay.save(good/'result.json',value);replay.seal(good,'RESULT_MANIFEST.json')
            with self.assertRaisesRegex(ValueError,'reader digest'):empirical.selection(good,code)
            value['reader_source_sha256']=reader;value['verdict']='NOT SUPPORTED'
            replay.save(good/'result.json',value);replay.seal(good,'RESULT_MANIFEST.json')
            with self.assertRaisesRegex(ValueError,'reproduce'):empirical.selection(good,code)
            historical=root/'historical';historical.mkdir()
            replay.save(historical/'mechanism.json',dict(reading='MECHANISM SUPPORTED',reader_source_sha256='f'*64))
            replay.seal(historical,'MECHANISM_MANIFEST.json')
            with self.assertRaisesRegex(ValueError,'Q7 reader'):empirical.selection(historical,code)

    def test_q7_hand_arithmetic_all_four_and_signs(self):
        result=q7.evaluate(records());self.assertEqual(result['verdict'],'SUPPORTED')
        self.assertEqual(len(result['comparisons']),4)
        for row in result['comparisons']:
            self.assertEqual(row['closure'],.8)
            self.assertEqual(row['signed_errors']['mean_block_delay'],dict(legacy=10,explicit=2))
            self.assertEqual(row['admission_errors']['legacy_absolute'],4)
        self.assertIn('one measured repetition',result['disclosure'].lower())
        self.assertIn('two complete models',result['disclosure'])
        r=records();r[0]['models']['explicit']['primary']['metrics']['mean_block_delay']=8
        self.assertEqual(q7.evaluate(r)['comparisons'][0]['signed_errors']['mean_block_delay']['explicit'],-2)

    def test_q7_699_tie_zero_and_negative_closure(self):
        for field,value in (('mean_block_delay',13.01),('mean_admission_wait',14)):
            r=records();r[0]['models']['explicit']['primary']['metrics'][field]=value
            self.assertEqual(q7.evaluate(r)['verdict'],'NOT SUPPORTED')
        r=records();r[0]['models']['legacy']['primary']['metrics']['mean_block_delay']=10
        value=q7.evaluate(r);self.assertEqual(value['verdict'],'NOT SUPPORTED');self.assertIsNone(value['comparisons'][0]['closure'])
        r=records();r[0]['models']['explicit']['primary']['metrics']['mean_block_delay']=35
        value=q7.evaluate(r);self.assertEqual(value['verdict'],'NOT SUPPORTED');self.assertEqual(value['comparisons'][0]['closure'],-1.5)

    def test_q7_invalid_precedence_missing_and_each_correctness_family(self):
        r=records();del r[1]['models']['explicit']['held_out']
        self.assertEqual(q7.evaluate(r)['verdict'],'INVALID')
        for location in ('prototype','legacy','explicit'):
            r=records();target=r[0]['prototype'] if location=='prototype' else r[0]['models'][location]['primary']
            target['violations']=['hand-planted G1 violation']
            self.assertEqual(q7.evaluate(r)['verdict'],'INVALID')
        for failure in ('drain','planned_dispatcher','observed_dispatcher','cycle_stationarity','admission_count','starvation','cohort_hits','memory','transport'):
            r=records();r[0]['prototype']['validity']=dict(passed=False,reason=failure)
            self.assertEqual(q7.evaluate(r)['verdict'],'INVALID')
        self.assertEqual(q7.evaluate(records()[:1])['verdict'],'INVALID')

    def test_dip_alone_is_diagnostic_and_not_a_q7_invalid_condition(self):
        conditions=mc.evaluate([],[],[dict(t=31,event='cache_miss',job_class='block_tx')],True,False)
        self.assertTrue(conditions['passed']);self.assertEqual(conditions['cache_bin_diagnostic']['minimum_one_second_hit_rate'],0)
        r=records();r[0]['prototype']['validity']['measurement_conditions']=conditions
        self.assertEqual(q7.evaluate(r)['verdict'],'SUPPORTED')

    def test_seed_overlap_is_hard_failure_and_all_identities_namespaced(self):
        ledger=v2.seed_ledger();self.assertEqual(ledger['overlap_count'],0)
        self.assertTrue(all(e['identity'].startswith('paper2-g3-rehearsal-v2-') for e in ledger['entries']))
        with self.assertRaisesRegex(ValueError,'overlap'):v2.seed_ledger(v2.identities(v2.NAMESPACE))
        with tempfile.TemporaryDirectory() as td:
            v2.write_ledger(td);self.assertEqual(v2.verify_ledger(td),ledger)
            (Path(td)/'SEED_LEDGER.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'seal'):v2.verify_ledger(td)

    def test_cells_namespace_policy_and_slot_mapping(self):
        from src.paper2.prototype.cycle_protocol import cold_cycle_reference
        refs={b:{k:cold_cycle_reference(k,dict(admission=.001,block_tx=.001,block_sig=.001),.0001) for k in (1,2)} for b in ('xmss','ml_dsa_44')}
        cells,rows,groups=production.plan(refs,'7X',v2.NAMESPACE)
        self.assertEqual(set(cells),{5,9});self.assertEqual(len(rows),2)
        self.assertEqual({(r['cell']['backend'],r['cell']['k'],r['cell']['policy'],r['replicate']) for r in rows},{('xmss',2,'fifo',0),('ml_dsa_44',1,'fifo',0)})
        self.assertTrue(all(r['run_id'].startswith(v2.NAMESPACE+'-') for r in rows))
        for r in rows:self.assertTrue(production.parameters(r['cell'],0,v2.NAMESPACE)['run_id'].startswith(v2.NAMESPACE+'-'))
        self.assertEqual(v2.dispatcher_tables.SLOTS,dict(primary=(0,1),held_out=(2,)))

    def test_capture_in_place_timers_are_report_only_and_partition_survives(self):
        with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'PAPER2_CAPTURE_TIMERS':'1'}):
            r=capture.Recorder(td,100,dict(window='fixture'));b=capture.Boundaries(r)
            b.begin(0,capture.F['arrival'],capture.S['arrival_pre']);b.end(100)
            result=r.finish(True,100);cost=result['append_cost']
            self.assertEqual(cost['count'],2) # outer begin/end; no nested double count
            for field in ('mean_ns','p50_ns','p95_ns','p99_ns','max_ns','total_ns','dispatcher_share','timer_overhead'):
                self.assertIn(field,cost)
            self.assertFalse(result['overhead_subtracted']);self.assertTrue(capture.audit(td)['passed'])

    def test_legacy_rehearsal_configuration_and_service_input_byte_identity(self):
        # Registered replay.simulate is called verbatim for legacy; occupancy
        # differs deliberately from duration to catch a hybrid input adapter.
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=root/'packet';packet.mkdir()
            config=dict(run_id=v2.NAMESPACE+'-fixture',k=2,policy=dict(name='fifo'))
            replay.save(packet/'config.json',config);replay.save(packet/'info.json',dict(mapped=dict(structural_cost=.001,state_cost=.002)))
            sample=root/'primary.csv';sample.write_text('backend,job_class,operation,variant,duration_ns,occupancy_ns\nxmss:admission,admission,verify,valid,900000,400000\n')
            seen=[]
            def run_model(cfg,model_type):
                seen.append((json.dumps(cfg,sort_keys=True).encode(),sample.read_bytes()))
                return 'events','manifest'
            # The v2 adapter's legacy function is exactly the registered path.
            with patch.object(replay,'run_model',side_effect=run_model):
                replay.simulate(packet,sample,root/'same-output')
                empirical.replay.simulate(packet,sample,root/'same-output')
            self.assertEqual(seen[0],seen[1])
            from src.paper2.prototype.analysis import CapturedService
            self.assertEqual(CapturedService(sample,'xmss').sample('admission','valid',0)[0],.0009)

    def test_real_adapter_legacy_slots_match_registered_configuration_and_inputs(self):
        from tests.paper2.test_phase5a_deviation9_empirical import inputs
        from tests.paper2.test_phase5a_deviation5 import Clock,Deviation5
        from src.paper2.prototype import corpus,runtime
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);costs=inputs(root/'costs')
            doc=corpus.build(Deviation5().fixture(dict(name='fifo')),'sleep');cp=corpus.write(doc,root/'corpus.json')
            cfg=dict(doc['workload'],output_dir=str(root/'prototype'))
            with Clock().patches():events,manifest=runtime.run(cfg,cp)
            sample_paths={}
            for slot,reps in (('primary',(0,1)),('held_out',(2,))):
                rows=[]
                for rep in reps:
                    with (root/'costs'/f'r{rep}'/'cycles.csv').open(newline='') as f:rows.extend(csv.DictReader(f))
                sample_paths[slot]=root/(slot+'.csv')
                with sample_paths[slot].open('w',newline='') as f:
                    writer=csv.DictWriter(f,fieldnames=tuple(rows[0]));writer.writeheader();writer.writerows(rows)
            packet=root/'packet'
            replay.create_packet(packet,cfg,cp,dict(events=str(events),manifest=str(manifest)),sample_paths['held_out'],
                dict(backend='sleep',k=1,policy='fifo',g3_input_version=6),0,window=(0,.1),primary=sample_paths['primary'])
            empirical.bind(packet,costs)
            baseline=[];observed=[];original=replay.run_model
            def record(target):
                def wrapped(config,**kwargs):
                    copy_config=copy.deepcopy(config);copy_config.pop('output_dir')
                    target.append(json.dumps(copy_config,sort_keys=True).encode())
                    return original(config,**kwargs)
                return wrapped
            with patch.object(replay,'run_model',side_effect=record(baseline)):
                for slot,name in (('primary','primary.csv'),('held_out','held-out.csv')):
                    replay.simulate(packet,packet/name,root/('reference-'+slot))
            before={n:(packet/n).read_bytes() for n in ('primary.csv','held-out.csv')}
            with patch.object(replay,'run_model',side_effect=record(observed)):
                result=empirical.execute(packet,costs,root/'replay',purpose='rehearsal-v2')
            self.assertEqual(observed,baseline)
            self.assertEqual(before,{n:(packet/n).read_bytes() for n in before})
            for slot in ('primary','held_out'):
                self.assertEqual(result['models']['legacy'][slot]['violations'],[])
                for name in ('events.csv','jobs.csv'):
                    self.assertEqual((root/('reference-'+slot)/name).read_bytes(),(root/'replay/legacy'/slot/name).read_bytes())

    def test_workflow_manual_pinned_separated_and_immutable_templates(self):
        base=ROOT/'src/paper2/prototype';text=(base/'paper2-g3-rehearsal-v2.yml').read_text()
        triggers=re.findall(r'^on:\n(.*?)(?=^\S)',text,re.M|re.S)
        self.assertEqual(len(triggers),1);self.assertTrue(triggers[0].startswith('  workflow_dispatch:\n'))
        self.assertEqual(re.findall(r'^      ([a-z0-9_]+):$',triggers[0],re.M),['attempt','attempt_1_run_id'])
        self.assertIn('runs-on: ubuntu-24.04-arm',text);self.assertIn('timeout-minutes: 330',text)
        self.assertEqual(hashlib.sha256(cleanup(text).encode()).hexdigest(),hashlib.sha256(cleanup((base/'paper2-g3-rehearsal.yml').read_text()).encode()).hexdigest())
        for action in re.findall(r'uses: (\S+)',text):self.assertRegex(action,r'@[0-9a-f]{40}$')
        self.assertIn('LIMIT = 280*60',text);self.assertIn("PAPER2_CAPTURE_TIMERS: '1'",text)
        self.assertEqual(text.count('nohup python -m src.paper2.prototype.rehearsal_v2 disk-monitor '),1)
        self.assertIn("options: ['1', '2']",text);self.assertIn("default: '1'",text)
        self.assertIn('ATTEMPT: ${{ inputs.attempt }}',text)
        self.assertIn('rehearsal_v2_attempts authorize',text);self.assertIn('rehearsal_v2_attempts outcome',text)
        self.assertLess(text.index('rehearsal_v2 ledger'),text.index('production prepare'))
        self.assertIn('Both registered models, both slots, independent G1 each',text)
        self.assertIn('needs: [prepare-replay, replay]',text)
        self.assertIn('failed-attempt-evidence-',text);self.assertIn('/UNVERIFIED',text)
        self.assertEqual(hashlib.sha256((base/'paper2-g3.yml').read_bytes()).hexdigest(),'b04b725b93f0dd3325b5fe708759c75c718804d888314d3b2e19f60ce4efa4f6')
        self.assertEqual(hashlib.sha256((base/'paper2-g3-rehearsal.yml').read_bytes()).hexdigest(),'80f9a73c225745da18a3f37805f36db8efdae9a324dbf941b5dcb0cc89965a2c')
