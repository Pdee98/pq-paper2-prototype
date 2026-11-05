"""Compact evidence transport and independently checked versioned identities."""
from tests.paper2._provenance import setUpModule,tearDownModule
import copy,csv,hashlib,json,tempfile,unittest,zipfile
from pathlib import Path
from src.paper2.prototype import compact,corpus,public_corpus,replay,runtime
from src.paper2.verify.invariants import check
from tests.paper2._support import config

class CompactCorpus(unittest.TestCase):
    def test_binary_lossless_types_and_rejects_truncation_or_trailing_data(self):
        value=dict(raw=bytes(range(256)),positive=2**64-1,negative=-17,
            null=None,flags=[True,False],number=.125,text='signed fields',digest='a'*64)
        raw=compact.pack(value)
        self.assertEqual(compact.unpack(raw),value)
        for broken in (raw[:-1],raw+b'extra',b'wrong'+raw):
            with self.assertRaises(ValueError):compact.unpack(broken)

    def fixture(self):
        return config(admissions=[dict(tx_id='a',arrival_t=0),dict(tx_id='b',arrival_t=.001)],
            blocks=[dict(block_id='B',tx_ids=['a','b'])],block_start=.03,
            cache=dict(capacity=32),pool=dict(enabled=True,capacity_bytes=100000))

    def test_v1_v2_equality_partition_distinct_signatures_and_tags(self):
        context=corpus.CONTEXT;public=b'p'*32;payload=b'same signed fields';sig=b'a'*64
        cases=[(context,public,payload,0,sig),(context,public,payload,0,sig),
            (context,public,payload,0,b'b'*64),(context,public,payload,1,sig),
            (dict(context,chain_id='other'),public,payload,0,sig),(context,b'q'*32,payload,0,sig)]
        old=[corpus.cache_key_v1(*x) for x in cases];new=[corpus.cache_key(*x) for x in cases]
        for i in range(len(cases)):
            self.assertNotEqual(old[i],new[i])
            for j in range(len(cases)):self.assertEqual(old[i]==old[j],new[i]==new[j])
        self.assertNotEqual(new[0],new[2])
        expected=hashlib.sha256(corpus.canonical([corpus.KEY_VERSION]+[context[k] for k in corpus.CONTEXT]+[
            hashlib.sha256(public).hexdigest(),dict(payload_hex=payload.hex(),nonce=0),hashlib.sha256(sig).hexdigest()])).hexdigest()
        self.assertEqual(new[0],expected)

    def test_arm_audit_rejects_signature_leaf_and_root_mismatch(self):
        doc=corpus.build(self.fixture(),'sleep')
        receipt=compact.audit_full(doc)
        self.assertEqual((receipt['signature_ids_checked'],receipt['wire_leaves_checked'],receipt['block_roots_checked']),(2,2,1))
        missing=copy.deepcopy(doc);del missing['transactions']['a']
        with self.assertRaisesRegex(ValueError,'coverage mismatch'):compact.audit_full(missing)
        for field,message in (('signature_id','signature_id mismatch'),('wire_leaf_hash','Merkle leaf mismatch'),('merkle_root','Merkle root mismatch')):
            bad=copy.deepcopy(doc)
            if field=='signature_id':bad['workload']['transactions']['a'][field]='0'*64
            elif field=='wire_leaf_hash':bad['transactions']['a'][field]='0'*64
            else:bad['block_objects']['B'][field]='0'*64
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,message):compact.audit_full(bad)

    def test_compact_full_checker_equivalence_and_corrupt_archive_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);doc=corpus.build(self.fixture(),'sleep');cp=corpus.write(doc,root/'full.json')
            cfg0=dict(doc['workload'],g3_input_version=6,calibration_cycle_means=dict.fromkeys(('admission','block_tx','block_sig'),.001))
            e,m=runtime.run(dict(cfg0,output_dir=str(root/'prototype')),cp,sleep_seconds=.001)
            progress=[json.loads(line) for line in (e.parent/'progress.jsonl').read_text().splitlines()]
            guard=next(row['prototype_validity'] for row in progress if row['phase']=='cycle_stationarity')
            self.assertEqual(guard['class_checks']['admission']['status'],'NOT OBSERVED')
            self.assertEqual(check(e,e.parent/'jobs.csv',m),[])
            held=replay.samples_from_jobs(e.parent/'jobs.csv',root/'held.csv','sleep','concurrency-k1-rep0')
            packet=root/'inputs/run';replay.create_packet(packet,doc['workload'],cp,dict(events=str(e),manifest=str(m)),held,
                dict(backend='sleep',k=1,policy='fifo',rho=.5,rate=2,period=1,dispatcher_utilisation=.1),0)
            moved=public_corpus.checker_manifest(packet,root/'check')
            self.assertEqual(check(packet/'prototype/events.csv',packet/'prototype/jobs.csv',moved),[])
            archive=packet/'prototype/public-corpus.zip'
            with zipfile.ZipFile(archive) as z:c=compact.unpack(z.read('corpus.bin'))
            self.assertEqual(c['version'],compact.FORMAT)
            self.assertNotIn(b'signature_hex',compact.pack(c));self.assertNotIn(b'public_key_hex',compact.pack(c))
            self.assertEqual(compact.expand(c)['workload']['transactions'],doc['workload']['transactions'])
            self.assertEqual(len(c['public_keys']),len({entry['key_id'] for group in ('transactions','blocks') for entry in doc[group].values()}))
            # The new replay path recomputes keys from the compact corpus and
            # shares one archive across policy packets rather than duplicating it.
            with held.open(newline='') as f:reader=csv.DictReader(f);fields=reader.fieldnames;rows=list(reader)
            for row in rows:row['source']='concurrency-cycle-k1-rep0'
            cycles=root/'cycles.csv'
            with cycles.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
            cfg=dict(doc['workload'],g3_input_version=6,calibration_cycle_means=dict.fromkeys(('admission','block_tx','block_sig'),.001))
            cell=dict(backend='sleep',k=1,policy='fifo',rho=.5,rate=2,period=1,dispatcher_utilisation=.1,g3_input_version=6)
            for name in ('policy-a','policy-b'):
                replay.create_packet(root/'shared-inputs'/name,cfg,cp,dict(events=str(e),manifest=str(m)),cycles,cell,0,
                    shared_public='shared-corpora/fixture/public-corpus.zip')
            self.assertEqual(len(list((root/'shared-inputs').rglob('public-corpus.zip'))),1)
            v6=root/'shared-inputs/policy-a'
            se,sm=replay.simulate(v6,v6/'primary.csv',root/'v6-simulation')
            self.assertEqual(check(se,se.parent/'jobs.csv',sm),[])
            keys=replay.read(v6/'keys.json');keys['a']['cache_key']='0'*64;replay.save(v6/'keys.json',keys)
            with self.assertRaisesRegex(ValueError,'recomputed compact v2 keys'):replay.ReplayModel(cfg,v6,v6/'primary.csv')
            archive.write_bytes(archive.read_bytes()+b'corruption')
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):replay.postprocess_prototype(packet,root/'corrupt-check')

    def test_compact_rejects_private_material_and_incorrect_counts(self):
        doc=corpus.build(self.fixture(),'sleep');c=compact.document(doc,compact.audit_full(doc));public_corpus.audit(c)
        bad=copy.deepcopy(c);bad['arm_audit']['signature_ids_checked']=1
        with self.assertRaisesRegex(ValueError,'count mismatch'):compact.expand(bad)
        bad=copy.deepcopy(c);bad['signing_state']={}
        with self.assertRaisesRegex(ValueError,'excluded'):public_corpus.audit(bad)
        bad=copy.deepcopy(c);bad['columns'][0]='private_seed'
        with self.assertRaisesRegex(ValueError,'excluded'):compact.expand(bad)

if __name__=='__main__':unittest.main()
