"""Two-source validation provenance, inventory, identities and failed attempts."""
import tempfile
import unittest
from pathlib import Path
from src.paper2.prototype import replay,split_replay,artifact_integrity


def part(root,label,commit='a'*40,attempt=1,complete=True):
    ids=list(range(8))+[16] if label=='7X' else list(range(8,16))
    backend='xmss' if label=='7X' else 'ml_dsa_44'
    cells=[dict(backend=backend,k=1 if i%8<4 else 2,policy='fifo' if i%4<2 else 'block_priority',
                rho_cold=.5 if i%2==0 else .85,dispatcher_utilisation=.1,
                **({'role':'secondary'} if i==16 else {})) for i in ids]
    source='101' if label=='7X' else '102'
    index=replay.initialize(root,cells,[],commit,source,cell_ids=ids)
    index['part_receipt']=dict(part=label,attempt=attempt,operational_status='complete' if complete else 'failed')
    if attempt==2:index['part_receipt']['previous_attempt_evidence']=dict(attempt=1,preserved=True,operational_status='failed',code_commit=commit)
    for run in index['runs']:
        directory=root/run['run_id']
        replay.save(directory/'info.json',dict(source_commit=commit,replicate=run['replicate'],cell=replay.cell_map(index)[run['cell_id']]))
        replay.seal(directory,'REPLAY_MANIFEST.json')
        run['manifest_sha256']=replay.sha256_file(directory/'REPLAY_MANIFEST.json')
    index['status']=replay.PENDING;replay.write_index(root,index);artifact_integrity.write_checksums(root)
    return index


class Split(unittest.TestCase):
    def test_two_source_union_preserves_ids_and_source_commits(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);part(root/'x','7X');part(root/'m','7M')
            result=split_replay.union(root/'x',root/'m',root/'union','101','102')
            self.assertEqual(len(result['runs']),49)
            self.assertEqual(result['source_run_ids'],['101','102'])
            self.assertEqual(result['cell_ids'],list(range(17)))
            self.assertEqual({r['source_run_id'] for r in result['runs'] if r['cell_id']<8},{'101'})
            self.assertEqual({r['source_run_id'] for r in result['runs'] if 8<=r['cell_id']<16},{'102'})
            self.assertEqual(replay.verify(root/'union','101'),result)

    def test_wrong_commit_or_incomplete_part_is_rejected(self):
        for mismatch in ('commit','incomplete','third_attempt'):
            with self.subTest(mismatch=mismatch),tempfile.TemporaryDirectory() as td:
                root=Path(td);part(root/'x','7X')
                part(root/'m','7M',commit='b'*40 if mismatch=='commit' else 'a'*40,
                     complete=mismatch!='incomplete',attempt=3 if mismatch=='third_attempt' else 1)
                with self.assertRaises(ValueError):split_replay.union(root/'x',root/'m',root/'union','101','102')

    def test_second_attempt_retains_first_attempt_and_excludes_its_results(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);part(root/'x','7X',attempt=2);part(root/'m','7M')
            result=split_replay.union(root/'x',root/'m',root/'union','101','102')
            self.assertEqual(len(result['runs']),49)
            receipt=result['part_receipts'][0]
            self.assertEqual(receipt['attempt'],2)
            self.assertEqual(receipt['previous_attempt_evidence']['operational_status'],'failed')
            self.assertTrue(receipt['previous_attempt_evidence']['preserved'])

    def test_absent_payload_fails_before_union(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);part(root/'x','7X');part(root/'m','7M')
            (root/'x/cell0-r0/info.json').unlink()
            with self.assertRaisesRegex(ValueError,'missing artifact'):split_replay.union(root/'x',root/'m',root/'union','101','102')


if __name__=='__main__':unittest.main()
