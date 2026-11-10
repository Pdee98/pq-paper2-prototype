"""The preparation bundle cannot execute validation; timing never assesses G3."""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from src.paper2.model.service_times import ROOT
from src.paper2.prototype import runner,replay,validation_dryrun
from src.paper2.prototype.validation_caps import BLOCK_MESSAGE,presigning


class Preparation(unittest.TestCase):
    def test_validation_first_step_unconditionally_blocks_before_any_work(self):
        text=(ROOT/'src/paper2/prototype/paper2-g3.yml').read_text()
        first=text.split('    steps:\n',1)[1].split('\n      - ',1)[0]
        self.assertNotIn('if:',first)
        script=first.split('        run: |\n',1)[1]
        script='\n'.join(line[10:] for line in script.splitlines())
        self.assertEqual(script.splitlines(),['echo "'+BLOCK_MESSAGE+'"','exit 1'])
        git_bash=Path('C:/Program Files/Git/cmd/git.exe').parents[1]/'bin/bash.exe'
        bash=str(git_bash) if os.name=='nt' and git_bash.is_file() else shutil.which('bash')
        self.assertIsNotNone(bash)
        result=subprocess.run([bash,'-c',script],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertIn(BLOCK_MESSAGE,result.stdout)
        self.assertLess(text.index(BLOCK_MESSAGE),text.index('actions/checkout@'))
        with tempfile.TemporaryDirectory() as td,patch('src.paper2.prototype.cycle_runner.calibrate_backend',side_effect=AssertionError('calibration reached')):
            destination=Path(td)/'must-not-exist'
            with self.assertRaisesRegex(RuntimeError,'Run #7 blocked'):runner.execute(destination)
            self.assertFalse(destination.exists())
        with patch.object(sys,'argv',['runner','--require-validation-caps']):
            with self.assertRaises(SystemExit) as stopped:runner.main()
        self.assertEqual(str(stopped.exception),BLOCK_MESSAGE)

    def test_author_end_to_end_signing_caps_no_extra_keygen_or_margin(self):
        x=presigning('xmss',953988);m=presigning('ml_dsa_44',896558)
        self.assertAlmostEqual(x['projected_seconds'],2758.159137281905)
        self.assertAlmostEqual(m['projected_seconds'],604.1167330256043)
        self.assertEqual((x['cap_seconds'],m['cap_seconds']),(5600,1300))
        self.assertEqual(x['extra_signing_margin'],1)
        self.assertTrue(x['includes_key_generation'])
        for bad in (True,0,-1,1.5):
            with self.assertRaises(ValueError):presigning('xmss',bad)

    def test_timing_job_discards_simulation_outputs_and_never_computes_metrics(self):
        from src.paper2.prototype import diagnostic,artifact_integrity
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=root/'paper2-g3-diag-v5-xmss-k2'
            replay.save(packet/'info.json',dict(arm_corpus_audit=dict(signature_ids_checked=117292)))
            index=dict(code_commit='a'*40,runs=[dict(run_id=packet.name,packet_sha256='b'*64)])
            outputs=[]
            def simulate(directory,sample,output):
                self.assertEqual(directory,packet);outputs.append(output);output.mkdir(parents=True)
                events=output/'events.csv'
                with events.open('w',newline='') as f:
                    w=csv.writer(f);w.writerow(['seq','event']);w.writerow([0,'enqueue']);w.writerow([1,'end'])
                return events,output/'unused-manifest.json'
            with patch.object(artifact_integrity,'verify_checksums') as hashes,patch.object(diagnostic,'verify',return_value=(index,packet)),patch.object(replay,'simulate',side_effect=simulate),patch.object(replay,'metrics',side_effect=AssertionError('metrics computed')),patch.object(replay,'compare',side_effect=AssertionError('comparison computed')),patch.object(replay,'check',side_effect=AssertionError('invariant evaluation in timing-only job')):
                result=validation_dryrun.timing(root,root/'timing.json')
            hashes.assert_called_once_with(root)
            self.assertTrue(result['outputs_discarded'])
            self.assertEqual(set(result['runs']),{'primary','held_out'})
            self.assertTrue(all(r['event_rows']==2 for r in result['runs'].values()))
            self.assertTrue(all(not p.exists() for p in outputs))
            self.assertEqual(sorted(p.name for p in root.iterdir()),[packet.name,'timing.json'])


if __name__=='__main__':unittest.main()
