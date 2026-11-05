"""Author-specified Deviation 6 formula, with literal hand calculations."""

from tests.paper2._provenance import setUpModule,tearDownModule

import math
import unittest

from src.paper2.prototype.cycle_protocol import cold_cycle_reference,cold_cycle_loads


class CycleCapacity(unittest.TestCase):
    def test_hand_computed_per_k_means_and_dispatcher_cap(self):
        # k=2, a=2ms, t=3ms, s=128ms. Cold denominator=6ms,
        # warm denominator=3ms. d=2ms -> dispatcher capacity=500/s.
        # Cold=min(2/.006,500)=1000/3; reference=min(2/.003,500)=500.
        # rho=.5 -> 500/3 tx/s, utilisation=1/3 (eligible).
        # rho=.85 -> 850/3 tx/s, utilisation=17/30 (excluded).
        ref=cold_cycle_reference(2,dict(admission=.002,block_tx=.003,block_sig=.128),.002,scaling=1.7)
        self.assertAlmostEqual(ref["B_cold_cycle"],1000/3)
        self.assertEqual(ref["B_ref_cycle"],500)
        self.assertEqual(ref["s_k"],1.7)
        low,high=cold_cycle_loads(ref)
        self.assertAlmostEqual(low["rate"],500/3)
        self.assertAlmostEqual(high["rate"],850/3)
        self.assertAlmostEqual(low["dispatcher_utilisation"],1/3)
        self.assertAlmostEqual(high["dispatcher_utilisation"],17/30)
        self.assertTrue(low["dispatcher_guard_passed"])
        self.assertFalse(high["dispatcher_guard_passed"])
        self.assertAlmostEqual(low["period"],128/(500/3))

    def test_cold_dispatcher_cap_and_scaling_reported_only(self):
        means=dict(admission=.002,block_tx=.003,block_sig=.128)
        a=cold_cycle_reference(2,means,.01,scaling=1)
        b=cold_cycle_reference(2,means,.01,scaling=9)
        self.assertEqual(a["B_cold_cycle"],100)
        self.assertEqual(a["B_ref_cycle"],100)
        self.assertEqual(b["B_cold_cycle"],100)
        self.assertEqual(b["B_ref_cycle"],100)
        self.assertEqual([r["rate"] for r in cold_cycle_loads(a)],[50,85])
        self.assertEqual([r["dispatcher_guard_passed"] for r in cold_cycle_loads(a)],[True,False])

    def test_invalid_calibration_is_refused(self):
        means=dict(admission=.002,block_tx=.003,block_sig=.128)
        for k in (True,0,-1,1.5):
            with self.subTest(k=k),self.assertRaises(ValueError):cold_cycle_reference(k,means,.01)
        for field in means:
            for bad in (0,-1,math.inf,math.nan,True):
                with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):
                    cold_cycle_reference(1,dict(means,**{field:bad}),.01)
        for bad in (-1,math.inf,math.nan,True):
            with self.subTest(dispatcher=bad),self.assertRaises(ValueError):cold_cycle_reference(1,means,bad)


if __name__=="__main__":unittest.main()
