"""Unit tests for coverage accounting, operators, schedulers and engine."""

from __future__ import annotations

import random
import unittest

from mutation_bandit.coverage import CoverageMap, set_coverage
from mutation_bandit.engine import fuzz
from mutation_bandit.errors import Budget, InjectedBug
from mutation_bandit.mutators import AFL_FIXED_WEIGHTS, OPERATORS, apply_operator, mutate
from mutation_bandit.schedulers import build
from mutation_bandit.targets import TARGETS, run_tlv


class TestCoverage(unittest.TestCase):
    def test_virgin_edge_counted_once(self):
        cov = CoverageMap()
        cov.hit(10)
        cov.hit(11)
        self.assertEqual(cov.new_edges, 2)
        cov.hit(11)
        self.assertEqual(cov.new_edges, 2)

    def test_edge_depends_on_predecessor(self):
        cov = CoverageMap()
        cov.reset_edge()
        cov.hit(7)
        cov.hit(9)  # edge 7->9
        first = cov.new_edges
        cov.reset_edge()
        cov.hit(8)
        cov.hit(9)  # edge 8->9 is a different edge; the 8->8 prefix edge is new too
        self.assertEqual(first, 2)
        self.assertEqual(cov.new_edges, 4)

    def test_hit_counter_saturates(self):
        cov = CoverageMap()
        for _ in range(400):
            cov.reset_edge()
            cov.hit(5)
        self.assertLessEqual(max(cov.map), 255)
        self.assertEqual(cov.touched(), 1)


class TestOperators(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(1)
        self.ctx = {
            "dictionary": TARGETS["tlv"].dictionary,
            "corpus": [b"TLV\x01\x01a\x00"],
            "fixup": TARGETS["tlv"].fixup,
        }

    def test_all_operators_return_bytes(self):
        for name in OPERATORS:
            out = apply_operator(name, self.rng, b"TLV\x01\x01a\x00", self.ctx)
            self.assertIsInstance(out, bytes, name)

    def test_fixup_repairs_count_and_crc(self):
        broken = b"TLV\x09\x01\x03abc\x00"
        fixed = TARGETS["tlv"].fixup(broken)
        self.assertEqual(fixed[3], 1)
        budget = Budget(500)
        run_tlv(fixed, budget)  # must not raise

    def test_fixup_preserves_payload(self):
        fixed = TARGETS["tlv"].fixup(b"TLV\x01\x01a\x00")
        self.assertIn(b"a", fixed)

    def test_mutate_respects_size_cap(self):
        sched = build("uniform", OPERATORS, AFL_FIXED_WEIGHTS)
        big = b"T" * 9000
        out, ops = mutate(self.rng, big, sched, self.ctx)
        self.assertLessEqual(len(out), 8192)
        self.assertGreaterEqual(len(ops), 1)

    def test_json_fixup_balances_brackets(self):
        out = TARGETS["json"].fixup(b'{"a":[1,2')
        self.assertEqual(out.count(b"{"), out.count(b"}"))
        self.assertEqual(out.count(b"["), out.count(b"]"))


class TestSchedulers(unittest.TestCase):
    def test_warmup_covers_every_arm(self):
        sched = build("ucb1", OPERATORS, AFL_FIXED_WEIGHTS)
        rng = random.Random(3)
        picked = []
        for _ in range(len(OPERATORS)):
            arm = sched.choose(rng)
            sched.update(arm, 0, 1e3)
            picked.append(arm)
        self.assertEqual(set(picked), set(OPERATORS))

    def test_repair_controller_adapts(self):
        sched = build("repair_ctl", OPERATORS, AFL_FIXED_WEIGHTS)
        rng = random.Random(3)
        for _ in range(len(OPERATORS)):
            sched.update(sched.choose(rng), 0, 1e3)
        start = sched.p_repair
        for _ in range(30):
            sched.observe(0)
        self.assertGreater(sched.p_repair, start)
        high = sched.p_repair
        for _ in range(30):
            sched.observe(20)
        self.assertLess(sched.p_repair, high)

    def test_contextual_bandit_tracks_context(self):
        sched = build("ctx_ucb", OPERATORS, AFL_FIXED_WEIGHTS)
        sched.observe(0)
        self.assertEqual(sched.context, 0)
        sched.observe(5)
        self.assertEqual(sched.context, 1)
        sched.observe(50)
        self.assertEqual(sched.context, 2)

    def test_cost_tracking(self):
        sched = build("ucb1", OPERATORS, AFL_FIXED_WEIGHTS)
        sched.update("bitflip", 2, 1_000_000)
        self.assertAlmostEqual(sched.mean_cost_ms("bitflip"), 1.0, places=6)
        self.assertEqual(sched.gain["bitflip"], 2)


class TestEngine(unittest.TestCase):
    def test_deterministic_campaign(self):
        a = fuzz("tlv", "afl_fixed", 11, max_execs=600)
        b = fuzz("tlv", "afl_fixed", 11, max_execs=600)
        self.assertEqual(a.edges, b.edges)
        self.assertEqual(a.bugs, b.bugs)
        self.assertEqual(a.curve, b.curve)

    def test_finds_seeded_defect(self):
        result = fuzz("tlv", "uniform", 5, max_execs=1200)
        self.assertIsNotNone(result.ttff)
        self.assertGreaterEqual(len(result.bugs), 1)

    def test_no_unexpected_crashes(self):
        for target in TARGETS:
            result = fuzz(target, "uniform", 2, max_execs=400)
            self.assertEqual(result.timeouts, 0, target)

    def test_budget_is_enforced(self):
        cov = CoverageMap()
        set_coverage(cov)
        with self.assertRaises(InjectedBug):
            run_tlv(b"TLV\x01\x00\x00\x5a", Budget(100))  # zero-length record


if __name__ == "__main__":
    unittest.main()


class TestReproducibility(unittest.TestCase):
    """The committed table has to be byte-stable, or it cannot be diffed."""

    def test_results_json_excludes_wall_clock(self):
        result = fuzz("tlv", "uniform", 1, max_execs=400)
        payload = result.as_dict()
        for key in ("elapsed_s", "us_per_exec"):
            self.assertNotIn(key, payload)
        for arm in payload["stats"]["arms"].values():
            self.assertNotIn("mean_cost_ms", arm)
        self.assertEqual(set(result.timing()), {"target", "scheduler", "seed",
                                                "elapsed_s", "us_per_exec",
                                                "arm_mean_cost_ms"})

    def test_two_runs_write_identical_bytes(self):
        import tempfile
        from pathlib import Path

        from mutation_bandit.bench import run_bench

        outputs = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "results.json"
                run_bench(
                    targets=("tlv",),
                    schedulers=("uniform", "repair_ctl"),
                    seeds=(1,),
                    max_execs=400,
                    out_path=path,
                )
                outputs.append(path.read_bytes())
                self.assertTrue((Path(tmp) / "timing.json").exists())
        self.assertEqual(outputs[0], outputs[1])
