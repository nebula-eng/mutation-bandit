"""Execution engine and fuzzing campaign driver."""

from __future__ import annotations

import hashlib
import math
import random
import time
from dataclasses import dataclass, field

from .coverage import CoverageMap, set_coverage
from .errors import Budget, BudgetExceeded, InjectedBug
from .mutators import AFL_FIXED_WEIGHTS, OPERATORS, mutate
from .schedulers import build
from .targets import TARGETS, Target

CHECKPOINT = 100


@dataclass
class RunResult:
    target: str
    scheduler: str
    seed: int
    execs: int
    edges: int
    ttff: int | None
    ttff_deep: int | None = None
    bugs: dict[str, int] = field(default_factory=dict)
    timeouts: int = 0
    elapsed_s: float = 0.0
    admission: str = "behavioral"
    curve: list[int] = field(default_factory=list)
    history: dict[str, list[int]] = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    arm_cost_ms: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict:
        """Deterministic part of a run, and only that.

        Wall-clock fields live in `timing()` instead. The split exists so
        `results/results.json` is byte-identical across re-runs and can be
        diffed; a machine-dependent number inside it would make every run look
        like a change.
        """
        return {
            "target": self.target,
            "scheduler": self.scheduler,
            "seed": self.seed,
            "execs": self.execs,
            "edges": self.edges,
            "ttff": self.ttff,
            "ttff_deep": self.ttff_deep,
            "bugs": self.bugs,
            "timeouts": self.timeouts,
            "admission": self.admission,
            "curve": self.curve,
            "history": self.history,
            "stats": self.stats,
        }

    def timing(self) -> dict:
        """Machine-dependent measurements for this run."""
        return {
            "target": self.target,
            "scheduler": self.scheduler,
            "seed": self.seed,
            "elapsed_s": round(self.elapsed_s, 4),
            "us_per_exec": round(self.elapsed_s / max(self.execs, 1) * 1e6, 3),
            "arm_mean_cost_ms": dict(sorted(self.arm_cost_ms.items())),
        }


def _execute(target: Target, data: bytes, steps: int) -> tuple[str, str | None]:
    budget = Budget(steps)
    try:
        target.run(data, budget)
        return "ok", None
    except InjectedBug as exc:
        return "bug", exc.name
    except BudgetExceeded:
        return "timeout", None
    except RecursionError:
        return "crash", "RecursionError"
    except (IndexError, ValueError, KeyError):
        return "crash", "unexpected"
    except Exception as exc:  # pragma: no cover - defensive
        return "crash", type(exc).__name__


def fuzz(
    target_name: str,
    scheduler_name: str,
    seed: int,
    max_execs: int = 4000,
    step_budget: int = 1200,
    admission: str = "behavioral",
) -> RunResult:
    target = TARGETS[target_name]
    cov = CoverageMap()
    set_coverage(cov)
    rng = random.Random(seed)
    scheduler = build(scheduler_name, OPERATORS, AFL_FIXED_WEIGHTS)

    corpus: list[bytes] = []
    depth: list[int] = []
    seen: set[str] = set()
    cells: set[tuple[int, int]] = set()
    deep_pool: list[bytes] = []

    def remember(data: bytes, progress: int = 0, gained: int = 0) -> None:
        """Admission is behavioural, not purely coverage-based.

        An input is kept if it adds an edge, or if it reaches a new
        (parse-progress, input-size) cell.  The second criterion is what
        lets payload growth accumulate: a larger input that parses
        equally deep is worthless for coverage but is exactly the
        stepping stone to a length-overflow defect.
        """
        cell = (progress // 3, int(math.log2(max(len(data), 1))))
        novel = cell not in cells
        cells.add(cell)
        if admission == "coverage":
            novel = False
        digest = hashlib.blake2b(data, digest_size=8).hexdigest()
        if digest in seen or (gained == 0 and not novel):
            return
        seen.add(digest)
        corpus.append(data)
        depth.append(progress)
        if progress >= 6:
            deep_pool.append(data)
            if len(deep_pool) > 256:
                del deep_pool[:64]
        if len(corpus) > 4096:
            del corpus[:1024]
            del depth[:1024]

    for seed_data in target.seeds:
        cov.reset_edge()
        hits_before = cov.total_hits
        _execute(target, seed_data, step_budget)
        remember(seed_data, cov.total_hits - hits_before)

    result = RunResult(
        target=target_name,
        scheduler=scheduler_name,
        seed=seed,
        execs=0,
        edges=cov.new_edges,
        ttff=None,
        admission=admission,
        history={arm: [] for arm in OPERATORS},
    )
    history_bucket = {arm: 0 for arm in OPERATORS}
    started = time.perf_counter()

    for step in range(1, max_execs + 1):
        if not corpus:
            corpus.append(b"")
            depth.append(0)
        parent_idx = rng.randrange(len(corpus))
        if getattr(scheduler, "depth_bias", False) and deep_pool and rng.random() < 0.5:
            parent = deep_pool[rng.randrange(len(deep_pool))]
        elif len(corpus) > 64 and rng.random() < 0.5:
            parent_idx = len(corpus) - 1 - rng.randrange(min(64, len(corpus) - 1))
            parent = corpus[parent_idx]
        else:
            parent = corpus[parent_idx]

        context = {
            "dictionary": target.dictionary,
            "corpus": corpus,
            "fixup": target.fixup,
        }
        t0 = time.perf_counter_ns()
        candidate, ops = mutate(rng, parent, scheduler, context)

        cov.reset_edge()
        before = cov.new_edges
        hits_before = cov.total_hits
        status, bug_name = _execute(target, candidate, step_budget)
        elapsed_ns = time.perf_counter_ns() - t0
        gained = cov.new_edges - before
        progress = cov.total_hits - hits_before
        if hasattr(scheduler, "observe"):
            scheduler.observe(progress)

        # Real cost is attributed evenly across the arms that produced
        # the input; with stack depth <= 2 the attribution error is bounded.
        per_arm_ns = elapsed_ns / len(ops)
        for arm in ops:
            history_bucket[arm] += 1
            scheduler.update(arm, gained, per_arm_ns)

        result.execs = step
        result.edges = cov.new_edges

        if status == "bug" and bug_name is not None:
            if bug_name not in result.bugs:
                result.bugs[bug_name] = step
                if result.ttff is None:
                    result.ttff = step
                if result.ttff_deep is None and bug_name in target.deep:
                    result.ttff_deep = step
        elif status == "timeout":
            result.timeouts += 1

        remember(candidate, progress, gained)

        if step % CHECKPOINT == 0:
            result.curve.append(cov.new_edges)
            for arm in OPERATORS:
                result.history[arm].append(history_bucket[arm])
                history_bucket[arm] = 0

    result.elapsed_s = time.perf_counter() - started
    result.stats = scheduler.summary()
    result.arm_cost_ms = scheduler.cost_snapshot()
    return result
