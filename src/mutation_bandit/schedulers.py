"""Mutation-operator schedulers.

The comparison is deliberately narrow: every policy uses the same
operator set, the same seed, the same step budget and the same corpus
policy.  Only the probability of choosing an arm differs.  That makes
any measured difference attributable to scheduling rather than to extra
capability.

Reward is sparse (most mutations add no edge), so all adaptive policies
use a Beta-style success model with Laplace smoothing and treat cost as
a first-class term.  A warm-up round guarantees every arm is sampled
once, which removes the cold-start artefact that otherwise dominates
short fuzzing campaigns.
"""

from __future__ import annotations

import math
import random


class Scheduler:
    name = "base"

    def __init__(self, arms: tuple[str, ...]) -> None:
        self.arms = arms
        self.n = {a: 0 for a in arms}
        self.wins = {a: 0 for a in arms}
        self.gain = {a: 0 for a in arms}
        self.cost_ns = {a: 0.0 for a in arms}
        self.total = 0

    # -- helpers -----------------------------------------------------------
    def _warmup(self) -> str | None:
        for arm in self.arms:
            if self.n[arm] == 0:
                return arm
        return None

    def mean_cost_ms(self, arm: str) -> float:
        if self.n[arm] == 0:
            return 1.0
        return max(self.cost_ns[arm] / self.n[arm] / 1e6, 0.01)

    def rate(self, arm: str) -> float:
        return (self.wins[arm] + 0.5) / (self.n[arm] + 1.0)

    def update(self, arm: str, gained_edges: int, cost_ns: float) -> None:
        self.n[arm] += 1
        self.total += 1
        self.cost_ns[arm] += cost_ns
        self.gain[arm] += gained_edges
        if gained_edges > 0:
            self.wins[arm] += 1

    def choose(self, rng: random.Random) -> str:
        raise NotImplementedError

    def summary(self) -> dict:
        """Deterministic bookkeeping. Costs live in `cost_snapshot`."""
        return {
            "arms": {
                a: {
                    "n": self.n[a],
                    "wins": self.wins[a],
                    "edges": self.gain[a],
                }
                for a in self.arms
            },
            "total": self.total,
        }

    def cost_snapshot(self) -> dict[str, float]:
        """Mean pull cost per arm, in milliseconds. Wall clock, not reproducible."""
        return {a: round(self.mean_cost_ms(a), 4) for a in self.arms}


class Uniform(Scheduler):
    name = "uniform"

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        return self.arms[rng.randrange(len(self.arms))]


class AFLFixed(Scheduler):
    name = "afl_fixed"

    def __init__(self, arms: tuple[str, ...], weights: dict[str, float]) -> None:
        super().__init__(arms)
        self.weights = [weights[a] for a in arms]
        self.cumulative = []
        acc = 0.0
        for w in self.weights:
            acc += w
            self.cumulative.append(acc)

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        r = rng.random() * self.cumulative[-1]
        for arm, edge in zip(self.arms, self.cumulative):
            if r <= edge:
                return arm
        return self.arms[-1]


class UCB1(Scheduler):
    name = "ucb1"

    def __init__(self, arms: tuple[str, ...], exploration: float = 0.6) -> None:
        super().__init__(arms)
        self.exploration = exploration

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        log_n = math.log(self.total + 1.0)
        best_arm = self.arms[0]
        best_score = -1.0
        for arm in self.arms:
            bonus = self.exploration * math.sqrt(log_n / (self.n[arm] + 1.0))
            # Efficiency term: success probability per millisecond.
            score = self.rate(arm) * (1.0 / self.mean_cost_ms(arm)) + bonus
            if score > best_score:
                best_score = score
                best_arm = arm
        return best_arm


class Thompson(Scheduler):
    name = "thompson"

    def __init__(self, arms: tuple[str, ...], rng_for_sampling: random.Random | None = None) -> None:
        super().__init__(arms)
        self._sampler = rng_for_sampling or random.Random(0xC0FFEE)

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        best_arm = self.arms[0]
        best_score = -1.0
        for arm in self.arms:
            alpha = self.wins[arm] + 1.0
            beta = self.n[arm] - self.wins[arm] + 1.0
            sample = self._sampler.betavariate(alpha, beta)
            score = sample / self.mean_cost_ms(arm)
            if score > best_score:
                best_score = score
                best_arm = arm
        return best_arm


class SlidingUCB(Scheduler):
    """UCB with a sliding reward window (non-stationary bandit).

    Operator yield is not stationary: structural repair matters early,
    byte-level tweaks matter once the parser is deep.  A global mean
    therefore lags.  A window of the last W pulls forgets stale arms.
    """

    name = "ucb_window"

    def __init__(self, arms: tuple[str, ...], window: int = 240, exploration: float = 0.35) -> None:
        super().__init__(arms)
        self.window = window
        self.exploration = exploration
        self.events: list[tuple[str, int]] = []

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        recent = self.events[-self.window :]
        n = {a: 0 for a in self.arms}
        wins = {a: 0 for a in self.arms}
        for arm, gained in recent:
            n[arm] += 1
            if gained > 0:
                wins[arm] += 1
        total = len(recent) + 1
        best_arm = self.arms[0]
        best_score = -1.0
        for arm in self.arms:
            rate = (wins[arm] + 0.5) / (n[arm] + 1.0)
            bonus = self.exploration * math.sqrt(math.log(total) / (n[arm] + 1.0))
            score = rate + bonus
            if score > best_score:
                best_score = score
                best_arm = arm
        return best_arm

    def update(self, arm: str, gained_edges: int, cost_ns: float) -> None:
        super().update(arm, gained_edges, cost_ns)
        self.events.append((arm, 1 if gained_edges > 0 else 0))
        if len(self.events) > 8 * self.window:
            del self.events[: 4 * self.window]


class ContextualUCB(Scheduler):
    """Contextual bandit: separate arm statistics per parse-progress bucket.

    Context is the number of parser nodes executed for the previous input
    (0-2 = rejected early, 3-8 = partial, 9+ = deep).  The hypothesis is
    that the best operator depends on how much structure survived, so a
    context-free scheduler averages over regimes and misallocates.
    """

    name = "ctx_ucb"
    BUCKETS = ((0, 2), (3, 8), (9, 10**9))
    LABELS = ("shallow", "partial", "deep")

    def __init__(self, arms: tuple[str, ...], exploration: float = 0.45) -> None:
        super().__init__(arms)
        self.exploration = exploration
        self.context = 2  # start optimistic: first inputs are valid seeds
        self.tables = [
            {"n": {a: 0 for a in arms}, "wins": {a: 0 for a in arms}, "total": 0}
            for _ in self.BUCKETS
        ]

    def observe(self, progress: int) -> None:
        for idx, (lo, hi) in enumerate(self.BUCKETS):
            if lo <= progress <= hi:
                self.context = idx
                return
        self.context = 2

    def choose(self, rng: random.Random) -> str:
        table = self.tables[self.context]
        for arm in self.arms:
            if table["n"][arm] == 0:
                return arm
        total = table["total"] + 1
        best_arm = self.arms[0]
        best_score = -1.0
        for arm in self.arms:
            rate = (table["wins"][arm] + 0.5) / (table["n"][arm] + 1.0)
            bonus = self.exploration * math.sqrt(math.log(total) / (table["n"][arm] + 1.0))
            score = rate + bonus
            if score > best_score:
                best_score = score
                best_arm = arm
        return best_arm

    def update(self, arm: str, gained_edges: int, cost_ns: float) -> None:
        super().update(arm, gained_edges, cost_ns)
        table = self.tables[self.context]
        table["n"][arm] += 1
        table["total"] += 1
        if gained_edges > 0:
            table["wins"][arm] += 1


class RepairController(Scheduler):
    """AIMD controller over the repair/destroy budget split.

    Only one decision matters for structured formats: how much of the
    mutation budget to spend restoring invariants versus perturbing
    bytes.  Fixed mixes cannot adapt when the corpus drifts from
    "mostly valid" to "mostly broken".  The controller raises the repair
    probability while recent inputs die early (progress == 0) and lowers
    it once inputs parse deep, which is the regime where byte-level
    perturbation pays off.
    """

    name = "repair_ctl"
    depth_bias = True

    def __init__(self, arms: tuple[str, ...], weights: dict[str, float], rng: random.Random | None = None) -> None:
        super().__init__(arms)
        self.weights = weights
        self.other = tuple(a for a in arms if a != "fixup")
        self.p_repair = 0.15
        self._rng = rng or random.Random(7)
        self._progress: list[int] = []

    def observe(self, progress: int) -> None:
        self._progress.append(progress)
        if len(self._progress) > 50:
            self._progress.pop(0)
        if progress <= 2:
            self.p_repair = min(0.60, self.p_repair + 0.02)
        elif progress >= 9:
            self.p_repair = max(0.02, self.p_repair - 0.01)

    def choose(self, rng: random.Random) -> str:
        cold = self._warmup()
        if cold is not None:
            return cold
        if rng.random() < self.p_repair:
            return "fixup"
        return self.other[rng.randrange(len(self.other))]

    def summary(self) -> dict:
        base = super().summary()
        base["p_repair"] = round(self.p_repair, 4)
        return base


def build(name: str, arms: tuple[str, ...], weights: dict[str, float]) -> Scheduler:
    if name == "uniform":
        return Uniform(arms)
    if name == "afl_fixed":
        return AFLFixed(arms, weights)
    if name == "ucb1":
        return UCB1(arms)
    if name == "thompson":
        return Thompson(arms)
    if name == "ucb_window":
        return SlidingUCB(arms)
    if name == "ctx_ucb":
        return ContextualUCB(arms)
    if name == "repair_ctl":
        return RepairController(arms, weights)
    raise ValueError(f"unknown scheduler: {name}")
