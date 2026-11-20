"""Admission-policy sweep across execution budgets.

The single-budget comparison in EVALUATION section 7 is extended here to a
curve: if coverage-only admission is a structural limit rather than a slow
start, its deep-defect reachability should stay at zero as the budget grows,
while behavioural admission should rise monotonically.

Writes results/admission_sweep.json. Every point is the mean over the four
scheduling policies and six seeds (24 campaigns per point).
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mutation_bandit.bench import run_bench  # noqa: E402

BUDGETS = (5000, 10000, 20000)
TARGETS = ("json", "tlv", "url")
POLICIES = ("uniform", "afl_fixed", "repair_ctl", "ctx_ucb")


def main() -> int:
    payload: dict = {
        "budgets": list(BUDGETS),
        "targets": list(TARGETS),
        "policies": list(POLICIES),
        "seeds": [1, 2, 3, 4, 5, 6],
        "points": {},
    }
    for admission in ("coverage", "behavioral"):
        rows = {}
        for budget in BUDGETS:
            bench = run_bench(
                targets=TARGETS,
                schedulers=POLICIES,
                seeds=(1, 2, 3, 4, 5, 6),
                max_execs=budget,
                admission=admission,
            )
            summary = bench["summary"]
            per_target = {}
            for target in TARGETS:
                deep = [summary[f"{target}/{policy}"]["deep_detection_rate"] for policy in POLICIES]
                det = [summary[f"{target}/{policy}"]["detection_rate"] for policy in POLICIES]
                per_target[target] = {
                    "deep_mean": round(statistics.fmean(deep), 4),
                    "deep_max": round(max(deep), 4),
                    "detection_mean": round(statistics.fmean(det), 4),
                    "detection_max": round(max(det), 4),
                }
            rows[str(budget)] = per_target
            print(f"{admission:11s} {budget:6d} " + "  ".join(
                f"{t}:{per_target[t]['deep_mean']:.3f}/{per_target[t]['detection_mean']:.3f}"
                for t in TARGETS
            ))
        payload["points"][admission] = rows

    out = Path("results/admission_sweep.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
