"""Regenerate results/ablation_ucb.json, the record of the rejected hypothesis.

The context-free bandit was the original idea: schedule operators with UCB1 over a
binary new-edge reward. Two things are recorded here, and the second is the reason
the policy was not adopted.

`uniform` and `ucb_window` do not consult measured cost, so their numbers reproduce
exactly. `ucb1` divides its success rate by the measured cost of each arm, so its
arm choice responds to timing noise; the script therefore runs it twice and stores
both repeats. The spread between them is reported in `docs/EVALUATION.md` section 6.

    PYTHONPATH=src python scripts/ucb_ablation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mutation_bandit.bench import run_bench  # noqa: E402

STABLE = ("uniform", "ucb_window")
NOISY = "ucb1"
TARGETS = ("json", "tlv", "url")


def summary_rows(payload: dict, policies) -> dict:
    return {
        f"{target}/{policy}": payload["summary"][f"{target}/{policy}"]
        for target in TARGETS
        for policy in policies
    }


def main() -> int:
    stable = run_bench(schedulers=STABLE, seeds=(1, 2, 3, 4, 5, 6), max_execs=20000)
    noisy = [
        run_bench(schedulers=(NOISY,), seeds=(1, 2, 3, 4, 5, 6), max_execs=20000)
        for _ in range(2)
    ]

    payload = {
        "config": stable["config"],
        "reproducible": summary_rows(stable, STABLE),
        "ucb1_repeats": [summary_rows(run, (NOISY,)) for run in noisy],
    }
    out = ROOT / "results" / "ablation_ucb.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(ROOT)}")

    for policy in STABLE:
        medians = [payload["reproducible"][f"{t}/{policy}"]["ttff_median"] for t in TARGETS]
        print(f"  {policy:12} " + " ".join(f"{t}={m}" for t, m in zip(TARGETS, medians)))
    for i, run in enumerate(payload["ucb1_repeats"], 1):
        medians = [run[f"{t}/{NOISY}"]["ttff_median"] for t in TARGETS]
        print(f"  ucb1 rep{i}    " + " ".join(f"{t}={m}" for t, m in zip(TARGETS, medians)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
