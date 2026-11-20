"""Benchmark driver: targets x schedulers x seeds, fixed exec budget."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from .engine import RunResult, fuzz
from .mutators import OPERATORS, AFL_FIXED_WEIGHTS
from .targets import TARGETS

DEFAULT_SCHEDULERS = ("uniform", "afl_fixed", "repair_ctl", "ctx_ucb")


def _median(values: list[float]) -> float:
    return round(statistics.median(values), 4) if values else 0.0


def summarize(runs: list[RunResult], max_execs: int) -> dict:
    summary: dict[str, dict] = {}
    for target in sorted({r.target for r in runs}):
        for scheduler in sorted({r.scheduler for r in runs}):
            subset = [r for r in runs if r.target == target and r.scheduler == scheduler]
            if not subset:
                continue
            ttff = [r.ttff for r in subset if r.ttff is not None]
            deep = [r.ttff_deep for r in subset if r.ttff_deep is not None]
            detection = len(ttff) / len(subset)
            bugs: set[str] = set()
            for r in subset:
                bugs.update(r.bugs)
            summary[f"{target}/{scheduler}"] = {
                "runs": len(subset),
                "edges_median": _median([r.edges for r in subset]),
                "edges_iqr": [
                    round(min(r.edges for r in subset), 2),
                    round(max(r.edges for r in subset), 2),
                ],
                "ttff_median": _median(ttff) if ttff else None,
                "ttff_mean": round(statistics.fmean(ttff), 2) if ttff else None,
                "detection_rate": round(detection, 4),
                "deep_detection_rate": round(len(deep) / len(subset), 4),
                "ttff_deep_median": _median(deep) if deep else None,
                "bugs_union": sorted(bugs),
                "bugs_per_run_median": _median([len(r.bugs) for r in subset]),
            }
    return summary


def summarize_timing(runs: list[RunResult]) -> dict:
    timing: dict[str, dict] = {}
    for target in sorted({r.target for r in runs}):
        for scheduler in sorted({r.scheduler for r in runs}):
            subset = [r for r in runs if r.target == target and r.scheduler == scheduler]
            if not subset:
                continue
            timing[f"{target}/{scheduler}"] = {
                "runs": len(subset),
                "us_per_exec_median": _median(
                    [r.elapsed_s / max(r.execs, 1) * 1e6 for r in subset]
                ),
                "us_per_exec_min": round(
                    min(r.elapsed_s / max(r.execs, 1) * 1e6 for r in subset), 4
                ),
                "elapsed_s_total": round(sum(r.elapsed_s for r in subset), 3),
            }
    return timing


def run_bench(
    targets: tuple[str, ...] = tuple(TARGETS),
    schedulers: tuple[str, ...] = DEFAULT_SCHEDULERS,
    seeds: tuple[int, ...] = (1, 2, 3, 4),
    max_execs: int = 4000,
    out_path: str | Path | None = None,
    admission: str = "behavioral",
) -> dict:
    runs: list[RunResult] = []
    for target in targets:
        for scheduler in schedulers:
            for seed in seeds:
                runs.append(fuzz(target, scheduler, seed, max_execs=max_execs, admission=admission))
    payload = {
        "config": {
            "targets": list(targets),
            "schedulers": list(schedulers),
            "seeds": list(seeds),
            "max_execs": max_execs,
            "operators": list(OPERATORS),
            "admission": admission,
            "afl_fixed_weights": AFL_FIXED_WEIGHTS,
        },
        "runs": [r.as_dict() for r in runs],
        "summary": summarize(runs, max_execs),
    }
    timing = {
        "config": payload["config"],
        "runs": [r.timing() for r in runs],
        "summary": summarize_timing(runs),
    }
    payload["timing"] = timing
    if out_path is not None:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # The file holds the deterministic projection only. `timing` stays in
        # the returned dict for callers that print cost, and goes to a sibling
        # file, so `results.json` is byte-identical across re-runs.
        payload["timing"] = timing
        path.write_text(
            json.dumps({k: v for k, v in payload.items() if k != "timing"},
                       indent=2, sort_keys=True),
            encoding="utf-8", newline="\n",
        )
        path.with_name("timing.json").write_text(
            json.dumps(timing, indent=2, sort_keys=True), encoding="utf-8", newline="\n"
        )
    return payload
