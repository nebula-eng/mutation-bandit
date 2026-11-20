"""Generate the three result figures from results/results.json."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "results.json"
FIGDIR = ROOT / "results"

COLORS = {
    "uniform": "#7f8c8d",
    "afl_fixed": "#2c7fb8",
    "repair_ctl": "#c0392b",
    "ctx_ucb": "#27ae60",
}
LABELS = {
    "uniform": "uniform random",
    "afl_fixed": "AFL-style fixed mix",
    "repair_ctl": "AIMD repair control",
    "ctx_ucb": "contextual bandit",
}
TARGET_LABELS = {"json": "JSON-lite", "tlv": "TLV", "url": "URL"}

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.edgecolor": "#444444",
        "axes.linewidth": 0.8,
        "axes.grid": True,
        "grid.color": "#e5e5e5",
        "grid.linewidth": 0.6,
        "figure.facecolor": "white",
    }
)


def _group(runs, target, scheduler):
    rows = [r for r in runs if r["target"] == target and r["scheduler"] == scheduler]
    return sorted(rows, key=lambda r: r["seed"])


def fig_coverage(payload):
    schedules = payload["config"]["schedulers"]
    targets = payload["config"]["targets"]
    fig, axes = plt.subplots(1, len(targets), figsize=(16, 5), sharey=False)
    for ax, target in zip(np.atleast_1d(axes), targets):
        for sched in schedules:
            rows = _group(payload["runs"], target, sched)
            curves = [r["curve"] for r in rows if r["curve"]]
            if not curves:
                continue
            length = min(len(c) for c in curves)
            matrix = np.array([c[:length] for c in curves], dtype=float)
            x = np.arange(1, length + 1) * 100
            ax.plot(x, matrix.mean(axis=0), color=COLORS[sched], lw=1.8, label=LABELS[sched])
            if matrix.shape[0] > 1:
                ax.fill_between(
                    x,
                    np.percentile(matrix, 25, axis=0),
                    np.percentile(matrix, 75, axis=0),
                    color=COLORS[sched],
                    alpha=0.15,
                    linewidth=0,
                )
        ax.set_title(TARGET_LABELS.get(target, target), fontsize=12, loc="left", weight="bold")
        ax.set_xlabel("executions")
        ax.set_ylabel("cumulative edges")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    np.atleast_1d(axes)[0].legend(frameon=False, fontsize=9)
    fig.suptitle(
        "Coverage growth under four mutation-scheduling policies (mean, IQR band over 6 seeds)",
        fontsize=13,
        weight="bold",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIGDIR / "fig_coverage.png", dpi=200)
    plt.close(fig)


def fig_ttff(payload):
    schedules = payload["config"]["schedulers"]
    targets = payload["config"]["targets"]
    fig, axes = plt.subplots(1, 2, figsize=(16, 5))
    ax = axes[0]
    width = 0.2
    for idx, sched in enumerate(schedules):
        medians = []
        for target in targets:
            rows = _group(payload["runs"], target, sched)
            vals = [r["ttff"] for r in rows if r["ttff"] is not None]
            medians.append(statistics.median(vals) if vals else 0)
        positions = np.arange(len(targets)) + (idx - 1.5) * width
        ax.bar(positions, medians, width=width, color=COLORS[sched], label=LABELS[sched], edgecolor="white")
    ax.set_xticks(np.arange(len(targets)))
    ax.set_xticklabels([TARGET_LABELS.get(t, t) for t in targets])
    ax.set_yscale("log")
    ax.set_ylabel("median time-to-first-bug (executions, log scale)")
    ax.set_title("Time to first seeded defect", fontsize=12, loc="left", weight="bold")
    ax.legend(frameon=False, fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax = axes[1]
    for idx, sched in enumerate(schedules):
        rates = []
        for target in targets:
            rows = _group(payload["runs"], target, sched)
            rates.append(sum(1 for r in rows if r["ttff_deep"] is not None) / max(len(rows), 1))
        positions = np.arange(len(targets)) + (idx - 1.5) * width
        ax.bar(positions, rates, width=width, color=COLORS[sched], label=LABELS[sched], edgecolor="white")
    ax.set_xticks(np.arange(len(targets)))
    ax.set_xticklabels([TARGET_LABELS.get(t, t) for t in targets])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("fraction of seeds reaching a deep defect")
    ax.set_title("Deep-defect reachability within budget", fontsize=12, loc="left", weight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.suptitle("Effect of scheduling policy on defect discovery (20,000 executions, 6 seeds)", fontsize=13, weight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIGDIR / "fig_ttff.png", dpi=200)
    plt.close(fig)


def fig_arms(payload):
    target = "tlv"
    sched = "repair_ctl"
    rows = _group(payload["runs"], target, sched)
    arm_names = payload["config"]["operators"]
    if not rows or not rows[0]["history"]:
        return
    length = min(len(r["history"][arm_names[0]]) for r in rows)
    stack = np.array([[np.mean([r["history"][a][i] for r in rows]) for a in arm_names] for i in range(length)])
    # Normalise each time bucket to a share so drift in total volume does not
    # dominate the picture.
    totals = stack.sum(axis=1, keepdims=True)
    totals[totals == 0] = 1
    shares = stack / totals
    x = np.arange(1, length + 1) * 100
    palette = ["#2c7fb8", "#41b6c4", "#7fcdbb", "#c7e9b4", "#fec44f", "#fe9929", "#c0392b"]
    fig, ax = plt.subplots(figsize=(16, 5))
    ax.stackplot(x, shares.T, labels=arm_names, colors=palette[: len(arm_names)], alpha=0.9)
    ax.set_xlabel("executions")
    ax.set_ylabel("share of operator selections")
    ax.set_ylim(0, 1)
    ax.set_title(
        "AIMD repair controller on TLV: operator mix over time (mean of 6 seeds)",
        fontsize=13,
        loc="left",
        weight="bold",
    )
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.14), frameon=False,
              fontsize=8, ncol=7, handlelength=1.4, columnspacing=1.2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIGDIR / "fig_arm_mix.png", dpi=200)
    plt.close(fig)


def fig_admission() -> None:
    sweep_path = FIGDIR / "admission_sweep.json"
    if not sweep_path.exists():
        return
    sweep = json.loads(sweep_path.read_text(encoding="utf-8"))
    budgets = sweep["budgets"]
    targets = sweep["targets"]
    fig, axes = plt.subplots(1, len(targets), figsize=(16, 5), sharey=True)
    for ax, target in zip(np.atleast_1d(axes), targets):
        for admission, color, style, label in (
            ("coverage", "#7f8c8d", "--", "coverage-only (0.000 at every budget)"),
            ("behavioral", "#c0392b", "-", "behavioural admission"),
        ):
            ys = [sweep["points"][admission][str(b)][target]["deep_mean"] for b in budgets]
            ax.plot(budgets, ys, color=color, linestyle=style, marker="o", lw=1.8, label=label)
            if admission == "behavioral":
                for x, y in zip(budgets, ys):
                    ax.annotate(f"{y:.3f}", (x, y), textcoords="offset points", xytext=(0, 7),
                                ha="center", fontsize=7.5, color=color)
        ax.set_title(TARGET_LABELS.get(target, target), fontsize=12, loc="left", weight="bold")
        ax.set_xlabel("execution budget")
        ax.set_xticks(list(budgets))
        ax.set_ylim(-0.04, 1.02)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    np.atleast_1d(axes)[0].set_ylabel("deep-defect reach (mean over 4 policies)")
    np.atleast_1d(axes)[0].legend(loc="upper left", frameon=False, fontsize=8)
    fig.suptitle(
        "Corpus admission sets the ceiling: coverage-only stays at zero as the budget grows",
        fontsize=13,
        weight="bold",
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIGDIR / "fig_admission.png", dpi=200)
    plt.close(fig)


def main() -> None:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    FIGDIR.mkdir(parents=True, exist_ok=True)
    fig_coverage(payload)
    fig_ttff(payload)
    fig_arms(payload)
    fig_admission()
    print("wrote fig_coverage.png fig_ttff.png fig_arm_mix.png fig_admission.png")


if __name__ == "__main__":
    main()
