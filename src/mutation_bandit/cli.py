"""Command line interface for the mutation-bandit experiments."""

from __future__ import annotations

import argparse
import json

from .bench import run_bench
from .engine import fuzz
from .mutators import OPERATORS
from .targets import TARGETS


def cmd_demo(args: argparse.Namespace) -> int:
    result = fuzz(args.target, args.scheduler, args.seed, max_execs=args.execs)
    print(json.dumps(result.as_dict(), indent=2)[:4000])
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    payload = run_bench(
        targets=tuple(args.targets),
        schedulers=tuple(args.schedulers),
        seeds=tuple(args.seeds),
        max_execs=args.execs,
        out_path=args.out,
        admission=args.admission,
    )
    costs = payload["timing"]["summary"]
    for key, row in payload["summary"].items():
        print(
            f"{key:22s} edges={row['edges_median']:6.1f} "
            f"ttff={str(row['ttff_median']):>8s} "
            f"det={row['detection_rate']:.2f} deep={row['deep_detection_rate']:.2f} "
            f"us/exec={costs[key]['us_per_exec_median']:.1f}"
        )
    return 0


def cmd_arms(args: argparse.Namespace) -> int:
    """Print the learned arm preferences for one campaign."""
    result = fuzz(args.target, args.scheduler, args.seed, max_execs=args.execs)
    stats = result.stats["arms"]
    total = max(result.stats["total"], 1)
    for arm in OPERATORS:
        row = stats[arm]
        share = row["n"] / total
        yield_rate = row["wins"] / max(row["n"], 1)
        print(
            f"{arm:18s} n={row['n']:5d} share={share:5.1%} "
            f"wins={row['wins']:4d} yield={yield_rate:5.1%} "
            f"edges={row['edges']:4d}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mutation_bandit")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run one campaign")
    demo.add_argument("--target", choices=sorted(TARGETS), default="tlv")
    demo.add_argument("--scheduler", choices=["uniform", "afl_fixed", "ucb1", "thompson", "ucb_window", "ctx_ucb", "repair_ctl"], default="ucb1")
    demo.add_argument("--seed", type=int, default=1)
    demo.add_argument("--execs", type=int, default=1500)
    demo.set_defaults(func=cmd_demo)

    bench = sub.add_parser("bench", help="full benchmark grid")
    bench.add_argument("--targets", nargs="+", default=sorted(TARGETS))
    bench.add_argument("--schedulers", nargs="+", default=["uniform", "afl_fixed", "repair_ctl", "ctx_ucb"])
    bench.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3, 4])
    bench.add_argument("--execs", type=int, default=4000)
    bench.add_argument("--out", default="results/results.json")
    bench.add_argument("--admission", choices=["behavioral", "coverage"], default="behavioral")
    bench.set_defaults(func=cmd_bench)

    arms = sub.add_parser("arms", help="arm statistics for one campaign")
    arms.add_argument("--target", choices=sorted(TARGETS), default="tlv")
    arms.add_argument("--scheduler", choices=["uniform", "afl_fixed", "ucb1", "thompson", "ucb_window", "ctx_ucb", "repair_ctl"], default="ucb1")
    arms.add_argument("--seed", type=int, default=1)
    arms.add_argument("--execs", type=int, default=3000)
    arms.set_defaults(func=cmd_arms)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
