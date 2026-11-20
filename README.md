# mutation-bandit

Mutation scheduling for coverage-guided fuzzers.

[![CI](https://github.com/nebula-eng/mutation-bandit/actions/workflows/ci.yml/badge.svg)](https://github.com/nebula-eng/mutation-bandit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776ab.svg)](pyproject.toml)

Structure-repair scheduling for coverage-guided fuzzers: a controlled study.

A deterministic, instrumented benchmark for one narrow question: *does operator-level
scheduling of mutations change how fast a fuzzer reaches a defect?* The repository
contains a coverage-guided fuzzer, three instrumented parsers with eleven seeded
defects, four scheduling policies, and a reproducible 20,000-execution campaign over
six seeds.

The result is not a victory lap. Two objectives are measured, time-to-first-bug
and deep-defect reachability, and no policy wins both. That trade-off is the
contribution.

## Measured results

Pooled over three targets (geometric mean of per-target medians, 20,000 executions
per run, 6 seeds, step-budgeted execution):

| policy | pooled TTFF (execs) | deep-defect reach (mean) | edges (mean) |
|---|---:|---:|---:|
| uniform random | 623.4 | 0.556 | 23.7 |
| AFL-style fixed mix | 525.5 | 0.500 | 22.3 |
| AIMD repair control | 381.3 | 0.389 | 22.7 |
| contextual bandit | 558.7 | 0.722 | 22.0 |

Per-target time-to-first-bug (executions, median of 6 seeds):

| target | uniform | AFL fixed | AIMD repair | contextual |
|---|---:|---:|---:|---:|
| TLV | 1242.5 | 819.5 | 311.0 | 534.5 |
| JSON-lite | 1026.0 | 1417.0 | 1196.5 | 3546.0 |
| URL | 190.0 | 125.0 | 149.0 | 92.0 |

Four findings:

1. Repair-budget control cuts first-bug latency by 1.38x against an AFL-style
   fixed mix and 1.63x against uniform random (pooled), driven by TLV, where
   checksum validity gates every deep path. On JSON it is 1.18x faster than the
   AFL mix but 1.17x slower than uniform random, so the gain is not uniform.
2. A context-aware policy buys depth, not speed. Conditioning operator choice on
   parse progress raises deep-defect reachability from 0.50 to 0.72, while making
   first-bug latency 6.8x worse on JSON. Depth and latency are different objectives.
3. Operator-level bandit scheduling alone is not an improvement. A context-free
   UCB1 over operators was measured and discarded: pooled time-to-first-bug lands
   within 7% of uniform, the per-target mix moves by a factor of two, and its
   cost-weighted efficiency term makes two identical runs disagree. The negative
   result, with both runs, is in `docs/EVALUATION.md` section 6.
4. Corpus admission dominates scheduling, and raising the budget does not fix it.
   Coverage-only admission reaches a deep defect 0.000 of the time on all three
   targets at 5,000, 10,000 and 20,000 executions; behavioural admission rises
   monotonically (JSON 0.042 to 0.167, TLV 0.125 to 0.583, URL 0.583 to 0.875) and
   reaches full detection by 10,000. See `results/fig_admission.png`.

## Install

Not on PyPI. Install from a clone:

```bash
git clone https://github.com/nebula-eng/mutation-bandit.git
cd mutation-bandit
python -m pip install -e ".[plots]"
```

The fuzzer, the targets and the schedulers are standard library only. `numpy` and
`matplotlib` sit behind the `plots` extra and are needed by `make figures` alone;
the test suite runs without them. Python 3.11 or newer.

## Quickstart

```bash
make test      # 18 unit tests
make demo      # one 5,000-execution campaign
make eval      # full grid -> results/results.json
make figures   # -> results/fig_*.png
```

No third-party dependency beyond `numpy`/`matplotlib` for plotting; the fuzzer
itself is standard library only. Python 3.11+.

```bash
PYTHONPATH=src python -m mutation_bandit.cli demo --target tlv --scheduler repair_ctl
PYTHONPATH=src python -m mutation_bandit.cli bench --execs 20000 --seeds 1 2 3 4 5 6
PYTHONPATH=src python -m mutation_bandit.cli arms --target tlv --scheduler repair_ctl
```

## Layout

```
src/mutation_bandit/
  coverage.py     AFL-style edge bitmap (node ^ prev), virgin-bit accounting
  targets.py      TLV, JSON-lite and URL parsers with 12 named defects
  mutators.py     7 operators incl. target-aware structural repair
  schedulers.py   uniform, AFL fixed mix, AIMD repair control, contextual bandit
  engine.py       deterministic campaign loop, behavioural corpus admission
  bench.py        grid driver + summary statistics
  cli.py          demo / bench / arms
tests/            18 tests: coverage, operators, schedulers, engine determinism,
                  byte-stability of results.json
scripts/          make_figures.py, admission_sweep.py, check_repro.py
docs/             DESIGN.md, THREAT_MODEL.md, EVALUATION.md
results/          results.json, timing.json + four figures (committed)
```
## Method

Each target calls `COV.hit(node)` at every basic block. An edge is `node ^ prev`, so
the same block reached from two callers counts twice. A mutated input is admitted to
the corpus if it adds an edge or if it reaches a new (parse-progress, input-size)
cell. The second criterion is what lets payload growth accumulate towards a
length-overflow defect. Execution is bounded by a deterministic step budget rather
than a wall-clock timeout, because Windows has no `SIGALRM` and wall-clock timeouts
make results machine-dependent.

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md): instrumentation, operators, policy formulas,
  corpus admission, complexity.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): experimental-bias model, defect
  injection, non-claims.
- [`docs/EVALUATION.md`](docs/EVALUATION.md): methodology, all tables, the rejected
  hypothesis, threats to validity.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the design rules a patch has to keep.
- [`SECURITY.md`](SECURITY.md): what counts as a vulnerability here, and how to report.
- [`CHANGELOG.md`](CHANGELOG.md): release notes.
## Limitations

- Targets are Python parsers, not real C libraries; per-execution costs and
  crash semantics differ from a native fuzzer.
- Defects are injected, so ground truth is exact but the defect distribution is not
  representative of any real codebase.
- The benchmark says nothing about multi-hour campaigns, dictionary quality, or
  grammar-based fuzzers.
- The scheduling effect sizes are small and target-dependent; the honest summary is
  "policy choice matters less than corpus admission".

## License

MIT, see [`LICENSE`](LICENSE).
