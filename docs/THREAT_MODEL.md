# Threat model and scope

## 1. What this repository is

A measurement artifact for fuzzing research. It is not a fuzzing product, not a
vulnerability scanner, and not a claim about any real software. The "targets" are
Python parsers written for this study; their defects are injected deliberately and
documented in `docs/DESIGN.md`.

## 2. Adversary model (of the measurement, not of a system)

The relevant "adversary" here is a source of experimental bias, not an attacker.

| bias | mitigation |
|---|---|
| target-specific overfitting | three targets with different structure (length-prefixed, recursive, string-scanning) |
| seed cherry-picking | seeds fixed before the final run; all six reported, including outliers |
| metric shopping | two objectives pre-registered in the README and reported together, including the case where they disagree |
| implementation confound | all policies share one engine, one operator set, one admission rule; only `choose()` differs |
| timing artefacts | deterministic step budget; cost reported per execution, not per second |
| corpus drift between policies | identical admission function for every policy |

## 3. Defect injection as ground truth

Each defect is a missing check, not a malformed input the parser correctly
rejects. This distinction was the single largest methodological fix in the project:

- Version 1 counted any parser error as a bug. Every policy found a bug within 1-2
  executions; the measurement had zero discriminative power.
- Version 2 requires a structurally valid prefix (correct magic, valid checksums,
  declared counts consistent) before a defect is reachable. Detection times moved
  into the 10^2-10^3 execution range and the policies separated.

The cost of this choice is that the defect distribution is designed by the author.
It is not sampled from CVE data and must not be read as a prevalence estimate.

## 4. Non-claims

- No claim that AIMD repair control improves fuzzing of real software.
- No claim that the contextual bandit is a better fuzzer. It trades latency for
  depth, and the trade is measured, not resolved.
- No claim of novelty for edge coverage, havoc mutation, or bandit scheduling
  individually. The contribution is the controlled comparison and the corpus
  admission finding.
- No claim about multi-hour campaigns, distributed fuzzing, or grammar-based
  fuzzers.

## 5. Safety

All experiments run in-process on loopback data. There is no network access, no
process spawning, no filesystem mutation outside `results/`, and no code execution
from fuzzer-generated input: the targets are parsers, and the only effect of a
"crash" is a Python exception that the engine catches.

## 6. Ethics

The defects are artificial and confined to this repository. Nothing here is
weaponisable against a third-party system. If the scheduling results are reused,
the appropriate citation target is the methodology (controlled comparison,
behavioural corpus admission), not the specific numbers, which are
machine-and-target dependent.
