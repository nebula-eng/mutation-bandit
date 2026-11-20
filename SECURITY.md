# Security policy

## Reporting a vulnerability

Report privately through GitHub's [security advisory
form](https://github.com/nebula-eng/mutation-bandit/security/advisories/new). The
report is visible only to the maintainer. There is no mailing list, so nothing sent
to an address at this project's name reaches anyone.

Include the command you ran, the input that triggers the problem, and the Python
version. You will get an acknowledgement within 72 hours.

## What counts here

This project runs four mutation-scheduling policies against three instrumented parsers with seeded defects, under a fixed execution budget. That shapes what a vulnerability is:

- Targets are Python parsers. Per-execution cost and crash semantics differ from a native fuzzer such as AFL++.
- Defects are injected, so ground truth is exact but the defect distribution is not representative of any real codebase.
- The negative result, operator-level bandit scheduling, is reported with its measured numbers in `docs/EVALUATION.md`.

A wrong verdict with no crash is in scope. In a measurement artifact a silently wrong
number is worse than an exception, because nothing prompts a reader to check it.

## Out of scope

- Anything that requires modifying the repository before running it.
- Differences caused by the host, where the README already states that a number is
  machine-dependent.
- The limits listed under Limitations in the README. They are known and written
  down; a report that restates one is not a finding.

## Data handling

The fuzzer runs entirely in process. Nothing is read from the network and nothing is written outside `results/`.
