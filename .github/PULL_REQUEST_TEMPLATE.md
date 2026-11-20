## What this changes

<!-- One paragraph. If it moves a reported number, give the before and after. -->

## Kind

- [ ] Defect fix
- [ ] New protocol, parser or detector
- [ ] New measurement or experiment
- [ ] Documentation
- [ ] Refactor with no behaviour change

## Design rules

- [ ] Execution is bounded by a step budget, never by wall-clock time. Windows has no `SIGALRM`, and a wall-clock cut-off makes results machine-dependent.
- [ ] `results/results.json` holds deterministic fields only; wall-clock measurements go to `results/timing.json`. The unit tests assert this.
- [ ] One `random.Random(seed)` per campaign, threaded through parent choice, operator choice and mutation. No second source of randomness.
- [ ] Defects are injected and named. A patch that adds one updates `targets.py`, the count in the README, and the ablation table together.

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -v` passes
- [ ] Reported numbers regenerated from `results/results.json`, not hand-edited
- [ ] Documentation updated where behaviour is user-visible

## Evidence

<!-- For a new detector or measurement: the input that triggers it, and one that must
not. False positives matter as much as detections. -->

## Notes for review

<!-- Ordering assumptions, overlap policy, performance trade-offs. -->
