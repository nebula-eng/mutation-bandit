# Design

## 1. Problem statement

A coverage-guided fuzzer has three decisions per iteration: which seed to mutate, how
many bytes to change, and which mutation operator to apply. The third decision is
usually hard-coded (AFL's havoc stage samples operators from a fixed distribution).
This project asks whether making that decision adaptive changes defect discovery, and
under which conditions.

The question is narrower than "build a better fuzzer". Everything except operator
choice is held fixed: same seeds, same operators, same step budget, same corpus
rules. A measured difference is therefore attributable to scheduling.

## 2. Architecture

```
            +-------------------+
            |  corpus (bytes)   |<--------------------+
            |  + depth labels   |                     |
            +---------+---------+                     |
                      | parent selection              |
                      v                               |
            +-------------------+                     |
            |    scheduler      |  choose() x 1..2    |
            |  uniform | fixed  |                     |
            |  AIMD    | ctxUCB |                     |
            +---------+---------+                     |
                      | operator id                   |
                      v                               |
            +-------------------+    candidate        |
            |    mutators (7)   |-------------------->+
            |  + target.fixup   |                     |
            +-------------------+                     |
                                                      |
            +-------------------+   edges, progress   |
            | instrumented      |-------------------->+
            | target (parsers)  |
            +-------------------+
```

The engine owns timing, coverage accounting and corpus admission. The scheduler owns
only operator selection, which keeps the comparison clean.

## 3. Coverage instrumentation

Manual instrumentation, equivalent in spirit to AFL's compile-time `__afl_area`
writes:

```python
def hit(node):
    idx = (node ^ prev) & 0xFFFF
    prev = (node >> 1) & 0xFFFF
    if map[idx] == 0:
        new_edges += 1          # virgin bit
        map[idx] = 1
```

`node ^ prev` encodes edges rather than nodes: a block reached from two different
predecessors contributes two edges, which is what makes "new coverage" sensitive to
control-flow context rather than just reachability.

Hit counts are stored but never bucketed, and the scheduler does not consume them.
This is intentional: hit-count-derived features are known to be noisy at low
execution counts and would confound the scheduling comparison.

## 4. Targets and defects

A defect is a missing check, not a malformed input. Every parser rejects
truncated headers, bad checksums and illegal characters cleanly. Only the eleven
seeded defects raise `InjectedBug`:

| target | defect | precondition |
|---|---|---|
| TLV | `zero_len_double_free` | type 0, length 0, valid CRC |
| TLV | `crc_sentinel_bypass` | CRC byte 0xFF and payload > 64 B |
| TLV | `total_len_wrap` | >= 4 records, cumulative length > 255 |
| TLV | `nested_depth_unbounded` | 4 levels of valid nested containers |
| JSON | `depth_overflow` | 49 nested objects/arrays |
| JSON | `duplicate_key` | repeated key at depth 0 |
| JSON | `number_buffer_overflow` | number literal > 64 digits |
| URL | `userinfo_confusion` | two `@` in authority |
| URL | `port_truncation` | 5+ digit port > 65535 |
| URL | `nul_byte_host` | `%00` or NUL in host |
| URL | `host_too_long` | host > 253 bytes |

Early iterations of this benchmark counted "parser returned an error" as a bug. Every
policy then found a bug within 1-2 executions and the measurement carried no
information. The current design requires structurally valid input, which is why the
distributions separate.

## 5. Operators

Seven arms, each individually selectable:

| operator | effect | typical cost |
|---|---|---|
| `bitflip` | flip 1-4 bits | low |
| `byte_interesting` | write boundary values (0x00, 0x7f, 0x80, 0xff...) | low |
| `insert_block` | insert dictionary token or 1-8 random bytes | low |
| `delete_block` | remove 1-16 bytes | low |
| `repeat_block` | duplicate a slice | low |
| `splice` | splice with another corpus entry | medium |
| `fixup` | target-aware structural repair | high |

`fixup` is not a mutation. For TLV it recomputes the record count, extended lengths
and every CRC; for JSON it closes dangling brackets and terminates open strings. It
is the only operator that can convert an invalid input back into a valid one, which
is why it is the object of study rather than an implementation detail.

## 6. Scheduling policies

Let `w_i` be the number of pulls of arm `i` that produced at least one new edge, `n_i`
the number of pulls, and `c_i` the mean execution cost in milliseconds.

Uniform. Every arm equally likely, after one guaranteed pull each.

AFL fixed mix. Probabilities `{bitflip .15, byte .25, insert .20, delete .12,
repeat .08, splice .10, fixup .10}`. The repair arm is included so that the only
difference from the adaptive policies is *how* the mix is chosen.

AIMD repair control. A single scalar `p` controls the repair/destroy split:
choose `fixup` with probability `p`, otherwise an arm uniformly from the remaining
six. After each execution, if parse progress `<= 2`, `p <- min(0.60, p + 0.02)`; if
progress `>= 9`, `p <- max(0.02, p - 0.01)`. Progress is the number of instrumented
nodes executed, used as a cheap proxy for "how much structure survived". The
controller also enables depth-biased parent selection: half of the parents are drawn
from a pool of inputs with progress `>= 6`.

Contextual bandit. Three contexts by progress bucket (0-2, 3-8, 9+), independent
UCB1 tables per context with Laplace-smoothed success rate and exploration 0.45.
Reward is binary new-edge. `ctx_ucb` is included as the strong form of the original
hypothesis; it is also the clearest negative result.

Rejected: context-free UCB1. Reward is sparse (most pulls produce no edge), so the
exploration bonus dominates the estimated means and the policy concentrates on a few
arms. Pooled time-to-first-bug ends up within noise of uniform, but the per-target mix
swings: 1.5x to 2.2x slower on JSON-lite with no deep defect reached at all, faster on
URL. Its efficiency term divides by measured cost, so two identical runs disagree by
up to 40% on one target. Kept as an ablation, excluded from the headline table; see
`docs/EVALUATION.md` section 6.

## 7. Corpus admission

An input is admitted if it adds an edge or if `(progress // 3, log2(size))` is a
cell never seen before. The second criterion matters for defects that require growth:
a longer input that parses equally deep adds no coverage, so a purely coverage-driven
corpus discards exactly the stepping stones needed to reach `total_len_wrap` or
`number_buffer_overflow`.

This was validated empirically: at 5,000 executions, coverage-only admission produced a deep-defect
reachability of 0.00 on all three targets, and the JSON target found no defect at
all. With behavioural admission at the same budget, mean reachability is 0.04-0.58
depending on target, rising to 0.33-0.83 at 20,000 executions.

## 8. Determinism

- One `random.Random(seed)` per campaign, threaded through parent choice, operator
  choice and mutation.
- `Budget(steps)` raises `BudgetExceeded` after a fixed number of parser nodes. No
  wall-clock timeouts.
- Corpus ordering is insertion-ordered; no set iteration affects behaviour.
- Wall-clock measurements are written to `results/timing.json`, never to
  `results.json`. Running the same command twice therefore produces a byte-identical
  `results.json`, which is what makes the committed table diffable.
- The four headline policies (`uniform`, `afl_fixed`, `repair_ctl`, `ctx_ucb`) make
  their choice from counts alone. `ucb1` and `thompson` divide by `mean_cost_ms`, a
  measured quantity, so their arm choice is not reproducible; they appear only in the
  ablation section, where the instability is part of the result.

## 9. Complexity

Per execution: `O(len(input))` for mutation plus `O(nodes)` for parsing. Corpus
admission is `O(1)` amortised (dict + set). Parent selection is `O(1)`: the depth pool
avoids sorting the corpus, which an earlier version did and which inflated per-exec
cost by up to 8x for the depth-biased policy.

## 10. Parameter table

| parameter | value | rationale |
|---|---|---|
| max input size | 8192 B | keeps per-exec cost bounded |
| stack depth | 1-2, p=0.25 | bounds credit-assignment error |
| step budget | 1200 nodes | ~20x the deepest seed path |
| corpus cap | 4096 | memory bound |
| deep pool cap | 256 | recency + depth |
| edge map | 65536 bytes | AFL default |
| seeds per config | 6 | median + spread |
