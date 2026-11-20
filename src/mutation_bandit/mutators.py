"""Mutation operators.

Each operator is a pure function of (rng, data, context) and is
individually selectable, which is what makes operator-level credit
assignment possible.  ``fixup`` is a structure-repair arm rather than a
mutation: it revisits an input and restores the invariants a grammar
would enforce (record count, checksum, bracket balance).
"""

from __future__ import annotations

import random

INTERESTING = bytes([0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF, 0x20, 0x22, 0x2C, 0x3A, 0x7B, 0x7D])

OPERATORS = (
    "bitflip",
    "byte_interesting",
    "insert_block",
    "delete_block",
    "repeat_block",
    "splice",
    "fixup",
)

# Fixed probabilities approximating a stock havoc stage with all
# operators enabled.  The repair arm is included so that the only
# difference from the bandit policies is *how* operators are scheduled.
AFL_FIXED_WEIGHTS = {
    "bitflip": 0.15,
    "byte_interesting": 0.25,
    "insert_block": 0.20,
    "delete_block": 0.12,
    "repeat_block": 0.08,
    "splice": 0.10,
    "fixup": 0.10,
}


def _bitflip(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    if not data:
        return bytes([rng.randrange(256)])
    out = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        pos = rng.randrange(len(out))
        out[pos] ^= 1 << rng.randrange(8)
    return bytes(out)


def _byte_interesting(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    if not data:
        return bytes([rng.choice(INTERESTING)])
    out = bytearray(data)
    for _ in range(rng.randint(1, 3)):
        out[rng.randrange(len(out))] = rng.choice(INTERESTING)
    return bytes(out)


def _insert_block(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    dictionary = ctx["dictionary"]
    if dictionary and rng.random() < 0.6:
        block = rng.choice(dictionary)
    else:
        block = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    pos = rng.randrange(len(data) + 1)
    return data[:pos] + block + data[pos:]


def _delete_block(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    if len(data) < 2:
        return data
    start = rng.randrange(len(data))
    length = rng.randint(1, min(16, len(data) - start))
    return data[:start] + data[start + length :]


def _repeat_block(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    if not data:
        return data
    start = rng.randrange(len(data))
    length = rng.randint(1, min(32, len(data) - start))
    block = data[start : start + length]
    pos = rng.randrange(len(data) + 1)
    return data[:pos] + block + data[pos:]


def _splice(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    corpus = ctx["corpus"]
    if not corpus:
        return data
    other = corpus[rng.randrange(len(corpus))]
    if not other:
        return data
    cut_a = rng.randrange(len(data) + 1) if data else 0
    cut_b = rng.randrange(len(other) + 1)
    return data[:cut_a] + other[cut_b:]


def _fixup(rng: random.Random, data: bytes, ctx: dict) -> bytes:
    return ctx["fixup"](data)


_DISPATCH = {
    "bitflip": _bitflip,
    "byte_interesting": _byte_interesting,
    "insert_block": _insert_block,
    "delete_block": _delete_block,
    "repeat_block": _repeat_block,
    "splice": _splice,
    "fixup": _fixup,
}


def apply_operator(name: str, rng: random.Random, data: bytes, ctx: dict) -> bytes:
    return _DISPATCH[name](rng, data, ctx)


def mutate(
    rng: random.Random,
    data: bytes,
    scheduler,
    ctx: dict,
    max_ops: int = 2,
    stack_probability: float = 0.25,
) -> tuple[bytes, list[str]]:
    """Apply one or two operator arms; return the input and the arms used.

    Stack depth is kept low (<= 2) on purpose: credit for a new edge is
    then attributable to at most two arms, which bounds the credit
    assignment error that the paper's scheduler has to tolerate.
    """
    ops: list[str] = []
    out = data
    n_ops = 2 if (max_ops >= 2 and rng.random() < stack_probability) else 1
    for _ in range(n_ops):
        name = scheduler.choose(rng)
        out = apply_operator(name, rng, out, ctx)
        ops.append(name)
        if len(out) > 8192:
            out = out[:8192]
    return out, ops
