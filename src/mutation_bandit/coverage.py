"""Edge coverage map in the spirit of AFL's shared-memory bitmap.

Instrumentation convention (manual, mirroring AFL's ``__afl_area``):
every basic block calls ``COV.hit(node_id)``.  Edges are derived from
``node_id ^ prev`` so that a block reached through two different callers
counts as two distinct edges.  Only virgin bits (0 -> non-zero) are
counted as "new"; hit-count bucketing is deliberately omitted because
none of the scheduling policies in this project consume hit counts.
"""

from __future__ import annotations

MAP_SIZE = 1 << 16
MASK = MAP_SIZE - 1


class CoverageMap:
    __slots__ = ("size", "map", "prev", "new_edges", "total_hits")

    def __init__(self, size: int = MAP_SIZE) -> None:
        self.size = size
        self.map = bytearray(size)
        self.prev = 0
        self.new_edges = 0
        self.total_hits = 0

    def reset_edge(self) -> None:
        self.prev = 0

    def hit(self, node: int) -> None:
        idx = (node ^ self.prev) & MASK
        self.prev = (node >> 1) & MASK
        value = self.map[idx]
        if value == 0:
            self.new_edges += 1
            self.map[idx] = 1
        elif value < 255:
            self.map[idx] = value + 1
        self.total_hits += 1

    def reset(self) -> None:
        self.map = bytearray(self.size)
        self.prev = 0
        self.new_edges = 0
        self.total_hits = 0

    def touched(self) -> int:
        return sum(1 for b in self.map if b)


COV = CoverageMap()


def set_coverage(cov: CoverageMap) -> None:
    global COV
    COV = cov
