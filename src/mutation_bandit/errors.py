"""Control-flow exceptions shared by targets and the execution engine."""

from __future__ import annotations


class BudgetExceeded(Exception):
    """Raised when a target exceeds its deterministic step budget.

    A wall-clock timeout is not used on purpose: on Windows there is no
    SIGALRM, and wall-clock timeouts make experiments non-reproducible
    under machine load.  A step budget is deterministic and portable.
    """


class InjectedBug(Exception):
    """Raised by a target when a seeded defect is reached."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class Budget:
    __slots__ = ("left", "steps")

    def __init__(self, steps: int) -> None:
        self.left = steps
        self.steps = steps

    def tick(self, n: int = 1) -> None:
        self.left -= n
        if self.left < 0:
            raise BudgetExceeded


def bug(name: str) -> None:
    raise InjectedBug(name)
