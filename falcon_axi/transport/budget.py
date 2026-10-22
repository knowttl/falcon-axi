"""Invocation deadlines shared by authentication, requests, retries, and search polling."""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from falcon_axi.core import CliError

_deadline: ContextVar[float | None] = ContextVar("request_deadline", default=None)


class BudgetExpired(CliError):
    def __init__(self) -> None:
        super().__init__("NETWORK_UNREACHABLE", "the search invocation reached its --wait deadline")


def deadline_after(wait: int) -> float | None:
    deadline = _deadline.get()
    if deadline is not None:
        return deadline
    return time.monotonic() + wait if wait else None


@contextmanager
def request_budget(deadline: float | None) -> Iterator[None]:
    inherited = _deadline.get()
    if inherited is not None:
        deadline = min(inherited, deadline) if deadline is not None else inherited
    token = _deadline.set(deadline)
    try:
        yield
    finally:
        _deadline.reset(token)


def remaining_seconds() -> float | None:
    deadline = _deadline.get()
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BudgetExpired()
    return remaining
