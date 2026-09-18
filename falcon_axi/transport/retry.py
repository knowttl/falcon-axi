"""Retry policy for transient upstream failures (docs/design/v1.md §7.4).

Pure by design so the rules are exercised offline: it decides, the transport waits.
Retrying is unconditionally safe because every registered operation is a read (§3).
"""

import random as _random
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

MAX_ATTEMPTS = 3

BASE_BACKOFF_MS = 500
RETRYABLE = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class RetryDecision:
    wait_ms: float
    reason: Literal["retry_after", "backoff"]


def _backoff(attempt: int, random: float) -> float:
    base = BASE_BACKOFF_MS * 2 ** (attempt - 1)
    return float(round(base * (1 + random)))


def _seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds == seconds and seconds not in (float("inf"), float("-inf")) else None


def retry_plan(
    status: int,
    headers: Mapping[str, str],
    attempt: int,
    now_ms: float,
    random: float | None = None,
) -> RetryDecision | None:
    """attempt is the 1-based number of the attempt that just failed; now_ms is epoch milliseconds.

    random is the jitter source in [0, 1); it defaults to a fresh draw.
    """
    if attempt >= MAX_ATTEMPTS or status not in RETRYABLE:
        return None
    if status == 429:
        # gofalcon 208826a: X-RateLimit-RetryAfter is an epoch-seconds timestamp, honored only on 429.
        seconds = _seconds(headers.get("x-ratelimit-retryafter"))
        if seconds is not None and seconds * 1000 > now_ms:
            return RetryDecision(seconds * 1000 - now_ms, "retry_after")
    # Jitter spreads retries; it is not a security decision, so the default generator is right.
    jitter = _random.random() if random is None else random  # noqa: S311
    return RetryDecision(_backoff(attempt, jitter), "backoff")
