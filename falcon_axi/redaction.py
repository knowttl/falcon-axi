"""Invocation-local exact-value redaction, including encoded secret forms."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from urllib.parse import quote

_values: ContextVar[set[str] | None] = ContextVar("redaction_values", default=None)


@contextmanager
def redaction_scope(*, inherit: bool = False) -> Iterator[None]:
    token = _values.set(set(_values.get() or ()) if inherit else set())
    try:
        yield
    finally:
        _values.reset(token)


def register_secret(value: str) -> None:
    values = _values.get()
    if values is not None and value:
        values.update((value, json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1], quote(value, safe="")))


def redact_text(text: str) -> str:
    for value in sorted(_values.get() or (), key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    return text
