"""Python port of beyondtrust-axi's canonical response-diagnostics contract.

The shared vectors are the byte contract; only structure and bounded metadata leave this module.
"""

import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.redaction import redact_text

_TYPES = frozenset(
    "string number boolean object array null undefined bigint symbol function date int unknown never void".split()
)
_ISSUE_CODES = frozenset(
    "invalid_type too_big too_small invalid_format not_multiple_of unrecognized_keys invalid_union "
    "invalid_key invalid_element invalid_value custom".split()
)
_MISSING = object()


def _type(value: Any) -> str:
    if value is _MISSING:
        return "undefined"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


class ResponseDiagnostics:
    def __init__(self, redactor: Callable[[str], str] = redact_text) -> None:
        self.redactor = redactor
        self.details: dict[str, Any] = {}
        self.data: Any = None
        self.shape_by_path: dict[tuple[str | int, ...], dict[str, Any]] = {}

    def _segment(self, key: str) -> str:
        identifier = re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,39}", key)
        guid = re.fullmatch(r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:[-_][0-9a-f]{4}){3}[-_][0-9a-f]{12})", key, re.I)
        return f"[{json.dumps(self.redactor(key) if identifier and not guid else '<key>', ensure_ascii=False)}]"

    def record(self, status: int, headers: Mapping[str, str], data: Any) -> None:
        self.data = data
        self.shape_by_path.clear()
        header = next((value for key, value in headers.items() if key.lower() == "content-type"), "")
        media_type = header.split(";", 1)[0].strip()
        content_type = (
            self.redactor(media_type)
            if len(media_type) <= 128 and re.fullmatch(r"[a-z0-9!#$&^_.+\-]+/[a-z0-9!#$&^_.+\-]+", media_type, re.I)
            else None
        )
        shape: list[dict[str, Any]] = []
        truncated = False
        characters = 0

        def visit(value: Any, path: str, keys: tuple[str | int, ...]) -> None:
            nonlocal truncated, characters
            if len(shape) >= 64 or len(path) > 256 or characters + len(path) > 4096:
                truncated = True
                return
            characters += len(path)
            entry: dict[str, Any] = {"path": path, "type": _type(value)}
            if isinstance(value, list):
                entry["count"] = len(value)
            shape.append(entry)
            self.shape_by_path[keys] = entry
            if isinstance(value, list) and value:
                if len(keys) >= 4:
                    truncated = True
                else:
                    visit(value[0], path + "[*]", (*keys, 0))
            elif isinstance(value, Mapping):
                for key, child in value.items():
                    if len(keys) >= 4 or len(shape) >= 64:
                        truncated = True
                        break
                    visit(child, path + self._segment(str(key)), (*keys, key))
                    if truncated:
                        break

        visit(data, "$", ())
        self.details = {
            "status": status if type(status) is int and 100 <= status <= 599 else None,
            "contentType": content_type,
            "shape": shape,
            "shapeTruncated": truncated,
        }

    def validation_failed(self, issues: Sequence[Mapping[str, Any]]) -> None:
        paths: list[str] = []
        annotations: list[dict[str, Any]] = []
        truncated = False
        characters = 0
        for issue in issues:
            keys = issue["path"]
            path = "$"
            for depth, key in enumerate(keys):
                if depth >= 4:
                    truncated = True
                    break
                path += "[*]" if type(key) is int and 0 <= key <= 2**53 - 1 else self._segment(str(key))
            if len(paths) >= 64 or len(path) > 256 or characters + len(path) > 4096:
                truncated = True
                break
            characters += len(path)
            paths.append(path)
            received = self.data
            for key in keys:
                if isinstance(received, Mapping):
                    received = received.get(key, _MISSING)
                elif isinstance(received, list) and type(key) is int and 0 <= key < len(received):
                    received = received[key]
                else:
                    received = _MISSING
            expected = issue.get("expected")
            expected = expected if isinstance(expected, str) and expected in _TYPES else "unknown"
            annotation: dict[str, Any] = {"path": path, "received": _type(received), "expected": expected}
            code = issue.get("code")
            if isinstance(code, str) and code in _ISSUE_CODES:
                annotation["code"] = code
            if truncated:
                annotation["pathTruncated"] = True
            annotations.append(annotation)
            if not truncated and isinstance(issue.get("expected"), str) and issue["expected"] in _TYPES:
                entry = self.shape_by_path.get(tuple(keys))
                if entry is not None:
                    entry["expected"] = expected
            if truncated:
                break
        self.details.update(issues=annotations, issuePaths=paths, issuePathsTruncated=truncated)


_current: ContextVar[ResponseDiagnostics | None] = ContextVar("response_diagnostics", default=None)


@contextmanager
def diagnostics_scope() -> Iterator[None]:
    token = _current.set(None)
    try:
        yield
    finally:
        _current.reset(token)


def record_response(status: int, headers: Mapping[str, str], body: Any) -> None:
    diagnostics = ResponseDiagnostics()
    if 200 <= status < 300:
        diagnostics.record(status, headers, body)
    _current.set(diagnostics)


def upstream_invalid(message: str, help: Sequence[str] = (), details: Mapping[str, Any] | None = None) -> CliError:
    diagnostics = _current.get()
    return CliError("UPSTREAM_ERROR", message, help, {**(diagnostics.details if diagnostics else {}), **(details or {})})
