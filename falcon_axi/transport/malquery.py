"""N4's closed pattern grammar and bounded search body, also checked at the sink."""

import re
from collections.abc import Mapping
from typing import Any

from falcon_axi.core import CliError

MAX_RESULTS = 100
MAX_PATTERN_BYTES = 4096


def search_body(string: str | None, hex: str | None, limit: int) -> dict[str, Any]:
    patterns = []
    if string is not None:
        if re.fullmatch(r"[\x20-\x7e]{1,4096}", string) is None or not string.strip():
            raise CliError("VALIDATION_ERROR", "--string requires 1-4096 printable ASCII characters with nonblank content")
        patterns.append({"type": "ascii", "value": string})
    if hex is not None:
        compact = hex.replace(" ", "")
        if not compact or len(compact) > MAX_PATTERN_BYTES * 2 or re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact) is None:
            raise CliError("VALIDATION_ERROR", "--hex requires 1-4096 literal byte pairs with optional spaces")
        patterns.append({"type": "hex", "value": compact.lower()})
    if not patterns:
        raise CliError("VALIDATION_ERROR", "malquery search requires --string or --hex", ["Both flags may be combined"])
    if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
        raise CliError("VALIDATION_ERROR", "MalQuery results require a limit from 1 to 100")
    return {"patterns": patterns, "options": {"limit": limit}}


def validate_search_body(body: Any, query: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Rebuild only admitted fields; no YARA, extra options, or unbounded matches can pass."""
    invalid = CliError("READ_ONLY_VIOLATION", "MalQuery search requires N4's validated patterns and bounded results")
    if query or not isinstance(body, Mapping) or set(body) != {"patterns", "options"}:
        raise invalid
    options, patterns = body["options"], body["patterns"]
    if not isinstance(options, Mapping) or set(options) != {"limit"}:
        raise invalid
    if not isinstance(patterns, list) or not 1 <= len(patterns) <= 2:
        raise invalid
    values: dict[str, str] = {}
    for pattern in patterns:
        if not isinstance(pattern, Mapping) or set(pattern) != {"type", "value"}:
            raise invalid
        kind, value = pattern["type"], pattern["value"]
        if not isinstance(kind, str) or kind not in ("ascii", "hex") or kind in values or not isinstance(value, str):
            raise invalid
        values[kind] = value
    try:
        return search_body(values.get("ascii"), values.get("hex"), options["limit"])
    except CliError:
        raise invalid from None
