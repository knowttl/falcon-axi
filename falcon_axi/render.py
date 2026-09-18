"""The TOON boundary (docs/design/v1.md §10.1)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

#: Keys redacted on every stream, taken from falconpy's `sanitize_dictionary` (§5.5).
REDACTED_KEYS = frozenset({"access_token", "client_id", "client_secret", "member_cid", "token", "authorization"})


class Raw(NamedTuple):
    """Emits `key: text` verbatim, for the hand-formatted lines `encode()` would mangle (§10.1)."""

    text: str


def raw(text: str) -> Raw:
    return Raw(text)


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: "[redacted]" if str(key).lower() in REDACTED_KEYS else redact(entry) for key, entry in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(entry) for entry in value]
    return value


def mask_cid(cid: str) -> str:
    """Masks a tenant identifier to its suffix; no v1 output reveals the value (§5.5)."""
    return "…" if len(cid) <= 4 else f"…{cid[-4:]}"


_CONTROL = re.compile(r"[\u0000-\u001f]")


def _escape(value: str) -> str:
    """TOON §7.1 string escaping, matching `@toon-format/toon`'s `escapeString`.

    The encoder's own escaping is not reachable for a single value, and the help block is
    hand-formatted, so this stays in step with the spec rather than with a private import.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return _CONTROL.sub(lambda match: f"\\u{ord(match.group()):04x}", escaped)


def _help_block(help: Sequence[str]) -> str:
    if not help:
        return ""
    items = ",".join(f'"{_escape(item)}"' for item in help)
    return f"help[{len(help)}]: {items}\n"


def render(value: Mapping[str, Any], help: Sequence[str] = ()) -> str:
    """Renders one TOON document on stdout (§10.1).

    Row data goes through `encode()`; raw lines and the help block are hand-formatted, because
    `encode()` inlines primitive arrays and would break the help block shape.
    """
    # The encoder is imported here, not at module load, so `--help` and a usage error answer
    # without paying for it (AXI §10).
    from toon_format import encode

    output = ""
    pending: dict[str, Any] = {}

    def flush() -> str:
        nonlocal pending
        if not pending:
            return ""
        text = f"{encode(redact(pending)).rstrip()}\n"
        pending = {}
        return text

    for key, entry in value.items():
        if entry is None:
            continue
        if isinstance(entry, Raw):
            output += flush()
            output += f"{key}: {entry.text}\n"
            continue
        pending[key] = entry
    output += flush()
    return f"{output}{_help_block(help)}"


class Truncated(NamedTuple):
    text: str
    truncated: bool


def truncate(value: str, maximum: int = 800) -> Truncated:
    """Truncates a long field and says how much is missing (§10.4)."""
    if len(value) <= maximum:
        return Truncated(value, False)
    return Truncated(f"{value[:maximum]}… (truncated, {len(value)} chars total)", True)
