"""The TOON boundary (docs/design/v1.md §10.1)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple

from falcon_axi.redaction import redact_text

#: Keys redacted on every stream. The first five match falconpy's `sanitize_dictionary` (§5.5).
#: `cid` and `#repo.cid` are NG-SIEM event fields that carry the tenant CID.
REDACTED_KEYS = frozenset(
    {
        "access_token",
        "client_id",
        "client_secret",
        "member_cid",
        "token",
        "authorization",
        "cid",
        "customer_id",
        "#repo.cid",
        "children_cids",
        "clientsecret",
        "clientid",
        "membercid",
        "refresh_token",
        "privatekey",
    }
)


class Raw(NamedTuple):
    """Emits `key: text` verbatim, for the hand-formatted lines `encode()` would mangle (§10.1)."""

    text: str


def raw(text: str) -> Raw:
    return Raw(text)


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            redact_text(str(key)): "[redacted]" if str(key).lower() in REDACTED_KEYS else redact(entry)
            for key, entry in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(entry) for entry in value]
    if isinstance(value, str):
        return _KEY_VALUE_PATTERN.sub(
            lambda match: match[1] + "[redacted]", _SECRET_PATTERN.sub("[redacted]", redact_text(value))
        )
    return value


_SECRET_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"|(?i:AccountKey=)[^;\s]+|(?i:sig=)[A-Za-z0-9%+/=]+"
)

_KEY_VALUE_PATTERN = re.compile(
    r'(?<![\w.#])("?(?:'
    + "|".join(re.escape(key) for key in sorted(REDACTED_KEYS))
    + r')"?\s*(?:<=>|:=|!=|==|=~|<=|>=|=|<|>|:|\blike\b)\s*)'
    r'(\[redacted\]|"(?:\\.|[^"\\\n])*(?:"|$)|Bearer[ \t]+[^\s|,;)\]}]+|[^\s|,;)\]}]+)',
    re.IGNORECASE,
)


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
    items = ",".join(f'"{_escape(_redact_help(item))}"' for item in help)
    return f"help[{len(help)}]: {items}\n"


def _redact_help(item: str) -> str:
    excerpt, separator, caret = item.rpartition("\n")
    if separator and caret.strip() == "^":
        prefix = excerpt.rsplit("\n", 1)[-1][: caret.index("^")]
        return f"{redact(excerpt)}\n{' ' * len(redact(prefix))}^"
    return str(redact(item))


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
