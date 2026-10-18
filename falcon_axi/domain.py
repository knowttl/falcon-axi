"""Response reading shared by the detection, host, and vulnerability domains.

Every domain module is a pure function from arguments to request descriptors and from responses to
rows (docs/design/v1-python.md §4), and these are the parts all three read the same way: the
resource list, the server's `total`, and the rate-limit note §7.4 puts on list output.
"""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.transport.types import FalconResponse

#: Rows in one non-walking call, for every list command (docs/design/v1.md §7.3).
DEFAULT_LIMIT = 20


@dataclass(frozen=True)
class CommandOutput:
    value: dict[str, Any]
    help: tuple[str, ...]


def parse_fields(value: str, allowed: Collection[str], defaults: Sequence[str]) -> tuple[str, ...]:
    """Validate extra columns and retain their first-requested order (§10.2)."""
    names = [part.strip() for part in value.split(",")]
    if any(not name for name in names):
        raise CliError(
            "VALIDATION_ERROR",
            "--fields requires one or more field names",
            [f"valid --fields names: {', '.join(allowed)}"],
        )
    unknown = [name for name in names if name not in allowed]
    if unknown:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown --fields name {', '.join(unknown)}",
            [
                f"valid --fields names: {', '.join(allowed)}",
                f"default columns {', '.join(defaults)} are always included",
            ],
        )
    return tuple(dict.fromkeys(names))


def body_of(response: FalconResponse) -> Mapping[str, Any]:
    return response.body if isinstance(response.body, Mapping) else {}


def resources(response: FalconResponse) -> list[Any]:
    listed = body_of(response).get("resources")
    return list(listed) if isinstance(listed, list) else []


def _pagination(response: FalconResponse) -> Mapping[str, Any] | None:
    meta = body_of(response).get("meta")
    pagination = meta.get("pagination") if isinstance(meta, Mapping) else None
    return pagination if isinstance(pagination, Mapping) else None


def total(response: FalconResponse) -> int | None:
    """The server's `total`, or None. It is never invented when the endpoint omits it (§7.2)."""
    pagination = _pagination(response)
    value = pagination.get("total") if pagination else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def after_token(response: FalconResponse) -> str | None:
    """Spotlight's opaque `after` token, read from `meta.pagination.after` (§7.1)."""
    pagination = _pagination(response)
    value = pagination.get("after") if pagination else None
    return value if isinstance(value, str) and value else None


def text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def rate_limit_note(session: Session) -> str | None:
    """Surfaces the remaining rate-limit budget below 10% of the window (§7.4)."""
    limit = session.rate_limit.limit
    remaining = session.rate_limit.remaining
    if limit is None or remaining is None or limit <= 0:
        return None
    if remaining < limit * 0.1:
        return f"{remaining} of {limit} requests remaining in this rate limit window"
    return None
