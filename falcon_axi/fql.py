"""Filter shorthands for the Alerts domain (docs/design/v1.md §11.3).

Field names follow the documented Alerts filter fields that falcon-mcp's detections module uses:
`severity_name`, `status`, and `created_timestamp`.
"""

import re
from dataclasses import dataclass

from falcon_axi.core import CliError

SEVERITIES = ("informational", "low", "medium", "high", "critical")
STATUSES = ("new", "in_progress", "closed", "reopened")

SINCE_PATTERN = re.compile(r"^(\d+)([mhd])$")


@dataclass(frozen=True)
class DetectionQuery:
    filter: str | None = None
    severity: str | None = None
    status: str | None = None
    since: str | None = None


def _severity_term(value: str) -> str:
    normalized = value.lower()
    if normalized not in SEVERITIES:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown severity {value}",
            [f"valid values for --severity: {', '.join(SEVERITIES)}"],
        )
    return f"severity_name:'{normalized[0].upper()}{normalized[1:]}'"


def _status_term(value: str) -> str:
    normalized = value.lower()
    if normalized not in STATUSES:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown status {value}",
            [f"valid values for --status: {', '.join(STATUSES)}"],
        )
    return f"status:'{normalized}'"


def _since_term(value: str) -> str:
    match = SINCE_PATTERN.match(value.lower())
    if not match:
        raise CliError(
            "VALIDATION_ERROR",
            "--since must be a relative window such as 24h",
            ["valid units for --since: m (minutes), h (hours), d (days)", "Example: `--since 7d`"],
        )
    return f"created_timestamp:>'now-{match.group(1)}{match.group(2)}'"


def detection_filter(query: DetectionQuery) -> str | None:
    """Composes the shorthand flags and any raw `--filter` into one FQL string; `+` is AND."""
    terms: list[str] = []
    if query.severity is not None:
        terms.append(_severity_term(query.severity))
    if query.status is not None:
        terms.append(_status_term(query.status))
    if query.since is not None:
        terms.append(_since_term(query.since))
    if query.filter is not None:
        if not query.filter.strip():
            raise CliError("VALIDATION_ERROR", "--filter requires a value")
        terms.append(query.filter)
    return "+".join(terms) if terms else None


def describe_detection_query(query: DetectionQuery) -> str:
    """Plain-language restatement of the query, so an empty result says what produced it (§10.5)."""
    parts: list[str] = []
    if query.severity:
        parts.append(f"{query.severity.lower()} severity")
    if query.status:
        parts.append(f"status {query.status.lower()}")
    if query.since:
        parts.append(f"in the last {query.since.lower()}")
    if query.filter:
        parts.append("the supplied filter")
    return " ".join(parts)
