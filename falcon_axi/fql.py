"""Filter shorthands for the three v1 domains (docs/design/v1.md §11.3).

Field names follow the documented filter tables of each collection: `severity_name`, `status`, and
`created_timestamp` on Alerts; `hostname`, `platform_name`, `status`, and `last_seen` on Hosts;
`aid`, `cve.severity`, `status`, and `created_timestamp` on Spotlight.
"""

import re
from dataclasses import dataclass

from falcon_axi.core import CliError

SEVERITIES = ("informational", "low", "medium", "high", "critical")
STATUSES = ("new", "in_progress", "closed", "reopened")
#: Documented Hosts `platform_name` and `status` filter values (§10.2); containment state is data,
#: never something falcon-axi can set.
PLATFORMS = ("windows", "mac", "linux")
HOST_STATUSES = ("normal", "containment_pending", "contained", "lift_containment_pending")
#: Documented Spotlight `cve.severity` and `status` filter values.
VULN_SEVERITIES = ("low", "medium", "high", "critical")
VULN_STATUSES = ("open", "closed", "reopen", "expired")

SINCE_PATTERN = re.compile(r"^(\d+)([mhd])$")


@dataclass(frozen=True)
class DetectionQuery:
    filter: str | None = None
    severity: str | None = None
    status: str | None = None
    since: str | None = None


@dataclass(frozen=True)
class HostQuery:
    filter: str | None = None
    hostname: str | None = None
    platform: str | None = None
    status: str | None = None
    since: str | None = None


@dataclass(frozen=True)
class VulnQuery:
    filter: str | None = None
    host: str | None = None
    severity: str | None = None
    status: str | None = None
    since: str | None = None


def _severity_term(value: str) -> str:
    normalized = _one_of(value, SEVERITIES, "severity")
    return f"severity_name:'{normalized[0].upper()}{normalized[1:]}'"


def _status_term(value: str) -> str:
    return f"status:'{_one_of(value, STATUSES, 'status')}'"


def _one_of(value: str, valid: tuple[str, ...], flag: str) -> str:
    normalized = value.lower()
    if normalized not in valid:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown {flag} {value}",
            [f"valid values for --{flag}: {', '.join(valid)}"],
        )
    return normalized


def _window(value: str) -> str:
    match = SINCE_PATTERN.match(value.lower())
    if not match:
        raise CliError(
            "VALIDATION_ERROR",
            "--since must be a relative window such as 24h",
            ["valid units for --since: m (minutes), h (hours), d (days)", "Example: `--since 7d`"],
        )
    return f"now-{match.group(1)}{match.group(2)}"


def _since_term(value: str) -> str:
    return f"created_timestamp:>'{_window(value)}'"


def _raw_term(value: str) -> str:
    if not value.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    return value


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
        terms.append(_raw_term(query.filter))
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


def host_filter(query: HostQuery) -> str | None:
    """Composes the Hosts shorthands into one FQL string; `hostname` supports wildcards (§7.3)."""
    terms: list[str] = []
    if query.hostname is not None:
        if not query.hostname.strip():
            raise CliError("VALIDATION_ERROR", "--hostname requires a value")
        terms.append(f"hostname:'{query.hostname}'")
    if query.platform is not None:
        platform = _one_of(query.platform, PLATFORMS, "platform")
        terms.append(f"platform_name:'{platform[0].upper()}{platform[1:]}'")
    if query.status is not None:
        terms.append(f"status:'{_one_of(query.status, HOST_STATUSES, 'status')}'")
    if query.since is not None:
        terms.append(f"last_seen:>'{_window(query.since)}'")
    if query.filter is not None:
        terms.append(_raw_term(query.filter))
    return "+".join(terms) if terms else None


def describe_host_query(query: HostQuery) -> str:
    parts: list[str] = []
    if query.hostname:
        parts.append(f"hostname {query.hostname}")
    if query.platform:
        parts.append(query.platform.lower())
    if query.status:
        parts.append(f"status {query.status.lower()}")
    if query.since:
        parts.append(f"seen in the last {query.since.lower()}")
    if query.filter:
        parts.append("the supplied filter")
    return " ".join(parts)


def vuln_filter(query: VulnQuery) -> str:
    """Composes the Spotlight shorthands, which are required and admit no wildcard (§7.3).

    `combinedQueryVulnerabilities` documents both rules: a filter must be provided, and wildcards
    are unsupported, so a `*` anywhere in the composed filter is rejected here rather than by a 400.
    """
    terms: list[str] = []
    if query.host is not None:
        if not query.host.strip():
            raise CliError("VALIDATION_ERROR", "--host requires a value")
        terms.append(f"aid:'{query.host}'")
    if query.severity is not None:
        terms.append(f"cve.severity:'{_one_of(query.severity, VULN_SEVERITIES, 'severity').upper()}'")
    if query.status is not None:
        terms.append(f"status:'{_one_of(query.status, VULN_STATUSES, 'status')}'")
    if query.since is not None:
        terms.append(_since_term(query.since))
    if query.filter is not None:
        terms.append(_raw_term(query.filter))
    if not terms:
        raise CliError(
            "VALIDATION_ERROR",
            "vuln list requires a filter",
            [
                "Run `falcon-axi vuln list --host <device_id>` for one host's vulnerabilities",
                "Run `falcon-axi vuln list --severity critical --status open` for the fleet's worst",
            ],
        )
    composed = "+".join(terms)
    if "*" in composed:
        raise CliError(
            "FQL_INVALID",
            "Spotlight filters do not support wildcards",
            [
                "Remove the `*` and match an exact value, for example `cve.id:'CVE-2024-3094'`",
                "Run `falcon-axi vuln list --help` for the filterable fields",
            ],
        )
    return composed


def describe_vuln_query(query: VulnQuery) -> str:
    parts: list[str] = []
    if query.severity:
        parts.append(f"{query.severity.lower()} severity")
    if query.status:
        parts.append(f"status {query.status.lower()}")
    if query.host:
        parts.append("on that host")
    if query.since:
        parts.append(f"first seen in the last {query.since.lower()}")
    if query.filter:
        parts.append("the supplied filter")
    return " ".join(parts)
