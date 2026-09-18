"""Stable error codes and exit codes (docs/design/v1.md §9.2)."""

from collections.abc import Mapping, Sequence
from typing import Any, Literal

ErrorCode = Literal[
    "VALIDATION_ERROR",
    "CREDENTIAL_INCOMPLETE",
    "FQL_INVALID",
    "AUTH_REQUIRED",
    "AUTH_FAILED",
    "SCOPE_DENIED",
    "TENANT_DENIED",
    "ORIGIN_NOT_ALLOWED",
    "REGION_MISMATCH",
    "NOT_FOUND",
    "PAGINATION_LIMIT",
    "RATE_LIMITED",
    "UPSTREAM_ERROR",
    "UPSTREAM_UNAVAILABLE",
    "NETWORK_UNREACHABLE",
    "TLS_UNTRUSTED",
    "READ_ONLY_VIOLATION",
    "UNKNOWN",
]

USAGE_CODES: frozenset[str] = frozenset({"VALIDATION_ERROR", "CREDENTIAL_INCOMPLETE", "FQL_INVALID"})


class CliError(Exception):
    """A failure carrying everything the error envelope prints.

    `details` holds the extra structured fields a specific code owes the caller, such as
    `required_scopes` on SCOPE_DENIED or `trace_id` on an upstream failure (§9.2, §9.4).
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        help: Sequence[str] = (),
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message
        self.help: tuple[str, ...] = tuple(help)
        self.details: dict[str, Any] = dict(details or {})
        self.exit_code = 2 if code in USAGE_CODES else 1
