"""Falcon failure to falcon-axi envelope (docs/design/v1.md §9.2, §9.4)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.transport.operations import OperationId, operation
from falcon_axi.transport.types import FalconResponse

_FILTER_WORDS = re.compile(r"\b(fql|filter|query)\b", re.IGNORECASE)


def _body_of(response: FalconResponse) -> Mapping[str, Any]:
    return response.body if isinstance(response.body, Mapping) else {}


def falcon_messages(response: FalconResponse) -> list[str]:
    """Falcon's error detail lives in the body, never only in the status line (§9.4)."""
    errors = _body_of(response).get("errors") or []
    if not isinstance(errors, Sequence):
        return []
    return [entry["message"] for entry in errors if isinstance(entry, Mapping) and entry.get("message")]


def trace_id(response: FalconResponse) -> str | None:
    meta = _body_of(response).get("meta")
    if isinstance(meta, Mapping):
        value = meta.get("trace_id")
        if isinstance(value, str):
            return value
    return None


def translate_falcon_error(response: FalconResponse, id: OperationId, subject: str) -> CliError:
    """Maps a Falcon failure onto falcon-axi's own envelope.

    Raw Falcon bodies, HTTP status numbers, and endpoint paths never reach stdout.
    """
    messages = falcon_messages(response)
    trace = trace_id(response)
    descriptor = operation(id)
    scopes = descriptor.scopes
    details = {"trace_id": trace} if trace else {}
    if response.status == 400:
        if any(_FILTER_WORDS.search(message) for message in messages):
            return CliError(
                "FQL_INVALID",
                f"the filter for {subject} was rejected",
                [
                    "FQL uses + for AND, `,` for OR, and values must be quoted",
                    "Example: `--filter \"severity_name:'High'+status:'new'\"`",
                    "Run `falcon-axi detection list --help` for the filterable fields",
                ],
            )
        return CliError(
            "UPSTREAM_ERROR",
            f"Falcon rejected the request for {subject}",
            ["Check the flags for this command with `--help`"],
            details,
        )
    if response.status == 401:
        return CliError(
            "AUTH_FAILED",
            "the Falcon credential was rejected",
            [
                "The client ID or secret is wrong, or the API client was revoked",
                "Run `falcon-axi auth status` after updating the credential",
            ],
        )
    if response.status == 403:
        if descriptor.effect != "read":
            # The one write scope falcon-axi asks for, so the remedy cannot say "read only" (§4.3).
            return CliError(
                "SCOPE_DENIED",
                f"this API client is not permitted to run {subject}",
                [
                    f"Grant {' and '.join(scopes)} to the API client in the Falcon console "
                    "under Support and resources > API clients and keys",
                    "Run `falcon-axi scopes` for the matrix, including which commands need this write scope",
                ],
                {"required_scopes": list(scopes)},
            )
        return CliError(
            "SCOPE_DENIED",
            f"this API client is not permitted to read {subject}",
            [
                f"Grant {' and '.join(scopes)} (read only) to the API client in the Falcon console "
                "under Support and resources > API clients and keys",
                "A 403 can also mean the API client is disabled",
            ],
            {"required_scopes": list(scopes)},
        )
    if response.status == 404:
        return CliError(
            "NOT_FOUND",
            f"no {subject} matched that identifier",
            ["Run `falcon-axi detection list` to see current identifiers"],
        )
    if response.status == 429:
        return CliError(
            "RATE_LIMITED",
            "Falcon rate limited this API client",
            [
                "Wait for the rate limit window to reset and retry",
                "Narrow the FQL filter or lower `--limit` to issue fewer requests",
            ],
        )
    if response.status in (502, 503, 504):
        return CliError(
            "UPSTREAM_UNAVAILABLE",
            "Falcon is temporarily unavailable",
            ["Retry shortly", "Quote the trace_id when opening a CrowdStrike support case"],
            details,
        )
    return CliError(
        "UPSTREAM_ERROR",
        f"Falcon could not answer the request for {subject}",
        ["Retry shortly", "Quote the trace_id when opening a CrowdStrike support case"],
        details,
    )
