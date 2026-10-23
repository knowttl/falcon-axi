"""MalQuery indexed-file metadata and quota reads, without search or downloads."""

import re
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput, body_of
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs

_METADATA_FIELDS = ("family", "filesize", "filetype", "first_seen", "label", "md5", "sha1", "sha256")
_QUOTA_FIELDS = (
    "days_left",
    "download_count",
    "download_counts",
    "download_limit",
    "hunt_count",
    "hunt_counts",
    "hunt_limit",
    "monitor_count",
    "monitor_limit",
    "refresh_time",
)


def validate_sha256(value: str) -> None:
    if re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
        raise CliError("VALIDATION_ERROR", "sha256 requires exactly 64 hex characters")


def _read(ctx: Invocation) -> CommandOutput:
    metadata = ctx.spec.name == "malquery show"
    operation = ctx.spec.operations[0]
    answer = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": (ctx.positionals[0].lower(),)} if metadata else {},
        ),
    )
    if answer.status != 200:
        raise translate_falcon_error(
            answer, operation, "MalQuery metadata" if metadata else "MalQuery quota", not_found_command="malquery quota"
        )
    body = body_of(answer)
    invalid = CliError("UPSTREAM_ERROR", "Falcon returned an invalid MalQuery response")
    if body.get("errors"):
        raise invalid
    fields: tuple[str, ...]
    if metadata:
        records = answer.body if isinstance(answer.body, list) else body.get("resources")
        if not isinstance(records, list):
            raise invalid
        if not records:
            return CommandOutput(
                {
                    "malquery": raw(
                        "0 indexed files for that SHA-256; no MalQuery metadata found. "
                        "No data or missing Falcon MalQuery licensing can cause an empty result"
                    )
                },
                (),
            )
        if len(records) != 1 or not isinstance(records[0], Mapping):
            raise invalid
        record = records[0]
        hash = record.get("sha256")
        if not isinstance(hash, str) or hash.lower() != ctx.positionals[0].lower():
            raise invalid
        fields = _METADATA_FIELDS
    else:
        quota = body.get("meta")
        if not isinstance(quota, Mapping) or not any(field in quota for field in _QUOTA_FIELDS):
            raise invalid
        record = quota
        fields = _QUOTA_FIELDS
    value: dict[str, Any] = {field: record.get(field) if record.get(field) is not None else "unknown" for field in fields}
    return CommandOutput({"malquery" if metadata else "quota": value}, ())


COMMAND_SPECS = (
    CommandSpec(
        name="malquery show",
        handler=_read,
        operations=("GetMalQueryMetadataV1",),
        summary="  malquery show <sha256>    indexed file metadata by SHA-256",
        positional=("SHA-256 hash", "Run `falcon-axi malquery show <64-hex-hash>` for indexed file metadata"),
        help="\n".join(
            [
                "falcon-axi malquery show <sha256>",
                "",
                "sha256 must contain exactly 64 hex characters; validated before authentication.",
                "Renders family, filesize, filetype, first_seen, label, md5, sha1, and sha256.",
                "An empty result can mean no indexed file or missing Falcon MalQuery licensing.",
                "",
                "Examples:",
                "  falcon-axi malquery show " + "0" * 64,
                "  falcon-axi malquery quota",
                "",
                "Read-only; requires MalQuery:read and Falcon MalQuery. No search or sample download.",
            ]
        ),
    ),
    CommandSpec(
        name="malquery quota",
        handler=_read,
        operations=("GetMalQueryQuotasV1",),
        summary="  malquery quota            MalQuery quota counters and refresh time",
        help="\n".join(
            [
                "falcon-axi malquery quota",
                "",
                "Renders download, hunt, and monitor counts and limits, days_left, and refresh_time.",
                "Includes the documented download_counts and hunt_counts arrays; absent fields are unknown.",
                "",
                "Examples:",
                "  falcon-axi malquery quota",
                "  falcon-axi malquery show " + "0" * 64,
                "",
                "Read-only; requires MalQuery:read and Falcon MalQuery. Does not consume search or download quota.",
            ]
        ),
    ),
)
