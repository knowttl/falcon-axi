"""MalQuery metadata, quota, and N4's bounded exact/fuzzy pattern searches."""

import re
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput, body_of, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.malquery import search_body
from falcon_axi.transport.operations import OperationId
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


def validate_request_id(value: str) -> None:
    if re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", value) is None:
        raise CliError("VALIDATION_ERROR", "MalQuery request id must be a UUID")


def _search(ctx: Invocation) -> CommandOutput:
    status = ctx.spec.name == "malquery status"
    operation: OperationId = (
        "GetMalQueryRequestV1"
        if status
        else ("PostMalQueryFuzzySearchV1" if ctx.flags.get("fuzzy") else "PostMalQueryExactSearchV1")
    )
    answer = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": (ctx.positionals[0],)} if status else {},
            body=None if status else search_body(ctx.text("string"), ctx.text("hex"), ctx.limit),
        ),
    )
    if answer.status != 200:
        if answer.status == 400:
            raise CliError(
                "UPSTREAM_ERROR",
                "Falcon rejected the MalQuery patterns or request",
                ["Check `falcon-axi malquery search --help` for the supported literal pattern grammar"],
            )
        raise translate_falcon_error(answer, operation, "MalQuery search", not_found_command="malquery quota")
    body = body_of(answer)
    invalid = CliError("UPSTREAM_ERROR", "Falcon returned an invalid MalQuery search response")
    if body.get("errors"):
        raise invalid
    meta = body.get("meta")
    if not isinstance(meta, Mapping):
        raise invalid
    request_id = meta.get("reqid")
    value: dict[str, Any] = {}
    help: list[str] = []
    if status or not ctx.flags.get("fuzzy"):
        if not isinstance(request_id, str) or not isinstance(meta.get("status"), str) or not meta["status"].strip():
            raise invalid
        try:
            validate_request_id(request_id)
        except CliError:
            raise invalid from None
        if status and request_id.lower() != ctx.positionals[0].lower():
            raise invalid
        value["request"] = {"id": request_id, "status": meta["status"]}
        if not status:
            return CommandOutput(value, (f"Run `falcon-axi malquery status {request_id}` for status and results",))
    records = body.get("resources", [] if status else None)
    if not isinstance(records, list) or any(not isinstance(row, Mapping) for row in records):
        raise invalid
    rows = [
        {field: row.get(field, "unknown") for field in ("sha256", "family", "filetype", "filesize")}
        for row in records[: ctx.limit]
    ]
    known_total = total(answer)
    value["count"] = raw(
        f"{len(rows)} of {known_total} total" if known_total is not None else f"{len(rows)} shown; total unknown"
    )
    value["samples"] = (
        rows
        if rows
        else raw(
            "0 samples returned; the request may still be running, no patterns matched, or Falcon MalQuery licensing is absent"
            if status
            else "0 samples matched; no data or missing Falcon MalQuery licensing can cause an empty result"
        )
    )
    if (
        len(records) > ctx.limit
        or (known_total is not None and known_total > len(rows))
        or (known_total is None and len(records) == ctx.limit)
    ):
        value["partial"] = True
        help.append("Results reached the requested limit; narrow the patterns to avoid an incomplete result")
    if rows:
        help.append("Run `falcon-axi malquery show <sha256>` for indexed file metadata")
    if status:
        help.append(f"Run `falcon-axi malquery status {request_id} --limit {ctx.limit}` to read the request again")
    return CommandOutput(value, tuple(help))


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
    CommandSpec(
        name="malquery search",
        handler=_search,
        operations=("PostMalQueryExactSearchV1", "PostMalQueryFuzzySearchV1"),
        summary="  malquery search           bounded exact or fuzzy literal-pattern search (N4)",
        flags=("string", "hex", "fuzzy", "limit"),
        value_flags=("string", "hex", "limit"),
        limit_ceiling=(100, "MalQuery CLI policy (not a published API maximum)"),
        help="\n".join(
            [
                "falcon-axi malquery search --string <ASCII> | --hex <bytes> [--fuzzy] [--limit N]",
                "",
                "At least one pattern is required; combine --string and --hex to search for both.",
                "--string: 1-4096 printable ASCII characters with nonblank content (API type ascii).",
                "--hex: 1-4096 literal hex byte pairs, optional spaces; no wildcards or YARA.",
                "--fuzzy: synchronous metadata rows, with possible false positives; default exact returns a request id.",
                "--limit: maximum matches, default 20, CLI cap 100 (not a published API maximum).",
                "No pagination, automatic polling, or replay; status uses `malquery status <id>`.",
                "",
                "Examples:",
                "  falcon-axi malquery search --string SYNTHETIC-PATTERN --limit 20",
                "  falcon-axi malquery search --hex '4d 5a' --fuzzy --limit 10",
                "",
                "Requires MalQuery:write and Falcon MalQuery under captain exception N4.",
                "FALCON_AXI_READ_ONLY refuses searches. Hunt and all sample downloads remain excluded.",
            ]
        ),
    ),
    CommandSpec(
        name="malquery status",
        handler=_search,
        operations=("GetMalQueryRequestV1",),
        summary="  malquery status <id>      exact-search request status and bounded metadata results",
        positional=("request id", "Run `falcon-axi malquery status <id>` for exact-search status"),
        flags=("limit",),
        value_flags=("limit",),
        limit_ceiling=(100, "MalQuery CLI policy (not a published API maximum)"),
        help="\n".join(
            [
                "falcon-axi malquery status <id> [--limit N]",
                "",
                "id: UUID returned by exact search; reads once, with no automatic polling.",
                "--limit: maximum displayed rows, default 20, CLI cap 100; no upstream pagination parameter.",
                "Renders request status and sha256, family, filetype, filesize; a capped result is marked partial.",
                "",
                "Examples:",
                "  falcon-axi malquery status 00000000-0000-4000-8000-000000000001",
                "  falcon-axi malquery status 00000000-0000-4000-8000-000000000001 --limit 100",
                "",
                "Read-only; requires MalQuery:read and Falcon MalQuery. No hunt or download is started.",
            ]
        ),
    ),
)
