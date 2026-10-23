"""Existing sandbox report summaries, without sample submission or downloads."""

import re
import shlex
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, body_of, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import QueryValue, RequestArgs

_ENV_FIELDS = ("threat_score", "environment_description", "submit_name")
_DETAIL_FIELDS = (*_ENV_FIELDS, "file_type", "classification_tags", "submit_url", "sha256")
_USAGE = "Run `falcon-axi sandbox list --sha256 <64-hex-hash>` or `falcon-axi sandbox list --filter \"verdict:'malicious'\"`"


def sandbox_filter(sha256: str | None, filter: str | None) -> str:
    if (sha256 is None) == (filter is None):
        raise CliError("VALIDATION_ERROR", "supply exactly one of --sha256 or --filter", [_USAGE])
    if sha256 is not None:
        if re.fullmatch(r"[a-fA-F0-9]{64}", sha256) is None:
            raise CliError("VALIDATION_ERROR", "--sha256 requires exactly 64 hex characters", [_USAGE])
        return f"sandbox.sha256:'{sha256}'"
    assert filter is not None
    if not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value", [_USAGE])
    return filter


def _read(ctx: Invocation, operation: OperationId, query: Mapping[str, QueryValue]) -> list[Any]:
    answer = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if answer.status != 200:
        raise translate_falcon_error(answer, operation, "sandbox reports")
    body = body_of(answer)
    records = body.get("resources")
    if body.get("errors") or not isinstance(records, list):
        raise CliError("UPSTREAM_ERROR", "Falcon returned an invalid sandbox report response")
    return records


def _summaries(ctx: Invocation, ids: Sequence[str]) -> list[Mapping[str, Any]]:
    records = _read(ctx, "GetSummaryReports", {"ids": tuple(ids)})
    if any(not isinstance(record, Mapping) or not isinstance(record.get("id"), str) for record in records):
        raise CliError("UPSTREAM_ERROR", "Falcon returned an invalid sandbox report summary")
    by_id = {record["id"]: record for record in records}
    if any(id not in by_id for id in ids):
        raise CliError("UPSTREAM_ERROR", "Falcon omitted a requested sandbox report summary")
    return [by_id[id] for id in ids]


def _environments(record: Mapping[str, Any], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    environments = record.get("sandbox", [])
    if not isinstance(environments, list) or any(not isinstance(env, Mapping) for env in environments):
        raise CliError("UPSTREAM_ERROR", "Falcon returned invalid sandbox environments")
    return [{field: env.get(field, "unknown") for field in fields} for env in environments]


def _list(ctx: Invocation) -> CommandOutput:
    filter = sandbox_filter(ctx.text("sha256"), ctx.text("filter"))
    context = CursorContext(
        operation="QueryReports",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    answer = ctx.transport.request(
        "QueryReports",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"filter": filter, "limit": ctx.limit, "offset": str(offset)},
        ),
    )
    if answer.status != 200:
        raise translate_falcon_error(answer, "QueryReports", "sandbox reports")
    body = body_of(answer)
    ids = body.get("resources")
    if body.get("errors") or not isinstance(ids, list) or any(not isinstance(id, str) or not id for id in ids):
        raise CliError("UPSTREAM_ERROR", "Falcon returned invalid sandbox report identifiers")
    if not ids:
        return CommandOutput(
            {
                "sandbox_reports": raw(
                    "0 sandbox reports: not licensed or no data; reports exist only for files submitted to this tenant's "
                    "Falcon Intelligence (Sandbox)"
                )
            },
            (),
        )
    records = _summaries(ctx, ids)
    rows = []
    for record in records:
        for env in _environments(record, _ENV_FIELDS) or [dict.fromkeys(_ENV_FIELDS, "unknown")]:
            rows.append(
                {
                    "id": record["id"],
                    "verdict": record.get("verdict", "unknown"),
                    **env,
                    "created_timestamp": record.get("created_timestamp", "unknown"),
                }
            )
    count = total(answer)
    value: dict[str, Any] = {
        "count": raw(f"{len(ids)} of {count if count is not None else 'unknown'} total reports"),
        "sandbox_reports": rows,
    }
    help = ["Run `falcon-axi sandbox show <report-id>` for report details"]
    position = offset + len(ids)
    if (position < count) if count is not None else (len(ids) >= ctx.limit):
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        suggestion = ctx.suggestion
        if sha256 := ctx.text("sha256"):
            suggestion += f" --sha256 {shlex.quote(sha256)}"
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    return CommandOutput(value, tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    id = ctx.positionals[0]
    records = _read(ctx, "GetSummaryReports", {"ids": (id,)})
    if not records:
        raise CliError("NOT_FOUND", "no sandbox report matched that identifier", [_USAGE])
    record = next((row for row in records if isinstance(row, Mapping) and row.get("id") == id), None)
    if record is None:
        raise CliError("UPSTREAM_ERROR", "Falcon omitted the requested sandbox report summary")
    return CommandOutput(
        {
            "sandbox_report": {
                "id": id,
                "verdict": record.get("verdict", "unknown"),
                "created_timestamp": record.get("created_timestamp", "unknown"),
                "sandbox": _environments(record, _DETAIL_FIELDS) or raw("no sandbox environments recorded"),
            }
        },
        (),
    )


COMMAND_SPECS = (
    CommandSpec(
        name="sandbox list",
        handler=_list,
        operations=("QueryReports", "GetSummaryReports"),
        summary="  sandbox list             existing sandbox reports by hash or FQL",
        flags=("sha256", "filter", "limit", "cursor"),
        value_flags=("sha256", "filter", "limit", "cursor"),
        limit_ceiling=(5000, "sandbox report query"),
        help="\n".join(
            [
                "falcon-axi sandbox list (--sha256 <hash> | --filter <FQL>) [--limit <n>] [--cursor <token>]",
                "",
                "--sha256  exactly 64 hex characters; builds sandbox.sha256:'<hash>'",
                "--filter  FQL instead of a hash; exactly one selector is required",
                "--limit   reports per page (default 20, maximum 5000)",
                "--cursor  opaque continuation token for the same query",
                "One row per sandbox environment; count and pagination refer to reports.",
                "The hash filter field is partner-corroborated, not CrowdStrike-documented.",
                "",
                "Examples:",
                "  falcon-axi sandbox list --sha256 " + "0" * 64,
                "  falcon-axi sandbox list --filter \"verdict:'malicious'\"",
                "",
                "Read-only; requires Sandbox (Falcon Intelligence):read and Falcon Intelligence (Sandbox).",
                "Reads existing reports only; an empty result can mean not licensed or no data.",
            ]
        ),
    ),
    CommandSpec(
        name="sandbox show",
        handler=_show,
        operations=("GetSummaryReports",),
        summary="  sandbox show <report-id> existing report summary and environment details",
        positional=("report identifier", _USAGE),
        help="\n".join(
            [
                "falcon-axi sandbox show <report-id>",
                "",
                "Includes file_type, classification_tags, submit_url, and sha256 per environment.",
                "Omits tenant CID, user identity, and artifact download handles.",
                "",
                "Examples:",
                "  falcon-axi sandbox show synthetic-report-01",
                "  falcon-axi sandbox list --filter \"verdict:'malicious'\"",
                "",
                "Read-only; requires Sandbox (Falcon Intelligence):read and Falcon Intelligence (Sandbox).",
            ]
        ),
    ),
)
