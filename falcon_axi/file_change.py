"""FileVantage change history, without captured file-content retrieval."""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, after_token, body_of, rate_limit_note, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.response_diagnostics import upstream_invalid
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, QueryValue, RequestArgs

_SORT = "action_timestamp|desc"
_COLUMNS = ("action_timestamp", "action_type", "entity_type", "entity_path", "host", "severity")
_PROCESS_FIELDS = (
    "process_id",
    "process_image_file_name",
    "command_line",
    "parent_process_image_file_name",
    "grandparent_process_image_file_name",
)
_EMPTY = "no file changes; this can mean no matching data or a tenant without Falcon FileVantage licensing"


def _request(ctx: Invocation, operation: OperationId, query: Mapping[str, QueryValue]) -> FalconResponse:
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
        raise translate_falcon_error(answer, operation, "file changes")
    return answer


def _resources(answer: FalconResponse) -> list[Any]:
    # The reference renders resources as arrays; SDK responses retain the Falcon envelope.
    listed = answer.body if isinstance(answer.body, list) else body_of(answer).get("resources")
    if not isinstance(listed, list) or body_of(answer).get("errors"):
        raise upstream_invalid("Falcon returned malformed file changes")
    return listed


def _hydrate(ctx: Invocation, ids: Sequence[str], *, allow_empty: bool = False) -> list[Mapping[str, Any]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    for start in range(0, len(ids), 500):
        answer = _request(ctx, "getChanges", {"ids": tuple(ids[start : start + 500])})
        for record in _resources(answer):
            if not isinstance(record, Mapping) or not isinstance(record.get("id"), str):
                raise upstream_invalid("Falcon returned a file change without an identifier")
            by_id[record["id"]] = record
    if allow_empty and not by_id:
        return []
    if any(id not in by_id for id in ids):
        raise upstream_invalid("Falcon omitted requested file change identifiers")
    return [by_id[id] for id in ids]


def _project(record: Mapping[str, Any]) -> dict[str, Any]:
    row = {field: record.get(field, "unknown") for field in _COLUMNS}
    host = record.get("host")
    # host.name is documented as a filter; do not spill the host object's tenant metadata.
    row["host"] = host.get("name", "unknown") if isinstance(host, Mapping) else "unknown"
    return row


def _list(ctx: Invocation) -> CommandOutput:
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter must not be empty")
    context = CursorContext(
        operation="highVolumeQueryChanges",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
        sort=_SORT,
        model="token",
    )
    cursor = ctx.text("cursor")
    query: dict[str, QueryValue] = {"limit": ctx.limit, "sort": _SORT}
    if cursor:
        query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    if filter is not None:
        query["filter"] = filter
    answer = _request(ctx, "highVolumeQueryChanges", query)
    ids = _resources(answer)
    if any(not isinstance(id, str) or not id for id in ids):
        raise upstream_invalid("Falcon returned invalid file change identifiers")
    records = _hydrate(ctx, ids)
    rows = [_project(record) for record in records]
    count = total(answer)
    value: dict[str, Any] = {
        "count": raw(f"{len(rows)} of {count} total" if count is not None else str(len(rows))),
        "file_changes": rows if rows else raw(_EMPTY),
    }
    help: list[str] = []
    if records:
        # Keep the requested compact columns while making every row addressable by show.
        value["change_ids"] = [record["id"] for record in records]
        help.append("Run `falcon-axi file-change show <id>` with a change_ids entry in row order")
    after = after_token(answer) if ids else None
    if after:
        token = encode_cursor(after, context, ctx.credential.client_secret)
        value["continuation_cursor"] = token
        help.append(f"Run `{ctx.suggestion} --cursor {token}` for the next page")
    note = rate_limit_note(ctx.session)
    if note:
        help.append(note)
    return CommandOutput(value, tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    records = _hydrate(ctx, [ctx.positionals[0]], allow_empty=True)
    if not records:
        raise CliError(
            "NOT_FOUND", "no file change matched that identifier", ["Run `falcon-axi file-change list` to find identifiers"]
        )
    record = records[0]
    value = {"id": record["id"], **_project(record)}
    value.update({field: record.get(field, "unknown") for field in _PROCESS_FIELDS})
    value["diff"] = record.get("diff", "unknown")
    return CommandOutput({"file_change": value}, ())


COMMAND_SPECS = (
    CommandSpec(
        name="file-change list",
        summary="  file-change list              list FileVantage change history",
        help="\n".join(
            [
                "falcon-axi file-change list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Read FileVantage change history, newest action_timestamp first.",
                "--filter   raw FQL; for example host.name:'SYNTHETIC-HOST' or action_timestamp:>'now-7d'",
                "--limit    rows per call (default 20, ceiling 5000); hydration uses batches of 500 ids",
                "--cursor   opaque after token bound to the query, sort, region, tenant and credential",
                "change_ids lists identifiers in the same order as the compact rows.",
                "Read-only; requires Falcon FileVantage:read and Falcon FileVantage licensing.",
                "Empty results can mean no matching changes or no FileVantage license.",
                "Captured file contents are excluded.",
                "",
                "Example: falcon-axi file-change list --filter \"host.name:'SYNTHETIC-HOST'\"",
            ]
        ),
        handler=_list,
        operations=("highVolumeQueryChanges", "getChanges"),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(5000, "FileVantage query"),
    ),
    CommandSpec(
        name="file-change show",
        summary="  file-change show <id>         inspect one FileVantage change",
        help="\n".join(
            [
                "falcon-axi file-change show <id>",
                "",
                "Show change metadata, process fields and the documented diff object.",
                "The id comes from change_ids in `falcon-axi file-change list`.",
                "Read-only; requires Falcon FileVantage:read and Falcon FileVantage licensing.",
                "Captured file contents are excluded; no content download is performed.",
                "",
                "Example: falcon-axi file-change show 00000000000000000000000000000001",
            ]
        ),
        handler=_show,
        operations=("getChanges",),
        positional=("file change identifier", "Run `falcon-axi file-change list` to find identifiers"),
    ),
)
