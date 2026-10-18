"""Container inventory paging with Falcon's bounded offset window."""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.command import Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, body_of, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import RequestArgs


def read_page(ctx: Invocation, key: str, columns: tuple[str, ...], sort: str) -> CommandOutput:
    """Read one combined inventory page, preserving reachable continuation and window headroom."""
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        query=filter,
        sort=sort,
        member_cid=ctx.session.member_cid,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    if offset >= 10000:
        raise CliError("PAGINATION_LIMIT", "Falcon's 10000-record inventory window is exhausted", ["Narrow --filter"])
    limit = min(ctx.limit, 10000 - offset)
    query: dict[str, str | int] = {"limit": limit, "offset": offset, "sort": sort}
    if filter:
        query["filter"] = filter
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, operation, key)
    records = body_of(response).get("resources")
    if not isinstance(records, list) or any(
        not isinstance(record, Mapping) or not record.get(columns[0]) for record in records
    ):
        raise CliError("UPSTREAM_ERROR", "Falcon returned an invalid inventory page")
    if not records:
        return CommandOutput(value={key: raw(f"no more {key}" if cursor else f"0 {key} matching the supplied query")}, help=())
    count = total(response)
    value: dict[str, Any] = {
        "count": raw(f"{len(records)} of {count if count is not None else 'unknown'} total"),
        key: [{name: record.get(name, "unknown") for name in columns} for record in records],
    }
    next_offset = offset + len(records)
    more = next_offset < count if count is not None else len(records) >= limit
    help = []
    if more and next_offset < 10000:
        continuation = encode_cursor(next_offset, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    elif more:
        value.update(partial=True, stop_reason="pagination_limit")
        help.append("Falcon's 10000-record inventory window is exhausted; narrow --filter")
    return CommandOutput(value=value, help=tuple(help))


def _request(ctx: Invocation, operation: OperationId, ids: Sequence[str]) -> list[Mapping[str, Any]]:
    # Quarantine's entity read accepts JSON; exclusion entity reads accept query ids.
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=None if operation == "GetQuarantineFiles" else {"ids": tuple(ids)},
            body={"ids": list(ids)} if operation == "GetQuarantineFiles" else None,
        ),
    )
    if response.status == 404:
        return []
    if response.status != 200:
        raise translate_falcon_error(response, operation, ctx.spec.name.split()[0])
    by_id = {entry["id"]: entry for entry in resources(response) if isinstance(entry, Mapping) and entry.get("id")}
    return [by_id[id] for id in ids if id in by_id]


def show_record(ctx: Invocation, operation: OperationId) -> CommandOutput:
    records = _request(ctx, operation, ctx.positionals)
    noun = ctx.spec.name.split()[0]
    if not records:
        raise CliError("NOT_FOUND", f"no {noun} matched that identifier")
    return CommandOutput(value={noun: dict(records[0])}, help=())


def list_records(
    ctx: Invocation, query_operation: OperationId, entity_operation: OperationId, fields: tuple[str, ...]
) -> CommandOutput:
    noun = ctx.spec.name.split()[0]
    subject = "exclusions" if noun == "exclusion" else "quarantined_files"
    filter = ctx.text("filter")
    context = CursorContext(
        operation=query_operation,
        client_id=ctx.credential.client_id,
        query=filter,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        model="offset",
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    query: dict[str, str | int] = {
        "limit": ctx.limit,
        "offset": str(offset) if query_operation == "QueryQuarantineFiles" else offset,
    }
    if filter:
        query["filter"] = filter
    response = ctx.transport.request(
        query_operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, query_operation, noun)
    ids = [id for id in resources(response) if isinstance(id, str)]
    if not ids:
        message = f"no more {subject}" if offset else f"0 {subject} matching the supplied filter" if filter else f"0 {subject}"
        return CommandOutput(value={subject: raw(message)}, help=())
    rows = [{field: entry.get(field, "unknown") for field in fields} for entry in _request(ctx, entity_operation, ids)]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    type_flag = f" --type {ctx.text('type')}" if noun == "exclusion" else ""
    help = [f"Run `falcon-axi {noun} show <id>{type_flag}` for the full record"]
    position = offset + len(ids)
    if (position < count) if count is not None else (len(ids) >= ctx.limit):
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value[subject] = rows
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))
