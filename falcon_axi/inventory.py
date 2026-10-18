"""Read configuration inventories with query order and cursor context preserved."""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.command import Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import RequestArgs


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
