"""Recon's shared query/hydrate pagination and bounded detail rendering."""

from collections.abc import Callable, Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, truncate
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, QueryValue, RequestArgs

QUERY_CEILING = 500
OFFSET_WALL = 10_000


def read(ctx: Invocation, operation: OperationId, query: Mapping[str, QueryValue]) -> FalconResponse:
    session = ctx.session
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, operation, ctx.spec.name)
    return response


def records(response: FalconResponse) -> list[Any]:
    # The reference describes successful entity responses as arrays; SDK envelopes use resources.
    return response.body if isinstance(response.body, list) else resources(response)


def _hydrate(ctx: Invocation, ids: list[str]) -> list[Mapping[str, Any]]:
    try:
        response = read(ctx, ctx.spec.operations[-1], {"ids": tuple(ids)})
    except CliError as error:
        if error.code != "NOT_FOUND":
            raise
        return []
    by_id = {entry.get("id"): entry for entry in records(response) if isinstance(entry, Mapping)}
    return [by_id[id] for id in ids if id in by_id]


def list_records(ctx: Invocation, row: Callable[[Mapping[str, Any]], dict[str, Any]]) -> CommandOutput:
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        query=filter,
        member_cid=ctx.session.member_cid,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    if offset >= OFFSET_WALL:
        raise CliError("PAGINATION_LIMIT", "Recon queries stop at 10000 results", ["Narrow --filter and start again"])
    limit = min(ctx.limit, OFFSET_WALL - offset)
    query: dict[str, QueryValue] = {"limit": limit, "offset": offset}
    if filter:
        query["filter"] = filter
    response = read(ctx, operation, query)
    ids = [entry for entry in records(response) if isinstance(entry, str)]
    noun = ctx.spec.name.split()[0]
    if not ids:
        message = "no more records" if offset else "0 records matching the supplied filter" if filter else "0 records"
        return CommandOutput(value={"records": raw(message)}, help=())
    rows = [row(entry) for entry in _hydrate(ctx, ids)]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    help = [f"Run `falcon-axi {noun} show <id>` for the full record"]
    position = offset + len(ids)
    more = position < count if count is not None else len(ids) >= limit
    if more and position < OFFSET_WALL:
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    elif more:
        value["stop_reason"] = "pagination_limit"
        help.append("Recon queries stop at 10000 results; narrow --filter and start again")
    value["records"] = rows
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def show_record(ctx: Invocation) -> CommandOutput:
    entries = _hydrate(ctx, [ctx.positionals[0]])
    if not entries:
        noun = ctx.spec.name.split()[0]
        raise CliError("NOT_FOUND", "no record matched that identifier", [f"Run `falcon-axi {noun} list` for identifiers"])
    shortened = False

    def preview(value: Any) -> Any:
        nonlocal shortened
        if isinstance(value, str):
            result = truncate(value)
            shortened |= result.truncated
            return result.text
        if isinstance(value, Mapping):
            return {key: preview(entry) for key, entry in value.items()}
        if isinstance(value, list):
            return [preview(entry) for entry in value]
        return value

    detail = entries[0] if ctx.flags.get("full") else preview(entries[0])
    help = (f"Run `{ctx.suggestion} --full` for untruncated content",) if shortened else ()
    return CommandOutput(value={"record": detail}, help=help)


def commands(
    noun: str,
    description: str,
    operations: tuple[OperationId, OperationId],
    row: Callable[[Mapping[str, Any]], dict[str, Any]],
    example_filter: str,
) -> tuple[CommandSpec, CommandSpec]:
    return (
        CommandSpec(
            name=f"{noun} list",
            help="\n".join(
                [
                    f"falcon-axi {noun} list [--filter <FQL>] [--limit N] [--cursor <token>]",
                    "",
                    description,
                    "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                    f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                    "--cursor     opaque continuation token; queries stop at 10000 results",
                    "Requires Monitoring rules (Falcon Intelligence Recon):read. Read-only.",
                    "Examples:",
                    f'  falcon-axi {noun} list --filter "{example_filter}"',
                    f"  falcon-axi {noun} list --limit 100",
                ]
            ),
            summary=f"  {noun + ' list':<30}{description}",
            handler=lambda ctx: list_records(ctx, row),
            operations=operations,
            flags=("filter", "limit", "cursor"),
            value_flags=("filter", "limit", "cursor"),
            limit_ceiling=(QUERY_CEILING, "Recon query"),
        ),
        CommandSpec(
            name=f"{noun} show",
            help="\n".join(
                [
                    f"falcon-axi {noun} show <id> [--full]",
                    "",
                    "Shows the complete record, with strings previewed at 800 characters.",
                    "--full       print untruncated content",
                    "Requires Monitoring rules (Falcon Intelligence Recon):read. Read-only.",
                    f"Example: falcon-axi {noun} show <id> --full",
                ]
            ),
            summary=f"  {noun + ' show <id>':<30}full record detail",
            handler=show_record,
            operations=(operations[1],),
            flags=("full",),
            positional=("record identifier", f"Run `falcon-axi {noun} list` for identifiers"),
        ),
    )
