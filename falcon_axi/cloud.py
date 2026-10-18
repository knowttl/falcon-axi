"""Cloud read commands: ordered hydration and cursor-bound offset/token pagination."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_cursor, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, body_of, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, RequestArgs


@dataclass(frozen=True)
class CloudDomain:
    noun: str
    plural: str
    description: str
    query: OperationId
    entity: OperationId | None
    scope: str
    columns: tuple[str, ...]
    detail: tuple[str, ...] = ()
    model: Literal["offset", "token"] = "offset"
    filter_example: str = "cloud_provider:'aws'"
    note: str = ""


def _request(ctx: Invocation, operation: OperationId, query: Mapping[str, Any]) -> FalconResponse:
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
        raise translate_falcon_error(response, operation, ctx.spec.name.split()[0])
    return response


def _hydrate(ctx: Invocation, domain: CloudDomain, ids: Sequence[str]) -> list[Mapping[str, Any]]:
    assert domain.entity is not None
    by_id: dict[str, Mapping[str, Any]] = {}
    # Both official GET entity reads and falcon-mcp's cloud helpers use batches of 100.
    for start in range(0, len(ids), 100):
        response = _request(ctx, domain.entity, {"ids": tuple(ids[start : start + 100])})
        for entry in resources(response):
            if isinstance(entry, Mapping) and isinstance(entry.get("id"), str):
                by_id[entry["id"]] = entry
    return [by_id[id] for id in ids if id in by_id]


def _project(record: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path in fields:
        value: Any = record
        for part in path.split("."):
            value = value.get(part) if isinstance(value, Mapping) else None
        result[path.replace(".", "_")] = value if isinstance(value, (str, int, float, bool)) else "unknown"
    return result


def _list(ctx: Invocation, domain: CloudDomain) -> CommandOutput:
    filter = ctx.text("filter")
    sort = ctx.text("sort")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter must not be empty")
    if sort is not None and not sort.strip():
        raise CliError("VALIDATION_ERROR", "--sort must not be empty")
    context = CursorContext(
        operation=domain.query,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
        sort=sort,
        model=domain.model,
    )
    cursor = ctx.text("cursor")
    position = decode_cursor(cursor, context, ctx.credential.client_secret) if cursor else None
    query: dict[str, Any] = {"limit": ctx.limit}
    if domain.model == "offset":
        query["offset"] = position or 0
    elif position is not None:
        query["after"] = position
    if filter is not None:
        query["filter"] = filter
    if sort is not None:
        query["sort"] = sort
    response = _request(ctx, domain.query, query)
    listed = resources(response)
    count = total(response)
    if domain.entity:
        records = _hydrate(ctx, domain, [id for id in listed if isinstance(id, str)])
    else:
        records = [entry for entry in listed if isinstance(entry, Mapping)]
    rows = [_project(record, domain.columns) for record in records]
    value: dict[str, Any] = {
        "count": raw(f"{len(rows)} of {count} total" if count is not None else str(len(rows))),
        domain.plural: rows
        if rows
        else raw(f"0 {domain.plural} matching the supplied filter" if filter else f"0 {domain.plural} in this tenant"),
    }
    next_position: int | str | None = None
    if listed:
        if domain.model == "token":
            meta = body_of(response).get("meta")
            next_token = meta.get("next") if isinstance(meta, Mapping) else None
            if isinstance(next_token, str) and next_token:
                next_position = next_token
        else:
            offset = int(query["offset"]) + len(listed)
            more = offset < count if count is not None else len(listed) == ctx.limit
            if more:
                next_position = offset
    help: list[str] = []
    if domain.entity:
        help.append(f"Run `falcon-axi {domain.noun} show <id>` for resource detail")
    if next_position is not None:
        token = encode_cursor(next_position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = token
        help.append(f"Run `{ctx.suggestion} --cursor {token}` for the next page")
    if domain.note:
        help.append(domain.note)
    note = rate_limit_note(ctx.session)
    if note:
        help.append(note)
    return CommandOutput(value=value, help=tuple(help))


def _show(ctx: Invocation, domain: CloudDomain) -> CommandOutput:
    requested = ctx.positionals[0]
    records = _hydrate(ctx, domain, [requested])
    if not records:
        raise CliError("NOT_FOUND", f"no {domain.noun} matched that identifier", [f"Run `falcon-axi {domain.noun} list`"])
    return CommandOutput(value={domain.noun: _project(records[0], (*domain.columns, *domain.detail))}, help=())


def commands(domain: CloudDomain) -> tuple[CommandSpec, ...]:
    """Declare a cloud inventory's supported reads and their shared paging contract."""
    list_spec = CommandSpec(
        name=f"{domain.noun} list",
        summary=f"  {domain.noun} list              {domain.description}",
        help="\n".join(
            [
                f"falcon-axi {domain.noun} list [--filter <FQL>] [--sort <field.direction>] [--limit N] [--cursor <token>]",
                "",
                f"{domain.description}.",
                "--filter   raw FQL; + is AND, `,` is OR, values are single-quoted",
                "--sort     upstream sort expression, for example cloud_provider.asc",
                f"--limit    rows in this call (default {DEFAULT_LIMIT}, ceiling 1000)",
                "--cursor   opaque continuation token bound to the filter, sort, region and credential",
                "",
                f"Read-only; requires {domain.scope}.",
                domain.note,
                "Examples:",
                f'  falcon-axi {domain.noun} list --filter "{domain.filter_example}"',
                f"  falcon-axi {domain.noun} list --limit 100",
            ]
        ).rstrip(),
        handler=lambda ctx: _list(ctx, domain),
        operations=(domain.query, domain.entity) if domain.entity else (domain.query,),
        flags=("filter", "sort", "limit", "cursor"),
        value_flags=("filter", "sort", "limit", "cursor"),
        limit_ceiling=(1000, "Cloud Security query"),
    )
    if domain.entity is None:
        return (list_spec,)
    return (
        list_spec,
        CommandSpec(
            name=f"{domain.noun} show",
            summary=f"  {domain.noun} show <id>         inspect one {domain.noun}",
            help="\n".join(
                [
                    f"falcon-axi {domain.noun} show <id>",
                    "",
                    f"The id is printed by `falcon-axi {domain.noun} list`.",
                    "Shows resource identity and security context without raw configuration blobs.",
                    f"Read-only; requires {domain.scope}.",
                    "",
                    f"Example: falcon-axi {domain.noun} show synthetic-{domain.noun}-01",
                ]
            ),
            handler=lambda ctx: _show(ctx, domain),
            operations=(domain.entity,),
            positional=(f"{domain.noun} identifier", f"Run `falcon-axi {domain.noun} list` to find identifiers"),
        ),
    )
