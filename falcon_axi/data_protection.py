"""Data Protection query/hydrate reads shared by classifications and policies.

Request shapes match CrowdStrike/falcon-mcp ece8575, modules/data_security.py,
and falconpy's _endpoint/_data_protection_configuration.py.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.command import Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, RequestArgs


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
        raise translate_falcon_error(response, operation, "Data Protection")
    return response


def _hydrate(ctx: Invocation, operation: OperationId, ids: Sequence[str]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for start in range(0, len(ids), 100):
        response = _request(ctx, operation, {"ids": tuple(ids[start : start + 100])})
        for item in resources(response):
            if isinstance(item, Mapping) and (id := text(item.get("id"))):
                by_id[id] = dict(item)
    return [by_id[id] for id in ids if id in by_id]


def validate_sort(sort: str | None, policy: bool) -> None:
    """Reject unsupported sort fields before authentication or any dependency call."""
    allowed_sort = ("name", "created_at", "modified_at", "precedence") if policy else ("name", "created_at", "modified_at")
    valid_sorts = tuple(f"{field}.{direction}" for field in allowed_sort for direction in ("asc", "desc"))
    if sort is not None and sort not in valid_sorts:
        raise CliError(
            "VALIDATION_ERROR",
            "--sort must use a supported field and .asc or .desc",
            [f"valid sort fields: {', '.join(allowed_sort)}"],
        )


def list_entities(ctx: Invocation, noun: str, platform: str | None = None) -> CommandOutput:
    """Keep query order, counts, chunk limits and continuation behind one read interface."""
    query_op, get_op = ctx.spec.operations
    filter = ctx.text("filter")
    sort = ctx.text("sort")
    context = CursorContext(
        operation=query_op,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=json.dumps([filter, platform], separators=(",", ":")),
        sort=sort,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    if offset > 10000:
        raise CliError("PAGINATION_LIMIT", "Data Protection queries cannot continue beyond offset 10000")
    query: dict[str, Any] = {"offset": offset, "limit": ctx.limit}
    if filter:
        query["filter"] = filter
    if sort:
        query["sort"] = sort
    if platform:
        query["platform_name"] = platform
    response = _request(ctx, query_op, query)
    ids = [item for item in resources(response) if isinstance(item, str)]
    count = total(response)
    if not ids:
        empty = f"no more {noun}" if offset > 0 else f"0 {noun} matching this query"
        return CommandOutput(value={noun: raw(empty)}, help=())
    entities = _hydrate(ctx, get_op, ids)
    rows = []
    for entity in entities:
        row = {"id": entity["id"], "name": text(entity.get("name")) or "unknown"}
        if platform:
            row["is_enabled"] = entity.get("is_enabled", "unknown")
            row["precedence"] = entity.get("precedence", "unknown")
        else:
            properties = entity.get("classification_properties")
            row["protection_mode"] = (
                properties.get("protection_mode", "unknown") if isinstance(properties, Mapping) else "unknown"
            )
        rows.append(row)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total"), noun: rows}
    help = [f"Run `falcon-axi {ctx.spec.name.split()[0]} show <id>` for the full record"]
    next_offset = offset + len(ids)
    more = next_offset < count if count is not None else len(ids) == ctx.limit
    if more and next_offset <= 10000:
        token = encode_cursor(next_offset, context, ctx.credential.client_secret)
        value["continuation_cursor"] = token
        help.append(f"Run `{ctx.suggestion} --cursor {token}` for the next page")
    elif more:
        value.update(partial=True, stop_reason="pagination_limit")
        help.append("Narrow --filter to read beyond the Data Protection offset limit")
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def show_entity(ctx: Invocation, noun: str) -> CommandOutput:
    entities = _hydrate(ctx, ctx.spec.operations[0], ctx.positionals)
    if not entities:
        raise CliError(
            "NOT_FOUND",
            f"no {noun} matched that identifier",
            [f"Run `falcon-axi {ctx.spec.name.split()[0]} list --help` to find identifiers"],
        )
    return CommandOutput(value={noun: entities[0]}, help=())
