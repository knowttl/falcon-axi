"""Discover inventory reads, distinct from the Falcon sensor-host collection."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, decode_offset, encode_cursor
from falcon_axi.domain import (
    DEFAULT_LIMIT,
    CommandOutput,
    after_token,
    rate_limit_note,
    resources,
    text,
    total,
)
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
        raise translate_falcon_error(response, operation, ctx.spec.name.split()[0])
    return response


def _list(ctx: Invocation) -> CommandOutput:
    noun = ctx.spec.name.split()[0]
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    token_model = noun != "login"
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
        model="token" if token_model else "offset",
    )
    query: dict[str, Any] = {"limit": ctx.limit}
    cursor = ctx.text("cursor")
    offset = 0
    if token_model:
        if cursor:
            query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    else:
        offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
        query["offset"] = offset
    if filter:
        query["filter"] = filter
    response = _request(ctx, operation, query)
    entries = resources(response)
    count = total(response)
    position: str | int | None = after_token(response) if token_model else None
    if not token_model:
        ids = [entry for entry in entries if isinstance(entry, str)]
        next_offset = offset + len(ids)
        if ids and (next_offset < count if count is not None else len(ids) >= ctx.limit):
            position = next_offset
        if ids:
            hydrated = _request(ctx, "get_logins", {"ids": tuple(ids)})
            by_id = {entry.get("id"): entry for entry in resources(hydrated) if isinstance(entry, Mapping)}
            entries = [by_id[id] for id in ids if id in by_id]
        else:
            entries = []
    columns = {
        "asset": ("id", "hostname", "entity_type", "platform_name"),
        "application": ("id", "name", "version", "vendor"),
        "login": ("id", "username", "hostname", "login_timestamp"),
    }[noun]
    rows = [
        {column: text(entry.get(column)) or "unknown" for column in columns} for entry in entries if isinstance(entry, Mapping)
    ]
    key = f"{noun}s"
    help = ["Run `falcon-axi asset show <id>` for asset details"] if noun == "asset" else []
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    if position is not None:
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value[key] = rows if rows else raw(f"0 {key} returned for this Discover query")
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def _show_asset(ctx: Invocation) -> CommandOutput:
    response = _request(ctx, "get_hosts", {"ids": (ctx.positionals[0],)})
    assets = [entry for entry in resources(response) if isinstance(entry, Mapping)]
    if not assets:
        raise CliError(
            "NOT_FOUND",
            "no asset matched that identifier",
            ["Run `falcon-axi asset list` to see current Discover asset identifiers"],
        )
    asset = assets[0]
    columns = (
        "id",
        "hostname",
        "entity_type",
        "platform_name",
        "os_version",
        "aid",
        "criticality",
        "current_local_ip",
        "external_ip",
        "current_mac_address",
        "first_seen_timestamp",
        "last_seen_timestamp",
    )
    return CommandOutput(value={"asset": {key: text(asset.get(key)) or "unknown" for key in columns}}, help=())


COMMAND_SPECS = (
    CommandSpec(
        name="asset list",
        help="\n".join(
            [
                "falcon-axi asset list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Discover managed and unmanaged assets, distinct from Falcon sensor hosts.",
                "--filter     raw FQL, including entity_type, hostname, platform_name, and criticality",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 1000)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi asset list --filter \"entity_type:'managed'\"",
                "  falcon-axi asset list --filter \"entity_type:'unmanaged'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  asset list                list Discover managed and unmanaged assets",
        handler=_list,
        operations=("combined_hosts",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(1000, "Discover combined hosts"),
    ),
    CommandSpec(
        name="asset show",
        help="\n".join(
            [
                "falcon-axi asset show <id>",
                "",
                "Shows one Discover asset's platform, sensor association, network addresses, and observation times.",
                "Use the Discover id from asset list, which is distinct from a Falcon device id.",
                "Example: falcon-axi asset show synthetic-asset-01",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  asset show <id>           details for one Discover asset",
        handler=_show_asset,
        operations=("get_hosts",),
        positional=("asset identifier", "Run `falcon-axi asset list` to see current Discover asset identifiers"),
    ),
    CommandSpec(
        name="application list",
        help="\n".join(
            [
                "falcon-axi application list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter     raw FQL on Discover application fields such as name, vendor, and host.hostname",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 1000)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi application list --filter \"name:'Chrome'\"",
                "  falcon-axi application list --filter \"vendor:'Microsoft Corporation'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  application list          list Discover applications",
        handler=_list,
        operations=("combined_applications",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(1000, "Discover combined applications"),
    ),
    CommandSpec(
        name="login list",
        help="\n".join(
            [
                "falcon-axi login list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Discover-observed logins across assets; host logins reads one sensor host's timeline.",
                "--filter     raw FQL, including username, hostname, login_status, and login_timestamp",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 100)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi login list --filter \"login_type:'Interactive'\"",
                "  falcon-axi login list --filter \"login_status:'Failed'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  login list                list Discover-observed logins across assets",
        handler=_list,
        operations=("query_logins", "get_logins"),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "Discover logins query"),
    ),
)
