"""Host-group reads matching falcon_mcp/modules/host_groups.py search tools."""

import json
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import QueryValue, RequestArgs


def _list(ctx: Invocation) -> CommandOutput:
    members = ctx.spec.name == "host-group members"
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=json.dumps([ctx.positionals, filter]),
        sort=None if members else "name.asc",
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    query: dict[str, QueryValue] = {"limit": ctx.limit, "offset": offset}
    if members:
        query["id"] = ctx.positionals[0]
    else:
        query["sort"] = "name.asc"
    if filter:
        query["filter"] = filter
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            query=query,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
        ),
    )
    if response.status == 404:
        raise CliError("NOT_FOUND", "no host group matched that identifier", ["Run `falcon-axi host-group list`"])
    if response.status != 200:
        raise translate_falcon_error(
            response,
            operation,
            "host-group members" if members else "host groups",
            filter_help=("host-group members", "platform_name:'Windows'") if members else None,
        )
    records = resources(response)
    keys = ("device_id", "hostname", "platform_name", "status") if members else ("id", "name", "group_type", "description")
    rows = [{key: record.get(key) for key in keys} for record in records if isinstance(record, Mapping)]
    count = total(response)
    name = "members" if members else "host_groups"
    empty = "0 members in this host group" if members else "0 host groups matching this query"
    value: dict[str, Any] = {
        "count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total"),
        name: rows if rows else raw(empty),
    }
    help = (
        ["Run `falcon-axi host show <device_id>` for host details"]
        if members
        else ["Run `falcon-axi host-group members <id>` for the hosts in a group"]
    )
    if records and (offset + len(records) < count if count is not None else len(records) >= ctx.limit):
        cursor = encode_cursor(offset + len(records), context, ctx.credential.client_secret)
        value["continuation_cursor"] = cursor
        help.append(f"Run `{ctx.suggestion} --cursor {cursor}` for the next page")
    if note := rate_limit_note(ctx.session):
        value["rate_limit"] = raw(note)
    return CommandOutput(value, tuple(help))


_READS: tuple[tuple[str, OperationId], ...] = (
    ("list", "queryCombinedHostGroups"),
    ("members", "queryCombinedGroupMembers"),
)

COMMAND_SPECS = tuple(
    CommandSpec(
        name=f"host-group {verb}",
        handler=_list,
        operations=(operation,),
        summary=f"  host-group {verb}" + (" <id>" if verb == "members" else "") + f"     list host-group {verb}",
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(5000, "Host Groups query"),
        positional=("host-group identifier", "Run `falcon-axi host-group list` for identifiers") if verb == "members" else None,
        help="\n".join(
            [
                f"falcon-axi host-group {verb}"
                + (" <id>" if verb == "members" else "")
                + " [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter  FQL on "
                + (
                    "host attributes: hostname, platform_name, status"
                    if verb == "members"
                    else "group attributes: name, group_type, created_timestamp, modified_timestamp"
                ),
                "--limit   rows per call (default 20, ceiling 5000)",
                "--cursor  opaque continuation token",
                "",
                "Examples:",
                f"  falcon-axi host-group {verb}" + (" <id>" if verb == "members" else "") + " --limit 100",
                f"  falcon-axi host-group {verb}"
                + (" <id> --filter \"platform_name:'Windows'\"" if verb == "members" else " --filter \"group_type:'dynamic'\""),
                "",
                "Read-only; requires Host Groups:read. No membership changes are performed.",
            ]
        ),
    )
    for verb, operation in _READS
)
