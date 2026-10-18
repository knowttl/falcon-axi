"""IoT inventory reads, corroborated by falconpy _discover and PSFalcon discover.ps1."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, after_token, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs


def _iot_list(ctx: Invocation) -> CommandOutput:
    context = CursorContext(
        operation="query_iot_hostsV2",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=ctx.text("filter"),
        model="token",
    )
    query: dict[str, Any] = {"limit": ctx.limit}
    if ctx.text("filter"):
        query["filter"] = ctx.text("filter")
    cursor = ctx.text("cursor")
    if cursor:
        query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    args = RequestArgs(
        base_url=ctx.session.base_url,
        token=ctx.session.token,
        allow_unknown_origin=ctx.session.allow_unknown_origin,
        query=query,
    )
    response = ctx.transport.request("query_iot_hostsV2", args)
    if response.status != 200:
        raise translate_falcon_error(response, "query_iot_hostsV2", "IoT assets")
    ids = [entry for entry in resources(response) if isinstance(entry, str)]
    if not ids:
        return CommandOutput({"iot": raw("no more IoT assets" if cursor else "0 IoT assets matching this query")}, ())
    details = ctx.transport.request(
        "get_iot_hosts",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": tuple(ids)},
        ),
    )
    if details.status not in (200, 404):
        raise translate_falcon_error(details, "get_iot_hosts", "IoT assets")
    by_id = {entry["id"]: entry for entry in resources(details) if isinstance(entry, Mapping) and entry.get("id")}
    rows = [
        {
            "id": id,
            "hostname": by_id[id].get("hostname", "unknown"),
            "device_type": by_id[id].get("device_type", "unknown"),
            "device_family": by_id[id].get("device_family", "unknown"),
        }
        for id in ids
        if id in by_id
    ]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total"), "iot": rows}
    help = []
    after = after_token(response)
    if after:
        continuation = encode_cursor(after, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    return CommandOutput(value, tuple(help))


COMMAND_SPECS = (
    CommandSpec(
        name="iot list",
        handler=_iot_list,
        operations=("query_iot_hostsV2", "get_iot_hosts"),
        summary="  iot list                  list Discover IoT assets",
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "Discover IoT query"),
        help="\n".join(
            [
                "falcon-axi iot list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter  raw FQL, including device_family, device_class, and device_type",
                "--limit   rows in this call (default 20, ceiling 100)",
                "--cursor  opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi iot list",
                "  falcon-axi iot list --limit 50",
                "",
                "Read-only. Requires Falcon Discover IoT:read (license-gated).",
            ]
        ),
    ),
)
