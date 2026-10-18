"""Custom IOC reads, matching falcon_mcp/modules/ioc.py search_iocs request shapes."""

import json
import shlex
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, after_token, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, QueryValue, RequestArgs


def _request(ctx: Invocation, operation: OperationId, query: dict[str, QueryValue]) -> FalconResponse:
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status == 404:
        raise CliError("NOT_FOUND", "no IOC record matched that identifier", ["Run `falcon-axi ioc list`"])
    if response.status != 200:
        raise translate_falcon_error(response, operation, "IOCs")
    return response


def _list(ctx: Invocation) -> CommandOutput:
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation="indicator_search_v1",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
        model="token",
    )
    query: dict[str, QueryValue] = {"limit": ctx.limit}
    if filter:
        query["filter"] = filter
    if cursor := ctx.text("cursor"):
        query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    response = _request(ctx, "indicator_search_v1", query)
    ids = [id for id in resources(response) if isinstance(id, str)]
    records = resources(_request(ctx, "indicator_get_v1", {"ids": tuple(ids)})) if ids else []
    by_id = {entry.get("id"): entry for entry in records if isinstance(entry, Mapping)}
    rows = [{key: by_id[id].get(key) for key in ("id", "type", "value", "action")} for id in ids if id in by_id]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    value["iocs"] = rows if ids else raw("0 custom IOCs matching this query")
    help = ["Run `falcon-axi ioc show <id>` for the indicator record"]
    if after := after_token(response):
        cursor = encode_cursor(after, context, ctx.credential.client_secret)
        value["continuation_cursor"] = cursor
        help.append(f"Run `{ctx.suggestion} --cursor {cursor}` for the next page")
    if note := rate_limit_note(ctx.session):
        value["rate_limit"] = raw(note)
    return CommandOutput(value, tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    id = ctx.positionals[0]
    records = resources(_request(ctx, "indicator_get_v1", {"ids": (id,)}))
    record = next((entry for entry in records if isinstance(entry, Mapping) and entry.get("id") == id), None)
    if record is None:
        raise CliError("NOT_FOUND", "no custom IOC matched that identifier", ["Run `falcon-axi ioc list`"])
    keys = (
        "id",
        "type",
        "value",
        "action",
        "severity",
        "description",
        "source",
        "platforms",
        "host_groups",
        "tags",
        "applied_globally",
        "expiration",
        "expired",
        "created_on",
        "modified_on",
        "metadata",
    )
    return CommandOutput({"ioc": {key: record[key] for key in keys if key in record}}, ())


def validate_observation(value: str, processes: bool, host: str | None) -> tuple[str, str]:
    type, separator, indicator = value.partition(":")
    if not separator or type not in ("domain", "ipv4", "ipv6", "md5", "sha256") or not indicator.strip():
        raise CliError("VALIDATION_ERROR", "indicator must be type:value (domain, ipv4, ipv6, md5, sha256)")
    if processes and (host is None or not host.strip()):
        raise CliError(
            "VALIDATION_ERROR",
            "ioc processes requires --host <device_id>",
            ["Run `falcon-axi ioc hosts <type:value>` to find host identifiers"],
        )
    return type, indicator


def _ran_on(ctx: Invocation) -> CommandOutput:
    processes = ctx.spec.name == "ioc processes"
    host = ctx.text("host")
    type, indicator = validate_observation(ctx.positionals[0], processes, host)
    operation: OperationId = "ProcessesRanOn" if processes else "DevicesRanOn"
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=json.dumps([type, indicator, host]),
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    query: dict[str, QueryValue] = {"type": type, "value": indicator, "offset": offset, "limit": ctx.limit}
    if processes and host is not None:
        query["device_id"] = host
    response = _request(ctx, operation, query)
    ids = [id for id in resources(response) if isinstance(id, str)]
    count = total(response)
    name = "processes" if processes else "hosts"
    field = "process_id" if processes else "device_id"
    value: dict[str, Any] = {
        "count": raw(f"{len(ids)} of {count if count is not None else 'unknown'} total"),
        name: [{field: id} for id in ids] if ids else raw(f"0 {name} observed for this IOC"),
    }
    help = (
        []
        if processes
        else [
            "Run `falcon-axi host show <device_id>` for host details",
            f"Run `falcon-axi ioc processes {shlex.quote(ctx.positionals[0])} --host <device_id>` for process IDs",
        ]
    )
    if ids and (offset + len(ids) < count if count is not None else len(ids) >= ctx.limit):
        cursor = encode_cursor(offset + len(ids), context, ctx.credential.client_secret)
        value["continuation_cursor"] = cursor
        help.append(f"Run `{ctx.suggestion} --cursor {cursor}` for the next page")
    return CommandOutput(value, tuple(help))


_OBSERVATIONS: tuple[tuple[str, OperationId, tuple[str, ...]], ...] = (
    ("hosts", "DevicesRanOn", ("limit", "cursor")),
    ("processes", "ProcessesRanOn", ("host", "limit", "cursor")),
)

COMMAND_SPECS = (
    CommandSpec(
        name="ioc list",
        handler=_list,
        operations=("indicator_search_v1", "indicator_get_v1"),
        summary="  ioc list                  list custom indicators",
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(500, "IOC search"),
        help="\n".join(
            [
                "falcon-axi ioc list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter  FQL on type, value, action, source, severity_number, expired, created_on, modified_on",
                "--limit   rows per call (default 20, ceiling 500)",
                "--cursor  opaque continuation token",
                "",
                "Examples:",
                "  falcon-axi ioc list --filter \"type:'domain'+expired:false\"",
                "  falcon-axi ioc list --limit 100",
                "",
                "Read-only; requires IOC Management:read.",
            ]
        ),
    ),
    CommandSpec(
        name="ioc show",
        handler=_show,
        operations=("indicator_get_v1",),
        summary="  ioc show <id>             read one custom indicator",
        positional=("IOC identifier", "Run `falcon-axi ioc list` for identifiers"),
        help="falcon-axi ioc show <id>\n\nExample: falcon-axi ioc show <id>\n\nRead-only; requires IOC Management:read.",
    ),
    *(
        CommandSpec(
            name=f"ioc {verb}",
            handler=_ran_on,
            operations=(operation,),
            summary=f"  ioc {verb} <type:value>  list observed {verb} for a custom IOC",
            positional=("indicator type:value", "Example: domain:example.invalid"),
            flags=flags,
            value_flags=flags,
            limit_ceiling=(100, "IOC observation query"),
            help="\n".join(
                [
                    f"falcon-axi ioc {verb} <type:value>"
                    + (" --host <device_id>" if verb == "processes" else "")
                    + " [--limit N] [--cursor <token>]",
                    "",
                    "Types: domain, ipv4, ipv6, md5, sha256. IPv6 values retain their colons.",
                    "--limit   identifiers per call (default 20, ceiling 100)",
                    "--cursor  opaque continuation token",
                    *(("--host    required device ID; use ioc hosts to find it",) if verb == "processes" else ()),
                    "",
                    "Returns observed identifiers; no process details or actions are requested.",
                    f"Example: falcon-axi ioc {verb} domain:example.invalid"
                    + (" --host <device_id>" if verb == "processes" else ""),
                    "Read-only; requires IOCs (Indicators of Compromise):read.",
                ]
            ),
        )
        for verb, operation, flags in _OBSERVATIONS
    ),
)
