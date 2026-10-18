"""Read-only Falcon Intelligence indicators with marker-based continuation."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs

SORT = "_marker.asc"
QUERY_CEILING = 10000


def _list(ctx: Invocation) -> CommandOutput:
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation="QueryIntelIndicatorEntities",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        query=filter,
        sort=SORT,
        member_cid=ctx.session.member_cid,
        model="marker",
    )
    cursor = ctx.text("cursor")
    marker = None if cursor is None else decode_after(cursor, context, ctx.credential.client_secret)
    effective_filter = filter
    if marker is not None:
        # The full marker includes a unique suffix. Never round it to its timestamp.
        escaped = marker.replace("\\", "\\\\").replace("'", "\\'")
        term = f"_marker:>'{escaped}'"
        effective_filter = f"({filter})+{term}" if filter else term
    query: dict[str, str | int] = {"limit": ctx.limit, "sort": SORT}
    if effective_filter:
        query["filter"] = effective_filter
    response = ctx.transport.request(
        "QueryIntelIndicatorEntities",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "QueryIntelIndicatorEntities", "intelligence indicators")
    records = resources(response)
    if not records:
        return CommandOutput(
            value={"indicators": raw("no more indicators" if cursor else "0 indicators matching the supplied query")},
            help=(),
        )
    if any(not isinstance(record, Mapping) or not text(record.get("id")) for record in records):
        raise CliError("UPSTREAM_ERROR", "Falcon returned an indicator without an identifier")
    rows = [
        {name: record.get(name, "unknown") for name in ("id", "indicator", "type", "malicious_confidence")}
        for record in records
    ]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    help = ["Run `falcon-axi indicator show <id>` for the full indicator record"]
    more = len(records) >= ctx.limit if count is None else len(records) < count
    if more:
        next_marker = text(records[-1].get("_marker"))
        if next_marker is None or (marker is not None and next_marker <= marker):
            raise CliError("UPSTREAM_ERROR", "Falcon returned no advancing indicator marker")
        continuation = encode_cursor(next_marker, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value["indicators"] = rows
    return CommandOutput(value=value, help=tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    id = ctx.positionals[0]
    response = ctx.transport.request(
        "GetIntelIndicatorEntities",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            body={"ids": [id]},
        ),
    )
    if response.status == 404 or (response.status == 200 and not resources(response)):
        raise CliError("NOT_FOUND", "no intelligence indicator matched that identifier")
    if response.status != 200:
        raise translate_falcon_error(response, "GetIntelIndicatorEntities", "intelligence indicators")
    matched = [record for record in resources(response) if isinstance(record, Mapping) and record.get("id") == id]
    if not matched:
        raise CliError("UPSTREAM_ERROR", "Falcon returned an indicator without the requested identifier")
    detail = {key: value for key, value in matched[0].items() if key != "_marker"}
    return CommandOutput(value={"indicator": detail}, help=())


COMMAND_SPECS = (
    CommandSpec(
        name="indicator list",
        help="\n".join(
            [
                "falcon-axi indicator list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Falcon Intelligence indicators, distinct from tenant custom IOCs.",
                "--filter     raw FQL, for example type:'domain' or malicious_confidence:'high'",
                f"--limit      rows per call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token; keep the same filter and credential",
                "",
                "Results use fixed marker order. Each page total describes the remaining query,",
                "not a stable snapshot. Pagination uses the complete last marker internally.",
                "Examples:",
                "  falcon-axi indicator list --filter \"type:'domain'\"",
                "  falcon-axi indicator list --limit 100",
                "",
                "Read-only; requires Indicators (Falcon Intelligence):read and the corresponding license.",
            ]
        ),
        summary="  indicator list            list Falcon Intelligence indicators",
        handler=_list,
        operations=("QueryIntelIndicatorEntities",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(QUERY_CEILING, "Intel indicators query"),
    ),
    CommandSpec(
        name="indicator show",
        help="\n".join(
            [
                "falcon-axi indicator show <id>",
                "",
                "Reads the full Falcon Intelligence indicator record, including labels and relations.",
                "Use the identifier printed by indicator list, rather than the indicator value.",
                "Example: falcon-axi indicator show <id>",
                "",
                "Read-only; requires Indicators (Falcon Intelligence):read and the corresponding license.",
            ]
        ),
        summary="  indicator show <id>       detail for one intelligence indicator",
        handler=_show,
        operations=("GetIntelIndicatorEntities",),
        positional=("indicator identifier", "Run `falcon-axi indicator list` to see current indicator identifiers"),
    ),
)
