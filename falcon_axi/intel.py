"""Read-only Falcon Intelligence actors, reports, and JSON ATT&CK mappings."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, truncate
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, RequestArgs

QUERY_CEILING = 5000


def _request(ctx: Invocation, operation: OperationId, query: Mapping[str, Any]) -> FalconResponse:
    return ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )


def _list(ctx: Invocation) -> CommandOutput:
    noun = ctx.spec.name.split()[0]
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        query=filter,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        model="offset",
    )
    cursor = ctx.text("cursor")
    offset = 0 if cursor is None else decode_offset(cursor, context, ctx.credential.client_secret)
    query: dict[str, Any] = {"limit": ctx.limit, "offset": offset}
    if filter:
        query["filter"] = filter
    response = _request(ctx, operation, query)
    if response.status != 200:
        raise translate_falcon_error(response, operation, f"{noun}s")
    entries = resources(response)
    if not all(isinstance(entry, Mapping) and "id" in entry for entry in entries):
        raise CliError("UPSTREAM_ERROR", f"Falcon returned an invalid {noun} resource")
    if not entries:
        message = f"no more {noun}s" if offset else f"0 {noun}s matching the supplied filter" if filter else f"0 {noun}s"
        return CommandOutput(value={f"{noun}s": raw(message)}, help=())
    rows = [
        {field: entry.get(field, "unknown") for field in ("id", "name", "created_date", "last_modified_date")}
        for entry in entries
    ]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    help = [f"Run `falcon-axi {noun} show <id>` for the full {noun} record"]
    position = offset + len(entries)
    more_remain = position < count if count is not None else len(entries) >= ctx.limit
    if more_remain:
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value[f"{noun}s"] = rows
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    noun = ctx.spec.name.split()[0]
    requested = ctx.positionals[0]
    operation = ctx.spec.operations[0]
    response = _request(ctx, operation, {"ids": (requested,), "fields": ("__full__",)})
    entries = resources(response)
    if response.status == 404 or (response.status == 200 and not entries):
        raise CliError(
            "NOT_FOUND",
            f"no {noun} matched that identifier",
            [f"Run `falcon-axi {noun} list` to see current {noun} identifiers"],
        )
    if response.status != 200:
        raise translate_falcon_error(response, operation, f"{noun}s")
    matched = [entry for entry in entries if isinstance(entry, Mapping) and str(entry.get("id")) == requested]
    if not matched:
        raise CliError("UPSTREAM_ERROR", f"Falcon returned a {noun} resource without the requested identifier")
    detail = dict(matched[0])
    help: list[str] = []
    if not ctx.flags.get("full"):
        for field, content in detail.items():
            if isinstance(content, str):
                preview = truncate(content)
                detail[field] = preview.text
                if preview.truncated and not help:
                    help.append(f"Run `falcon-axi {noun} show {requested} --full` to see complete text fields")
    value: dict[str, Any] = {noun: detail}
    if ctx.flags.get("mitre"):
        mitre = _request(ctx, "GetMitreReport", {"actor_id": requested, "format": "json"})
        if mitre.status != 200:
            raise translate_falcon_error(mitre, "GetMitreReport", "actor ATT&CK mappings")
        # Unlike other Intel reads this export is a top-level JSON array, not a resources envelope.
        # falcon_mcp/modules/intel.py:get_mitre_report also treats JSON null as no mappings.
        mappings = mitre.body
        if mappings is not None and (
            not isinstance(mappings, list) or not all(isinstance(entry, Mapping) for entry in mappings)
        ):
            raise CliError("UPSTREAM_ERROR", "Falcon returned an invalid JSON ATT&CK report")
        value["mitre"] = mappings if mappings else raw("0 ATT&CK mappings for this actor")
    return CommandOutput(value=value, help=tuple(help))


def _specs(noun: str, query: OperationId, entity: OperationId, scope: str) -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name=f"{noun} list",
            help="\n".join(
                [
                    f"falcon-axi {noun} list [--filter <FQL>] [--limit N] [--cursor <token>]",
                    "",
                    "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                    f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                    "--cursor     opaque continuation token from a previous call",
                    "",
                    "Default fields: id, name, created_date, last_modified_date.",
                    "Filterable fields include name, slug, target_countries, and target_industries.",
                    "Examples:",
                    f"  falcon-axi {noun} list",
                    f"  falcon-axi {noun} list --filter \"name:'Synthetic*'\"",
                    "",
                    f"This command is read-only and requires {scope}:read (Falcon Intelligence subscription).",
                ]
            ),
            summary=f"  {noun} list".ljust(28) + f"list Falcon Intelligence {noun}s",
            handler=_list,
            operations=(query,),
            flags=("filter", "limit", "cursor"),
            value_flags=("filter", "limit", "cursor"),
            limit_ceiling=(QUERY_CEILING, "Intel combined query"),
        ),
        CommandSpec(
            name=f"{noun} show",
            help="\n".join(
                [
                    f"falcon-axi {noun} show <id> [--full]" + (" [--mitre]" if noun == "actor" else ""),
                    "",
                    "--full       print text fields without truncation (default 800 characters per field)",
                    *(["--mitre      also read this actor's JSON MITRE ATT&CK mappings"] if noun == "actor" else []),
                    "",
                    f"Reads the full {noun} record using an identifier from `falcon-axi {noun} list`.",
                    "No PDF, CSV, or rule file is downloaded or written.",
                    "Examples:",
                    f"  falcon-axi {noun} show 123456",
                    f"  falcon-axi {noun} show 123456 --full",
                    "",
                    f"This command is read-only and requires {scope}:read (Falcon Intelligence subscription).",
                ]
            ),
            summary=f"  {noun} show <id>".ljust(28) + f"the detail for one intelligence {noun}",
            handler=_show,
            operations=(entity, "GetMitreReport") if noun == "actor" else (entity,),
            flags=("full", "mitre") if noun == "actor" else ("full",),
            positional=(f"{noun} identifier", f"Run `falcon-axi {noun} list` to see current {noun} identifiers"),
        ),
    )


def _malware_list(ctx: Invocation) -> CommandOutput:
    context = CursorContext(
        operation="QueryMalwareEntities",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=ctx.text("filter"),
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    query: dict[str, Any] = {"limit": ctx.limit, "offset": offset}
    if ctx.text("filter"):
        query["filter"] = ctx.text("filter")
    response = ctx.transport.request(
        "QueryMalwareEntities",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "QueryMalwareEntities", "malware families")
    entries = [entry for entry in resources(response) if isinstance(entry, Mapping)]
    if not entries:
        return CommandOutput(
            {"malware": raw("no more malware families" if offset else "0 malware families matching this query")}, ()
        )
    rows = [{"id": entry.get("slug", "unknown"), "family_name": entry.get("name", "unknown")} for entry in entries]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total"), "malware": rows}
    help = ["Run `falcon-axi malware show <id>` for the malware family record"]
    if offset + len(entries) < count if count is not None else len(entries) == ctx.limit:
        continuation = encode_cursor(offset + len(entries), context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    return CommandOutput(value, tuple(help))


def _malware_show(ctx: Invocation) -> CommandOutput:
    response = ctx.transport.request(
        "GetMalwareEntities",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": (ctx.positionals[0],)},
        ),
    )
    if response.status not in (200, 404):
        raise translate_falcon_error(response, "GetMalwareEntities", "malware families")
    entries = (
        [entry for entry in resources(response) if isinstance(entry, Mapping) and entry.get("slug") == ctx.positionals[0]]
        if response.status == 200
        else []
    )
    if not entries:
        raise CliError(
            "NOT_FOUND",
            "no malware family matched that identifier",
            ["Run `falcon-axi malware list` to see family identifiers"],
        )
    detail = dict(entries[0])
    help: tuple[str, ...] = ()
    description = detail.get("description")
    if isinstance(description, str) and not ctx.flags.get("full"):
        shortened = truncate(description)
        detail["description"] = shortened.text
        if shortened.truncated:
            help = (f"Run `{ctx.suggestion} --full` for the full description",)
    return CommandOutput({"malware": detail}, help)


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    *_specs("actor", "QueryIntelActorEntities", "GetIntelActorEntities", "Actors (Falcon Intelligence)"),
    *_specs("report", "QueryIntelReportEntities", "GetIntelReportEntities", "Reports (Falcon Intelligence)"),
)

COMMAND_SPECS += (
    CommandSpec(
        name="malware list",
        handler=_malware_list,
        operations=("QueryMalwareEntities",),
        summary="  malware list              list intelligence malware families",
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(5000, "malware family query"),
        help="\n".join(
            [
                "falcon-axi malware list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter  raw FQL",
                "--limit   rows in this call (default 20, ceiling 5000)",
                "--cursor  opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi malware list",
                "  falcon-axi malware list --limit 50",
                "",
                "Read-only. Requires Malware Families (Falcon Intelligence):read.",
            ]
        ),
    ),
    CommandSpec(
        name="malware show",
        flags=("full",),
        handler=_malware_show,
        operations=("GetMalwareEntities",),
        summary="  malware show <id>         the full malware family record",
        positional=("malware family identifier", "Run `falcon-axi malware list` to see family identifiers"),
        help="\n".join(
            [
                "falcon-axi malware show <id> [--full]",
                "",
                "--full  show the complete description (default preview: 800 characters)",
                "Use the family slug printed by malware list.",
                "Example: falcon-axi malware show synthetic-family",
                "",
                "Read-only. Requires Malware Families (Falcon Intelligence):read.",
            ]
        ),
    ),
)
