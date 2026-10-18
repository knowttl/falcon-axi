"""Malware family reads, corroborated by falconpy _intel and PSFalcon intel.ps1."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, truncate
from falcon_axi.transport.types import RequestArgs


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
    rows = [{"id": entry.get("slug", "unknown"), "family_name": entry.get("family_name", "unknown")} for entry in entries]
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


COMMAND_SPECS = (
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
