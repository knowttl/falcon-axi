"""Falcon Shield posture checks, matching falcon-mcp's search_shield_checks read."""

import json
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, redact, truncate
from falcon_axi.response_diagnostics import upstream_invalid
from falcon_axi.transport.types import RequestArgs

# The API documents no maximum. This is a local page-size cap, not a server claim.
PAGE_CEILING = 100
STATUSES = ("Passed", "Failed", "Dismissed", "Pending", "Can't Run", "Stale", "NA", "Not Available")
IMPACTS = ("Low", "Medium", "High")


def _checks(ctx: Invocation, query: Mapping[str, str | int]) -> list[Mapping[str, Any]]:
    response = ctx.transport.request(
        "GetSecurityChecksV3",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status == 404 and ctx.spec.name == "shield show":
        return []
    if response.status != 200:
        raise translate_falcon_error(response, "GetSecurityChecksV3", "Shield checks")
    listed = response.body
    if not isinstance(listed, list):
        raise upstream_invalid("Falcon returned an invalid Shield check array")
    if any(not isinstance(entry, Mapping) or not isinstance(entry.get("id"), str) or not entry["id"] for entry in listed):
        raise upstream_invalid("Falcon returned a Shield check without an identifier")
    return listed


def check_filters(flags: Mapping[str, str | bool]) -> dict[str, str | int]:
    query: dict[str, str | int] = {}
    for name, choices in (("status", STATUSES), ("impact", IMPACTS)):
        supplied = flags.get(name)
        if isinstance(supplied, str):
            normalized = next((choice for choice in choices if choice.lower() == supplied.lower()), None)
            if normalized is None:
                raise CliError("VALIDATION_ERROR", f"--{name} must be one of {', '.join(choices)}")
            query[name] = normalized
    return query


def _list(ctx: Invocation) -> CommandOutput:
    query = check_filters(ctx.flags)
    context = CursorContext(
        operation="GetSecurityChecksV3",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=json.dumps(query, sort_keys=True),
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    query.update(limit=ctx.limit, offset=offset)
    checks = _checks(ctx, query)
    if not checks:
        return CommandOutput(
            {"checks": raw("no more Shield checks" if offset else "0 Shield checks matching this query")},
            (),
        )
    value: dict[str, Any] = {"count": raw(f"{len(checks)} of unknown total")}
    help = ["Run `falcon-axi shield show <id>` for the full posture check"]
    next_offset = offset + len(checks)
    if len(checks) == ctx.limit:
        continuation = encode_cursor(next_offset, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value["checks"] = [{key: check.get(key, "unknown") for key in ("id", "name", "status", "impact")} for check in checks]
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value, tuple(help))


def _show(ctx: Invocation) -> CommandOutput:
    requested = ctx.positionals[0]
    checks = _checks(ctx, {"id": requested})
    if not checks:
        raise CliError("NOT_FOUND", "no Shield check matched that identifier", ["Run `falcon-axi shield list` for check IDs"])
    matched = next((check for check in checks if check["id"] == requested), None)
    if matched is None:
        raise upstream_invalid("Falcon returned Shield checks without the requested identifier")
    truncated = False

    def detail(value: Any) -> Any:
        nonlocal truncated
        if isinstance(value, str) and not ctx.flags.get("full"):
            shortened = truncate(value)
            truncated |= shortened.truncated
            return shortened.text
        if isinstance(value, Mapping):
            return {key: detail(entry) for key, entry in value.items()}
        if isinstance(value, list):
            return [detail(entry) for entry in value]
        return value

    value = {"check": detail(redact(matched))}
    help = (f"Run `falcon-axi shield show {requested} --full` for untruncated text",) if truncated else ()
    return CommandOutput(value, help)


COMMAND_SPECS = (
    CommandSpec(
        name="shield list",
        help="\n".join(
            [
                "falcon-axi shield list [--status <status>] [--impact <impact>] [--limit N] [--cursor <token>]",
                "",
                "List Falcon Shield SaaS security posture checks. This is not the detection alerts list.",
                f"--status   {', '.join(STATUSES)} (case-insensitive)",
                "--impact   Low, Medium, High (case-insensitive)",
                "--limit    rows in this call (default 20, local cap 100)",
                "--cursor   opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi shield list --status failed --impact high",
                "  falcon-axi shield list --limit 50",
                "",
                "Read-only. Requires SaaS Security:read (Falcon Shield).",
            ]
        ),
        summary="  shield list               list SaaS security posture checks",
        handler=_list,
        operations=("GetSecurityChecksV3",),
        flags=("status", "impact", "limit", "cursor"),
        value_flags=("status", "impact", "limit", "cursor"),
        limit_ceiling=(PAGE_CEILING, "local Shield page-size"),
    ),
    CommandSpec(
        name="shield show",
        help="\n".join(
            [
                "falcon-axi shield show <check id> [--full]",
                "",
                "Read one Falcon Shield posture check, including remediation details returned by the API.",
                "Long text is truncated at 800 characters by default; --full returns untruncated text.",
                "",
                "Examples:",
                "  falcon-axi shield show <id>",
                "  falcon-axi shield show <id> --full",
                "",
                "Read-only. Requires SaaS Security:read (Falcon Shield).",
            ]
        ),
        summary="  shield show <id>          detail for one SaaS security posture check",
        handler=_show,
        operations=("GetSecurityChecksV3",),
        flags=("full",),
        positional=("Shield check identifier", "Run `falcon-axi shield list` for check IDs"),
    ),
)
