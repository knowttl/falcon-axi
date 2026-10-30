"""Falcon Intelligence CVE query and detail reads (docs/design/v1.md §2.1, §2.2)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import window
from falcon_axi.render import raw
from falcon_axi.response_diagnostics import upstream_invalid
from falcon_axi.transport.types import RequestArgs, Transport

#: MITRE's CVE id shape. Rejecting anything else also keeps the value out of a later FQL filter.
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

# A conservative CLI page cap; the Intel reference does not publish an endpoint maximum.
QUERY_CEILING = 100
SEVERITIES = ("low", "medium", "high", "critical")


def list_cves(ctx: Invocation) -> CommandOutput:
    """Query Intel CVE ids by offset, then hydrate and restore query order."""
    terms: list[str] = []
    severity = ctx.text("severity")
    if severity is not None:
        if severity.lower() not in SEVERITIES:
            raise CliError("VALIDATION_ERROR", f"unknown severity {severity}", [f"valid severities: {', '.join(SEVERITIES)}"])
        terms.append(f"severity:'{severity.upper()}'")
    since = ctx.text("since")
    if since is not None:
        terms.append(f"publish_date:>'{window(since)}'")
    supplied = ctx.text("filter")
    if supplied is not None:
        if not supplied.strip():
            raise CliError("VALIDATION_ERROR", "--filter requires a value")
        terms.append(f"({supplied})" if terms else supplied)
    filter = "+".join(terms) or None
    session = ctx.session
    credential = ctx.credential
    context = CursorContext(
        operation="QueryVulnerabilities",
        client_id=credential.client_id,
        origin=session.base_url,
        query=filter,
        member_cid=session.member_cid,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, credential.client_secret) if cursor is not None else 0
    query: dict[str, str | int] = {"limit": ctx.limit, "offset": str(offset)}
    if filter:
        query["filter"] = filter
    response = ctx.transport.request(
        "QueryVulnerabilities",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "QueryVulnerabilities", "CVE intelligence")
    ids = [entry for entry in resources(response) if isinstance(entry, str)]
    count = total(response)
    if not ids:
        message = (
            "no more CVEs"
            if offset
            else ("0 CVEs matching the supplied filters" if filter else "0 CVEs in Falcon Intelligence")
        )
        return CommandOutput(value={"cves": raw(message)}, help=())
    hydrated = ctx.transport.request(
        "GetVulnerabilities",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            body={"ids": ids},
        ),
    )
    if hydrated.status not in (200, 404):
        raise translate_falcon_error(hydrated, "GetVulnerabilities", "CVE intelligence")
    entries = resources(hydrated) if hydrated.status == 200 else []
    by_id = {entry.get("cve"): entry for entry in entries if isinstance(entry, Mapping)}
    rows = [
        {
            "cve": id,
            "severity": _plain(by_id[id].get("severity")),
            "cvss_v3_score": _score(by_id[id]),
            "exploit_status": _plain(by_id[id].get("exploit_status")),
        }
        for id in ids
        if id in by_id
    ]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    help = ["Run `falcon-axi cve show <CVE-ID>` for CVE intelligence and tenant-exposure guidance"]
    position = offset + len(ids)
    more_remain = position < count if count is not None else len(ids) >= ctx.limit
    if more_remain:
        continuation = encode_cursor(position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value["cves"] = rows
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def validate_cve_id(value: str) -> str:
    if CVE_ID.fullmatch(value):
        return value
    raise CliError(
        "VALIDATION_ERROR",
        "cve show requires a CVE identifier such as CVE-2021-44228",
        ["A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228"],
    )


def _count(value: Any) -> int:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return len(value)
    return 0


def _score(record: Mapping[str, Any]) -> int | float | str:
    base = record.get("cvss_v3_base")
    score = base.get("score") if isinstance(base, Mapping) else None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return "unknown"
    return int(score) if float(score).is_integer() else float(score)


def _plain(value: Any) -> str:
    found = text(value)
    if found:
        return found
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "unknown"
    return str(value)


def _empty(cve_id: str) -> CommandOutput:
    return CommandOutput(
        value={"vulnerabilities": raw(f"0 vulnerabilities matching {cve_id}")},
        help=(
            "CrowdStrike Intelligence has no entry for that CVE, which is not the same as no host exposure",
            f"Run `falcon-axi vuln list --filter \"cve.id:'{cve_id}'\"` for tenant exposure",
        ),
    )


def show_cve(transport: Transport, session: Session, cve_id: str) -> CommandOutput:
    """`cve show <CVE-ID>`: one GetVulnerabilities read, shaped to the default fields."""
    requested = validate_cve_id(cve_id)
    response = transport.request(
        "GetVulnerabilities",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            body={"ids": [requested]},
        ),
    )
    if response.status == 404:
        return _empty(requested)
    if response.status != 200:
        error = translate_falcon_error(response, "GetVulnerabilities", "CVE intelligence")
        if error.code == "SCOPE_DENIED":
            raise CliError(
                error.code,
                error.message,
                (
                    *error.help,
                    "This scope requires a Falcon Intelligence subscription; "
                    "Spotlight's Vulnerabilities:read does not satisfy it",
                    "If the scope is missing from the API client picker, ask your Falcon administrator about the license",
                ),
                error.details,
            )
        raise error
    listed = resources(response)
    if not listed:
        return _empty(requested)
    matched = [entry for entry in listed if isinstance(entry, Mapping) and entry.get("cve") == requested]
    if not matched:
        raise upstream_invalid("Falcon returned a CVE intelligence resource without the requested CVE")
    record = matched[0]
    return CommandOutput(
        value={
            "cve": {
                "cve": requested,
                "severity": _plain(record.get("severity")),
                "cvss_v3_score": _score(record),
                "exploit_status": _plain(record.get("exploit_status")),
                "publish_date": _plain(record.get("publish_date")),
                "updated": _plain(record.get("updated_timestamp")),
                "description": _plain(record.get("description")),
                "affected_products": _count(record.get("affected_products")),
                "related_actors": _count(record.get("related_actors")),
                "related_reports": _count(record.get("related_reports")),
                "related_threats": _count(record.get("related_threats")),
            }
        },
        help=(
            "Related actor, report, threat, and affected-product lists are counts; this command does not expand them",
            f"Run `falcon-axi vuln list --filter \"cve.id:'{requested}'\"` for tenant exposure",
        ),
    )


def _cve_show(ctx: Invocation) -> CommandOutput:
    return show_cve(ctx.transport, ctx.session, ctx.positionals[0])


COMMAND_SPECS = (
    CommandSpec(
        name="cve list",
        help="\n".join(
            [
                "falcon-axi cve list [--filter <FQL>] [--severity <name>] [--since <window>] [--limit N] [--cursor <token>]",
                "",
                "Lists Falcon Intelligence CVEs, not tenant host exposure.",
                "--filter     raw FQL, combined with shorthand filters using AND",
                f"--severity   one of {', '.join(SEVERITIES)}",
                "--since      publish_date within a relative window such as 24h or 7d",
                "--limit      rows in this call (default 20, CLI cap 100; API maximum is undocumented)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Default columns are cve, severity, cvss_v3_score, and exploit_status.",
                "Filterable fields include cve, severity, publish_date, updated_timestamp, and exploit_status.",
                "Examples:",
                "  falcon-axi cve list --severity critical --since 7d",
                "  falcon-axi cve list --filter \"exploit_status:'unproven'\"",
                "",
                "This command is read-only and requires Vulnerabilities (Falcon Intelligence):read.",
                "That scope requires a Falcon Intelligence subscription; Spotlight's Vulnerabilities:read does not satisfy it.",
            ]
        ),
        summary="  cve list                  list Falcon Intelligence CVEs",
        handler=list_cves,
        operations=("QueryVulnerabilities", "GetVulnerabilities"),
        flags=("filter", "severity", "since", "limit", "cursor"),
        value_flags=("filter", "severity", "since", "limit", "cursor"),
        limit_ceiling=(QUERY_CEILING, "CVE CLI page policy (API maximum undocumented)"),
    ),
    CommandSpec(
        name="cve show",
        help="\n".join(
            [
                "falcon-axi cve show <CVE-ID>",
                "",
                "Reads one CVE from Falcon Intelligence. It is not Spotlight host exposure:",
                "an empty result means CrowdStrike Intelligence has no entry, not that no host is affected.",
                "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228.",
                "",
                "Default fields are cve, severity, cvss_v3_score, exploit_status, publish_date, updated,",
                "and description. Related actor, report, threat, and affected-product lists are counts.",
                "This command does not expand those lists. Run `falcon-axi cve list` to find CVEs.",
                "",
                "Example: falcon-axi cve show CVE-2021-44228",
                "",
                "This command is read-only and requires Vulnerabilities (Falcon Intelligence):read.",
                "That scope is license-gated. Spotlight's Vulnerabilities:read does not satisfy it, and a",
                "scope missing from the API client picker means the tenant has no Falcon Intelligence subscription.",
                "Whether --member-cid carries this scope is unverified.",
            ]
        ),
        summary="  cve show <CVE-ID>         Falcon Intelligence detail for one CVE",
        handler=_cve_show,
        operations=("GetVulnerabilities",),
        positional=("CVE identifier", "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228"),
    ),
)
