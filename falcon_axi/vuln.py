"""The Spotlight vulnerabilities domain: one combined request per page, paginated by `after` token.

`combinedQueryVulnerabilities` returns entities directly, so there is no hydrate step (§2.3), and
its cursor lives in `meta.pagination.after` rather than an offset (§7.1).
"""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.command import CommandSpec, Invocation, string
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, Position, decode_after, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, after_token, parse_fields, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import VULN_SEVERITIES, VULN_STATUSES, VulnQuery, describe_vuln_query, vuln_filter
from falcon_axi.render import raw
from falcon_axi.transport.types import FalconResponse, QueryValue, RequestArgs, Transport
from falcon_axi.walk import Page, max_rows_of, walk

#: Documented Spotlight limits (docs/design/v1.md §7.3): "Max: 5000, Default: 100".
QUERY_CEILING = 5_000

#: Default columns always need these facets; Spotlight omits them otherwise (docs/design/v1.md §10.2).
DEFAULT_FACETS = ("cve", "host_info")
DEFAULT_FIELDS = ("id", "cve", "severity", "hostname")

#: `--fields` extends the default row; each name maps to the facet it needs, or none (§7.2, §10).
EXTRA_FIELDS: Mapping[str, str | None] = {
    "description": "cve",
    "base_score": "cve",
    "exprt_rating": "cve",
    "status": None,
    "created": None,
    "updated": None,
    "product": None,
    "remediation": "remediation",
    "platform": "host_info",
    "os": "host_info",
    "local_ip": "host_info",
}

Vulnerability = Mapping[str, Any]


def _cve_of(record: Vulnerability) -> Mapping[str, Any]:
    cve = record.get("cve")
    return cve if isinstance(cve, Mapping) else {}


def _host_of(record: Vulnerability) -> Mapping[str, Any]:
    host = record.get("host_info")
    return host if isinstance(host, Mapping) else {}


def facets_for(fields: Sequence[str]) -> tuple[str, ...]:
    """The Spotlight facets the rendered columns need, and no others."""
    selected = list(DEFAULT_FACETS)
    for name in fields:
        facet = EXTRA_FIELDS.get(name)
        if facet and facet not in selected:
            selected.append(facet)
    return tuple(selected)


def _query_vulnerabilities(
    transport: Transport,
    session: Session,
    filter: str,
    limit: int,
    after: str | None,
    fields: Sequence[str],
) -> FalconResponse:
    query: dict[str, QueryValue] = {"limit": limit, "filter": filter, "facet": facets_for(fields)}
    if after:
        query["after"] = after
    response = transport.request(
        "combinedQueryVulnerabilities",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "combinedQueryVulnerabilities", "vulnerabilities")
    return response


def _cursor_context(session: Session, credential: Credential, filter: str) -> CursorContext:
    return CursorContext(
        operation="combinedQueryVulnerabilities",
        client_id=credential.client_id,
        query=filter,
        origin=session.base_url,
        member_cid=session.member_cid,
        model="token",
    )


def _cell(value: Any) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, bool) or value is None:
        return "unknown"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    return "unknown"


def _joined(values: Any, key: str | None = None) -> str | None:
    if isinstance(values, str) and values:
        return values
    if not isinstance(values, list):
        return None
    parts: list[str] = []
    for entry in values:
        if key is None:
            part = text(entry)
        else:
            part = text(entry.get(key)) if isinstance(entry, Mapping) else None
        if part and part not in parts:
            parts.append(part)
    return ",".join(parts) if parts else None


def _product_of(record: Vulnerability) -> str | None:
    named = _joined(record.get("apps"), "product_name_version")
    if named:
        return named
    app = record.get("app")
    return text(app.get("product_name_version")) if isinstance(app, Mapping) else None


def _remediation_of(record: Vulnerability) -> str | None:
    remediation = record.get("remediation")
    if not isinstance(remediation, Mapping):
        return None
    return _joined(remediation.get("ids"))


def _extra(record: Vulnerability, name: str) -> str:
    cve = _cve_of(record)
    host = _host_of(record)
    value: Any
    if name == "description":
        value = cve.get("description")
    elif name == "base_score":
        value = cve.get("base_score")
    elif name == "exprt_rating":
        value = cve.get("exprt_rating")
    elif name == "status":
        value = record.get("status")
    elif name == "created":
        value = record.get("created_timestamp")
    elif name == "updated":
        value = record.get("updated_timestamp")
    elif name == "product":
        return _product_of(record) or "unknown"
    elif name == "remediation":
        return _remediation_of(record) or "unknown"
    elif name == "platform":
        value = host.get("platform_name") or host.get("platform")
    elif name == "os":
        value = host.get("os_version")
    elif name == "local_ip":
        value = host.get("local_ip")
    else:
        value = None
    return _cell(value)


def list_vulnerabilities(
    transport: Transport,
    session: Session,
    query: VulnQuery,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
    fields: Sequence[str] = (),
    max_rows: int | None = None,
) -> CommandOutput:
    """`vuln list`: combined reads, rendered as the default row plus any `--fields` (§10.2)."""
    selected = parse_fields(",".join(fields), EXTRA_FIELDS, DEFAULT_FIELDS) if fields else ()
    filter = vuln_filter(query)
    context = _cursor_context(session, credential, filter)
    after = None if cursor is None else decode_after(cursor, context, credential.client_secret)

    def fetch(size: int, position: Position | None) -> Page[Vulnerability]:
        assert position is None or isinstance(position, str)
        response = _query_vulnerabilities(transport, session, filter, size, position, selected)
        records = [entry for entry in resources(response) if isinstance(entry, Mapping)]
        next_after = after_token(response)
        return Page(records, total(response), next_after if len(records) >= size else None, len(records))

    result = walk(fetch, after, limit, QUERY_CEILING, max_rows)
    records = result.items
    describe = describe_vuln_query(query)

    if not records:
        if after is not None:
            return CommandOutput(value={"vulnerabilities": raw("no more vulnerabilities")}, help=())
        return CommandOutput(
            value={"vulnerabilities": raw(f"0 vulnerabilities matching {describe}" if describe else "0 vulnerabilities")},
            help=(
                "Run `falcon-axi vuln list --status open` to see every open vulnerability",
                "Run `falcon-axi host list` to find the host you meant",
            ),
        )

    rows = [
        {
            "id": text(record.get("id")) or "unknown",
            "cve": text(_cve_of(record).get("id")) or "unknown",
            "severity": text(_cve_of(record).get("severity")) or "unknown",
            "hostname": text(_host_of(record).get("hostname")) or "unknown",
            **{name: _extra(record, name) for name in selected},
        }
        for record in records
    ]
    count = result.total
    help = ["Run `falcon-axi host list --filter \"hostname:'<name>'\"` to read an affected host"]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    result.partial(value, help, result.next_position is not None)
    if result.next_position is not None:
        continuation = encode_cursor(result.next_position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    value["vulnerabilities"] = rows
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def _vuln_list(ctx: Invocation) -> CommandOutput:
    return list_vulnerabilities(
        ctx.transport,
        ctx.session,
        query=_vuln_query_of(ctx.flags),
        limit=ctx.limit,
        cursor=ctx.text("cursor"),
        credential=ctx.credential,
        suggestion=ctx.suggestion,
        max_rows=max_rows_of(ctx.flags),
        fields=parse_fields(ctx.text("fields") or "", ctx.spec.extra_fields, ctx.spec.default_fields)
        if "fields" in ctx.flags
        else (),
    )


def _vuln_query_of(flags: Mapping[str, str | bool]) -> VulnQuery:
    return VulnQuery(
        filter=string(flags.get("filter")),
        host=string(flags.get("host")),
        severity=string(flags.get("severity")),
        status=string(flags.get("status")),
        since=string(flags.get("since")),
    )


COMMAND_SPECS = (
    CommandSpec(
        name="vuln list",
        help="\n".join(
            [
                "falcon-axi vuln list [--host <device id>] [--severity <name>] [--status <name>] "
                "[--since <window>] [--filter <FQL>] [--limit N] [--cursor <token>] [--fields <names>] "
                "[--all] [--max-rows N]",
                "",
                "--host       device id (AID) whose vulnerabilities to read",
                f"--severity   one of {', '.join(VULN_SEVERITIES)}",
                f"--status     one of {', '.join(VULN_STATUSES)}",
                "--since      created_timestamp within a relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "--all        walk pages; page size is independent of --limit",
                "--max-rows   row budget (default 1000; requires --all)",
                f"--fields     extra columns, comma-separated: {', '.join(EXTRA_FIELDS)}",
                "",
                "Default columns are id, cve, severity, and hostname. --fields adds columns from that",
                "allowlist; an unknown name is refused and the valid names are listed.",
                "A filter is required, from a shorthand flag or --filter, because Spotlight requires one.",
                "Wildcards are unsupported and a `*` is refused before the request is made.",
                "Filterable fields include aid, cve.id, cve.severity, cve.exprt_rating, cve.exploit_status,",
                "status, and created_timestamp.",
                "Examples:",
                "  falcon-axi vuln list --severity critical --status open",
                "  falcon-axi vuln list --filter \"status:'open'+cve.exploit_status:'90'\"",
                "",
                "This command is read-only and requires only Vulnerabilities:read.",
            ]
        ),
        summary="  vuln list                 list Spotlight vulnerabilities; a filter is required",
        handler=_vuln_list,
        operations=("combinedQueryVulnerabilities",),
        flags=("filter", "host", "severity", "status", "since", "limit", "cursor", "fields", "all", "max-rows"),
        value_flags=("filter", "host", "severity", "status", "since", "limit", "cursor", "fields", "max-rows"),
        limit_ceiling=(QUERY_CEILING, "Spotlight query"),
        extra_fields=tuple(EXTRA_FIELDS),
        default_fields=DEFAULT_FIELDS,
    ),
)
