"""The Spotlight vulnerabilities domain: one combined request, paginated by `after` token.

`combinedQueryVulnerabilities` returns entities directly, so there is no hydrate step (§2.3), and
its cursor lives in `meta.pagination.after` rather than an offset (§7.1).
"""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, after_token, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import VulnQuery, describe_vuln_query, vuln_filter
from falcon_axi.render import raw
from falcon_axi.transport.types import FalconResponse, QueryValue, RequestArgs, Transport

#: Documented Spotlight limits (docs/design/v1.md §7.3): "Max: 5000, Default: 100".
QUERY_CEILING = 5_000

#: Default columns always need these facets; Spotlight omits them otherwise (docs/design/v1.md §10.2).
DEFAULT_FACETS = ("cve", "host_info")

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


def parse_fields(value: str) -> tuple[str, ...]:
    """`--fields` is a comma-separated extension of the default row (§7.2).

    An unknown name is a validation error listing the allowlist. It is never dropped.
    """
    names = [part.strip() for part in value.split(",")]
    if not names or any(not name for name in names):
        raise CliError(
            "VALIDATION_ERROR",
            "--fields requires one or more field names",
            [f"valid --fields names: {', '.join(EXTRA_FIELDS)}"],
        )
    unknown = [name for name in names if name not in EXTRA_FIELDS]
    if unknown:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown --fields name {', '.join(unknown)}",
            [
                f"valid --fields names: {', '.join(EXTRA_FIELDS)}",
                "default columns id, cve, severity, hostname are always included",
            ],
        )
    selected: list[str] = []
    for name in names:
        if name not in selected:
            selected.append(name)
    return tuple(selected)


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
) -> CommandOutput:
    """`vuln list`: one combined read, rendered as the default row plus any `--fields` (§10.2)."""
    selected = parse_fields(",".join(fields)) if fields else ()
    filter = vuln_filter(query)
    context = _cursor_context(session, credential, filter)
    after = None if cursor is None else decode_after(cursor, context, credential.client_secret)
    response = _query_vulnerabilities(transport, session, filter, limit, after, selected)
    records = [entry for entry in resources(response) if isinstance(entry, Mapping)]
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
    count = total(response)
    help = ["Run `falcon-axi host list --filter \"hostname:'<name>'\"` to read an affected host"]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    next_after = after_token(response)
    if next_after and len(rows) >= limit:
        continuation = encode_cursor(next_after, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
        if session.member_cid:
            help.append("Supply the same tenant selection used for this invocation when continuing")
    value["vulnerabilities"] = rows
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))
