"""The Spotlight vulnerabilities domain: one combined request, paginated by `after` token.

`combinedQueryVulnerabilities` returns entities directly, so there is no hydrate step (§2.3), and
its cursor lives in `meta.pagination.after` rather than an offset (§7.1).
"""

from collections.abc import Mapping
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, after_token, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import VulnQuery, describe_vuln_query, vuln_filter
from falcon_axi.render import raw
from falcon_axi.transport.types import FalconResponse, RequestArgs, Transport

#: Documented Spotlight limits (docs/design/v1.md §7.3): "Max: 5000, Default: 100".
QUERY_CEILING = 5_000

Vulnerability = Mapping[str, Any]


def _cve_of(record: Vulnerability) -> Mapping[str, Any]:
    cve = record.get("cve")
    return cve if isinstance(cve, Mapping) else {}


def _host_of(record: Vulnerability) -> Mapping[str, Any]:
    host = record.get("host_info")
    return host if isinstance(host, Mapping) else {}


def _query_vulnerabilities(
    transport: Transport, session: Session, filter: str, limit: int, after: str | None
) -> FalconResponse:
    query: dict[str, str | int] = {"limit": limit, "filter": filter}
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


def list_vulnerabilities(
    transport: Transport,
    session: Session,
    query: VulnQuery,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
) -> CommandOutput:
    """`vuln list`: one combined read, rendered as the four-field schema (§10.2)."""
    filter = vuln_filter(query)
    context = _cursor_context(session, credential, filter)
    after = None if cursor is None else decode_after(cursor, context, credential.client_secret)
    response = _query_vulnerabilities(transport, session, filter, limit, after)
    records = [entry for entry in resources(response) if isinstance(entry, Mapping)]
    describe = describe_vuln_query(query)

    if not records:
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
