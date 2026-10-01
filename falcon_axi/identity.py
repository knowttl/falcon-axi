"""Identity Protection directory and timeline reads over GraphQL, plus NG-SIEM account activity.

The directory commands send fixed, registered GraphQL documents through captain exception N2
(docs/design/v1.md §4.4), with variables and Relay pagination behind the same `--cursor` (§7.1).
`identity activity` composes a fixed NG-SIEM search under N1, adding no operation or scope (§4.3).
Its subject's closed shape excludes CQL syntax before regex metacharacters are escaped.
"""

import json
import re
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, body_of, rate_limit_note, text
from falcon_axi.falcon_error import trace_id, translate_falcon_error
from falcon_axi.fql import since_seconds
from falcon_axi.render import raw
from falcon_axi.search import DEFAULT_REPOSITORY, start_search
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import RequestArgs, Transport

GRAPHQL: OperationId = "api_preempt_proxy_post_graphql"

#: falcon-mcp caps its identity page size at 200. CrowdStrike publishes no ceiling for this endpoint,
#: so falcon-axi takes the one cited cap rather than inventing a larger one (§7.3, §17).
QUERY_CEILING = 200

ENTITY_TYPES = ("user", "endpoint")
#: The timeline categories falcon-mcp documents for `categories`, lowercased for the flag.
TIMELINE_CATEGORIES = ("activity", "notification", "threat", "entity", "audit", "policy", "system")
DEFAULT_SINCE = "7d"

#: Rows of one association list rendered by `identity show` without `--full`.
ASSOCIATIONS_SHOWN = 25

Node = Mapping[str, Any]


@dataclass(frozen=True)
class IdentityQuery:
    name: str | None = None
    email: str | None = None
    domain: str | None = None
    type: str | None = None


def _mapping(value: Any) -> Node:
    return value if isinstance(value, Mapping) else {}


def _objects(value: Any) -> list[Node]:
    return [entry for entry in value if isinstance(entry, Mapping)] if isinstance(value, list) else []


def _nodes(connection: Any) -> list[Node]:
    return _objects(_mapping(connection).get("nodes"))


def validate_entity_id(value: str) -> str:
    """An entity id is a GUID, and the variable's GraphQL type is `UUID`, so anything else cannot match."""
    candidate = value.strip()
    try:
        uuid.UUID(candidate)
    except ValueError as error:
        raise CliError(
            "VALIDATION_ERROR",
            "an identity id must be an entity GUID",
            [
                "Run `falcon-axi identity list --name '<name>'` to find an identity id",
                "For an Active Directory user the id may be the account object GUID, as in an identity detection's "
                "`source_account_object_guid`, which is unverified",
            ],
        ) from error
    return candidate


def _validate_pattern(value: str | None, flag: str) -> None:
    if value is None:
        return
    if not value.strip("* "):
        raise CliError(
            "VALIDATION_ERROR",
            f"--{flag} requires a value, and a bare wildcard matches every identity",
            [f"Pass a more specific pattern, for example `--{flag} 'Admin*'`"],
        )


def validate_identity_query(query: IdentityQuery) -> None:
    if query.type is not None and query.type.lower() not in ENTITY_TYPES:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown type {query.type}",
            [f"valid values for --type: {', '.join(ENTITY_TYPES)}"],
        )
    _validate_pattern(query.name, "name")
    _validate_pattern(query.email, "email")
    if query.domain is not None and not query.domain.strip():
        raise CliError("VALIDATION_ERROR", "--domain requires a value")


def _query(transport: Transport, session: Session, document: str, variables: Mapping[str, Any], subject: str) -> Node:
    """Sends one registered document and returns its `data`.

    GraphQL reports an execution failure as HTTP 200 with a body `errors` list (§17.9), so the body is
    read on success too, and a failure there is never rendered as an empty result.
    """
    response = transport.request(
        GRAPHQL,
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            document=document,
            variables=variables,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, GRAPHQL, subject, document)
    body = body_of(response)
    data = body.get("data")
    if body.get("errors") or not isinstance(data, Mapping):
        trace = trace_id(response)
        raise CliError(
            "UPSTREAM_ERROR",
            f"Falcon reported an error while answering the Identity Protection query for {subject}",
            ["Retry shortly", "Quote the trace_id when opening a CrowdStrike support case"],
            {"trace_id": trace} if trace else {},
        )
    return data


def _cell(value: Any) -> str:
    return text(value) or "unknown"


def _risk_of(node: Node) -> str:
    severity = _cell(node.get("riskScoreSeverity"))
    score = node.get("riskScore")
    return f"{severity} ({score})" if isinstance(score, (int, float)) and not isinstance(score, bool) else severity


def _page_info(connection: Any) -> tuple[bool, str | None]:
    info = _mapping(_mapping(connection).get("pageInfo"))
    cursor = text(info.get("endCursor"))
    return info.get("hasNextPage") is True and cursor is not None, cursor


def _rate_limit(session: Session, value: dict[str, Any]) -> dict[str, Any]:
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return value


def _cursor_context(session: Session, credential: Credential, fingerprint: str) -> CursorContext:
    return CursorContext(
        operation=GRAPHQL,
        client_id=credential.client_id,
        query=fingerprint,
        origin=session.base_url,
        member_cid=session.member_cid,
        model="token",
    )


def _list_document(entity_type: str | None) -> str:
    if entity_type is None:
        return "identity_list"
    return "identity_list_users" if entity_type == "user" else "identity_list_endpoints"


def describe_identity_query(query: IdentityQuery) -> str:
    parts: list[str] = []
    if query.type:
        parts.append(query.type)
    if query.name:
        parts.append(f"name {query.name}")
    if query.email:
        parts.append(f"email {query.email}")
    if query.domain:
        parts.append(f"domain {query.domain}")
    return " ".join(parts)


def list_identities(
    transport: Transport,
    session: Session,
    query: IdentityQuery,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
) -> CommandOutput:
    """`identity list`: one directory page, rendered as the five-field schema."""
    validate_identity_query(query)
    entity_type = query.type.lower() if query.type else None
    name = query.name
    email = query.email
    variables: dict[str, Any] = {"first": limit}
    if name:
        variables["name"] = name
    if email:
        variables["email"] = email
    if query.domain:
        variables["domains"] = [query.domain]
    fingerprint = json.dumps((entity_type, name, email, query.domain), separators=(",", ":"))
    context = _cursor_context(session, credential, fingerprint)
    if cursor is not None:
        variables["after"] = decode_after(cursor, context, credential.client_secret)

    data = _query(transport, session, _list_document(entity_type), variables, "identities")
    connection = data.get("entities")
    nodes = _nodes(connection)
    describe = describe_identity_query(replace(query, type=entity_type))
    if not nodes:
        empty = f"0 identities matching {describe}" if describe else "0 identities"
        return CommandOutput(
            value=_rate_limit(session, {"identities": empty}),
            help=(
                "Run `falcon-axi identity list` without filters to see the directory",
                "Name and email patterns accept `*` wildcards, for example `--name 'Admin*'`",
            ),
        )
    rows = [
        {
            "id": _cell(node.get("entityId")),
            "name": _cell(node.get("primaryDisplayName")),
            "secondary": _cell(node.get("secondaryDisplayName")),
            "type": _cell(node.get("type")),
            "risk": _risk_of(node),
        }
        for node in nodes
    ]
    help = [
        "Run `falcon-axi identity show <id>` for accounts, risk factors, associations, and open incidents",
        "Run `falcon-axi identity timeline <id>` for recent activity",
    ]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} shown")}
    more, end_cursor = _page_info(connection)
    if more and end_cursor:
        continuation = encode_cursor(end_cursor, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    value["identities"] = rows
    return CommandOutput(value=_rate_limit(session, value), help=tuple(help))


def _account_row(account: Node) -> dict[str, str]:
    columns = (
        ("domain", account.get("domain")),
        ("account", account.get("samAccountName")),
        ("source", account.get("dataSource")),
        ("title", account.get("title")),
        ("ou", account.get("ou")),
        ("password_last_changed", _mapping(account.get("passwordAttributes")).get("lastChange")),
        ("expires", account.get("expirationTime")),
    )
    return {name: str(value) for name, value in columns if text(value)}


def _association_row(association: Node) -> dict[str, str]:
    related = _mapping(association.get("entity"))
    place = _mapping(association.get("geoLocation"))
    name = (
        text(related.get("primaryDisplayName"))
        or text(association.get("accountName"))
        or ", ".join(part for part in (text(place.get("city")), text(place.get("country"))) if part)
    )
    row = {"binding": _cell(association.get("bindingType")), "name": name or "unknown"}
    related_id = text(related.get("entityId"))
    if related_id:
        row["entity_id"] = related_id
    return row


def _incident_row(incident: Node) -> dict[str, str]:
    compromised = _objects(incident.get("compromisedEntities"))
    return {
        "type": _cell(incident.get("type")),
        "start": _cell(incident.get("startTime")),
        "end": _cell(incident.get("endTime")),
        "compromised": ",".join(name for name in (text(entity.get("primaryDisplayName")) for entity in compromised) if name)
        or "unknown",
    }


def show_identity(transport: Transport, session: Session, id: str, full: bool) -> CommandOutput:
    """`identity show <id>`: one entity's directory detail, risk, accounts, associations, and open incidents."""
    entity_id = validate_entity_id(id)
    data = _query(transport, session, "identity_show", {"entityIds": [entity_id]}, "identities")
    nodes = _nodes(data.get("entities"))
    if not nodes:
        raise CliError(
            "NOT_FOUND",
            "no identity matched that identifier",
            ["Run `falcon-axi identity list --name '<name>'` to find current identity ids"],
        )
    node = nodes[0]
    associations = [_association_row(entry) for entry in _objects(node.get("associations"))]
    shown = associations if full else associations[:ASSOCIATIONS_SHOWN]
    detail: dict[str, Any] = {
        "id": _cell(node.get("entityId")),
        "name": _cell(node.get("primaryDisplayName")),
        "secondary": _cell(node.get("secondaryDisplayName")),
        "type": _cell(node.get("type")),
        "risk": _risk_of(node),
        "risk_factors": [
            {"type": _cell(factor.get("type")), "severity": _cell(factor.get("severity"))}
            for factor in _objects(node.get("riskFactors"))
        ],
        "accounts": [_account_row(entry) for entry in _objects(node.get("accounts"))],
        "associations": shown,
        "open_incidents": [_incident_row(entry) for entry in _nodes(node.get("openIncidents"))],
    }
    help = [f"Run `falcon-axi identity timeline {detail['id']}` for this identity's recent activity"]
    if len(shown) < len(associations):
        detail["associations_total"] = len(associations)
        help.append(f"Run `falcon-axi identity show {detail['id']} --full` to list every association")
    if _mapping(_mapping(node.get("openIncidents")).get("pageInfo")).get("hasNextPage") is True:
        detail["open_incidents_partial"] = True
        help.append(
            f"Open incidents are limited to the first {len(detail['open_incidents'])}; more exist in Falcon. "
            "--full expands associations only"
        )
    return CommandOutput(value=_rate_limit(session, {"identity": detail}), help=tuple(help))


def parse_categories(value: str) -> tuple[str, ...]:
    """`--category` takes one or more comma-separated timeline categories; an unknown one is refused."""
    names = [part.strip().lower() for part in value.split(",")]
    unknown = [name for name in names if name not in TIMELINE_CATEGORIES]
    if unknown:
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown --category {', '.join(name or '(empty)' for name in unknown)}",
            [f"valid values for --category: {', '.join(TIMELINE_CATEGORIES)}"],
        )
    return tuple(dict.fromkeys(names))


def _window_start(since: str) -> str:
    start = datetime.fromtimestamp(time.time() - since_seconds(since), tz=UTC)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_row(event: Node) -> dict[str, str]:
    source = _mapping(event.get("sourceEntity"))
    target = _mapping(event.get("targetEntity"))
    return {
        "time": _cell(event.get("timestamp")),
        "type": _cell(event.get("eventType")),
        "severity": _cell(event.get("eventSeverity")),
        "user": text(event.get("userDisplayName")) or _cell(source.get("primaryDisplayName")),
        "endpoint": text(event.get("endpointDisplayName")) or _cell(target.get("primaryDisplayName")),
        "ip": _cell(event.get("ipAddress")),
    }


def identity_timeline(
    transport: Transport,
    session: Session,
    id: str,
    since: str,
    categories: Sequence[str],
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
) -> CommandOutput:
    """`identity timeline <id>`: one page of an identity's recent activity, newest first."""
    entity_id = validate_entity_id(id)
    chosen = parse_categories(",".join(categories)) if categories else ()
    context = _cursor_context(session, credential, "|".join((entity_id.lower(), since.lower(), ",".join(chosen))))
    start = _window_start(since)
    variables: dict[str, Any] = {"entityIds": [entity_id], "first": limit}
    if categories:
        variables["categories"] = [name.upper() for name in chosen]
    if cursor is not None:
        # The window start travels in the cursor, so a later page continues the same window rather than a shifted one.
        start, _, after = decode_after(cursor, context, credential.client_secret).partition("|")
        variables["after"] = after
    variables["startTime"] = start

    data = _query(transport, session, "identity_timeline", variables, "identity timelines")
    connection = data.get("timeline")
    events = _nodes(connection)
    if not events:
        return CommandOutput(
            value=_rate_limit(session, {"events": f"0 events for this identity in the last {since}"}),
            help=(
                f"Run `falcon-axi identity timeline {entity_id} --since 30d` to widen the window",
                f"Run `falcon-axi identity show {entity_id}` to confirm the identity exists",
            ),
        )
    help = [
        f"Run `falcon-axi identity show {entity_id}` for this identity's risk, accounts, and associations",
        f"Run `falcon-axi identity timeline {entity_id} --category threat` to narrow to threat events",
    ]
    value: dict[str, Any] = {"window": f"the last {since}", "count": raw(f"{len(events)} shown")}
    more, end_cursor = _page_info(connection)
    if more and end_cursor:
        continuation = encode_cursor(f"{start}|{end_cursor}", context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    value["events"] = [_event_row(event) for event in events]
    return CommandOutput(value=_rate_limit(session, value), help=tuple(help))


_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
#: sAMAccountName and UPN characters. No quote, backslash, or `*`, so no value can end the CQL string
#: or become a wildcard.
_NAME = re.compile(r"^[A-Za-z0-9._@$-]{1,256}$")

_GUID_FIELDS = ("SourceAccountObjectGuid", "PerformedOnAccountObjectGuid", "AccountObjectGuid")
_NAME_FIELDS = ("SourceAccountSamAccountName", "SourceAccountUserName", "PerformedOnAccountName", "SamAccountName")
_EVENT_FAMILIES = "^(ActiveDirectory|Sso|IdpEntityRiskScoreChange)"
#: Rows the timeline returns, newest first.
TIMELINE_ROWS = 200
#: Authentication events carry Kerberos ticket hash samples, which are deliberately absent here.
_COLUMNS = (
    "@timestamp",
    "#event_simpleName",
    "SourceAccountSamAccountName",
    "SourceAccountUserName",
    "PerformedByAccountObjectName",
    "PerformedOnAccountName",
    "SourceEndpointHostName",
    "source.ip",
    "TargetServiceAccessIdentifier",
    "ActiveDirectoryAuditActionType",
)


def is_account_subject(subject: str) -> bool:
    return bool(_GUID.match(subject) or _NAME.match(subject))


def activity_query(subject: str) -> str:
    """The CQL for one account, given its objectGUID (an alert's `account_id`) or its account name."""
    if _GUID.match(subject):
        fields: tuple[str, ...] = _GUID_FIELDS
        pattern = subject
    elif _NAME.match(subject):
        fields = _NAME_FIELDS
        pattern = subject.replace(".", "\\.").replace("$", "\\$")
    else:
        raise CliError(
            "VALIDATION_ERROR",
            "identity activity takes an account objectGUID or an account name",
            [
                "An account name may contain letters, digits, and `. _ @ $ -` only; no wildcard is accepted",
                "Run `falcon-axi detection show <id>` for an identity detection's account and account_id",
            ],
        )
    # Matching is case-sensitive for a quoted string, and Falcon stores GUIDs in upper case while an
    # account name's case is whatever the directory holds, so both go through an anchored `/i` regex.
    match = " OR ".join(f"{field}=/^{pattern}$/i" for field in fields)
    columns = ", ".join(_COLUMNS)
    return (
        f"#event_simpleName=/{_EVENT_FAMILIES}/ | {match} "
        f"| table([{columns}], limit={TIMELINE_ROWS}, sortby=@timestamp, order=desc)"
    )


def start_identity_activity(
    transport: Transport,
    session: Session,
    subject: str,
    since: str,
) -> CommandOutput:
    """`identity activity <account>`: start one NG-SIEM job and hand its polling to `search status`."""
    return start_search(transport, session, activity_query(subject), DEFAULT_REPOSITORY, since)
