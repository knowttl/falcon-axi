"""The detections domain: pure functions from arguments to requests and responses to rows."""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import DetectionQuery, describe_detection_query, detection_filter
from falcon_axi.render import raw, truncate
from falcon_axi.transport.types import RequestArgs, Transport

#: Documented Alerts limits (docs/design/v1.md §7.3, §2.3).
QUERY_CEILING = 10_000
HYDRATE_CHUNK = 1_000
#: v1's defensive Alerts result stop; unverified and open in §17.12.
ALERTS_WALL = 10_000

Alert = Mapping[str, Any]


def _hostname_of(alert: Alert) -> str | None:
    device = alert.get("device")
    from_device = text(device.get("hostname")) if isinstance(device, Mapping) else None
    return from_device or text(alert.get("hostname"))


def _device_id_of(alert: Alert) -> str | None:
    device = alert.get("device")
    from_device = text(device.get("device_id")) if isinstance(device, Mapping) else None
    return from_device or text(alert.get("device_id")) or text(alert.get("agent_id"))


def _id_of(alert: Alert) -> str:
    return text(alert.get("composite_id")) or text(alert.get("id")) or ""


def _severity_of(alert: Alert) -> str:
    name = text(alert.get("severity_name")) or "unknown"
    severity = alert.get("severity")
    return f"{name} ({severity})" if isinstance(severity, (int, float)) and not isinstance(severity, bool) else name


def _query_alert_ids(
    transport: Transport, session: Session, filter: str | None, limit: int, offset: int
) -> tuple[list[str], int | None]:
    query: dict[str, str | int] = {"limit": limit, "offset": offset}
    if filter:
        query["filter"] = filter
    response = transport.request(
        "GetQueriesAlertsV2",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "GetQueriesAlertsV2", "detections")
    return [id for id in resources(response) if isinstance(id, str)], total(response)


def _hydrate_alerts(transport: Transport, session: Session, ids: Sequence[str]) -> list[Alert]:
    """Hydrates composite ids into alert records (§2.3).

    The hydrate cap is smaller than the query cap, so the step is chunked, and the query-step order
    is reapplied because an entity endpoint may return resources in arbitrary order.
    """
    by_id: dict[str, Alert] = {}
    for index in range(0, len(ids), HYDRATE_CHUNK):
        chunk = list(ids[index : index + HYDRATE_CHUNK])
        response = transport.request(
            "PostEntitiesAlertsV2",
            RequestArgs(
                base_url=session.base_url,
                token=session.token,
                allow_unknown_origin=session.allow_unknown_origin,
                body={"composite_ids": chunk},
            ),
        )
        if response.status != 200:
            raise translate_falcon_error(response, "PostEntitiesAlertsV2", "detections")
        for entry in resources(response):
            if not isinstance(entry, Mapping):
                continue
            id = _id_of(entry)
            if id:
                by_id[id] = entry
    return [by_id[id] for id in ids if id in by_id]


def _cursor_context(session: Session, credential: Credential, filter: str | None) -> CursorContext:
    return CursorContext(
        operation="GetQueriesAlertsV2",
        client_id=credential.client_id,
        query=filter,
        origin=session.base_url,
        member_cid=session.member_cid,
    )


def list_detections(
    transport: Transport,
    session: Session,
    query: DetectionQuery,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
    rows: int | None = None,
) -> CommandOutput:
    """`detection list`: query ids, hydrate them, and render the four-field schema (§10.2)."""
    filter = detection_filter(query)
    context = _cursor_context(session, credential, filter)
    offset = 0 if cursor is None else decode_offset(cursor, context, credential.client_secret)
    headroom = ALERTS_WALL - offset
    if headroom <= 0:
        raise CliError(
            "PAGINATION_LIMIT",
            f"this read reached the {ALERTS_WALL} result boundary falcon-axi enforces for Alerts",
            [
                f"Narrow the filter so the result set fits under {ALERTS_WALL}, for example by "
                "shortening `--since` or adding `--severity`",
                "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` "
                "pagination, which falcon-axi v1 does not register",
            ],
        )
    page = min(limit, headroom)
    ids, count = _query_alert_ids(transport, session, filter, page, offset)
    describe = describe_detection_query(query)

    if not ids:
        if offset > 0:
            return CommandOutput(value={"detections": raw("no more detections")}, help=())
        empty_help = (
            (f"Run `{suggestion} --since 7d` to widen the window",)
            if query.since
            else ("Run `falcon-axi detection list` without filters to see what is firing",)
        )
        detections = f"0 detections matching {describe}" if describe else "0 detections in this tenant"
        return CommandOutput(value={"detections": raw(detections)}, help=empty_help)

    alerts = _hydrate_alerts(transport, session, ids)
    all_rows = [
        {
            "id": _id_of(alert),
            "severity": text(alert.get("severity_name")) or "unknown",
            "tactic": text(alert.get("tactic")) or "unknown",
            "hostname": _hostname_of(alert) or "unknown",
        }
        for alert in alerts
    ]
    shown = all_rows if rows is None else all_rows[:rows]
    next_position = offset + len(ids)
    more_remain = len(ids) >= page if count is None else next_position < count
    reachable = more_remain and next_position < ALERTS_WALL

    help = ["Run `falcon-axi detection show <id>` for the full detection"]
    value: dict[str, Any] = {"count": raw(f"{len(shown)} of {count if count is not None else 'unknown'} total")}
    if reachable:
        continuation = encode_cursor(next_position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
        if session.member_cid:
            help.append("Supply the same tenant selection used for this invocation when continuing")
    elif more_remain:
        help.append(
            f"Narrow the filter so the result set fits under {ALERTS_WALL}, for example by "
            "shortening `--since` or adding `--severity`"
        )
        help.append(
            "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` pagination, "
            "which falcon-axi v1 does not register, so those rows are not reachable through this CLI"
        )
    value["detections"] = shown
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def show_detection(transport: Transport, session: Session, id: str, full: bool) -> CommandOutput:
    """`detection show <id>`: hydrate one composite id into the detail view (§10.4)."""
    alerts = _hydrate_alerts(transport, session, [id])
    if not alerts:
        raise CliError(
            "NOT_FOUND",
            "no detection matched that identifier",
            [
                "Run `falcon-axi detection list` to see current detection identifiers",
                "A composite id looks like `ldt:<agent id>:<detection id>`",
            ],
        )
    alert = alerts[0]
    cmdline = text(alert.get("cmdline"))
    rendered = None if cmdline is None else (cmdline, False) if full else truncate(cmdline)
    help: list[str] = []
    if rendered is not None and rendered[1]:
        help.append(f"Run `falcon-axi detection show {id} --full` to see the complete command line")
    device = _device_id_of(alert)
    detail: dict[str, Any] = {
        "id": _id_of(alert),
        "severity": _severity_of(alert),
        "tactic": text(alert.get("tactic")) or "unknown",
        "technique": text(alert.get("technique")) or "unknown",
        "hostname": _hostname_of(alert) or "unknown",
    }
    if device:
        detail["device_id"] = device
    detail["status"] = text(alert.get("status")) or "unknown"
    detail["first_seen"] = text(alert.get("created_timestamp")) or "unknown"
    if rendered is not None:
        detail["cmdline"] = rendered[0]
    return CommandOutput(value={"detection": detail}, help=tuple(help))
