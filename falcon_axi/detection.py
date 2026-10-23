"""The detections domain: pure functions from arguments to requests and responses to rows."""

import shlex
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.command import CommandSpec, Invocation, string
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, Position, decode_offset, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, parse_fields, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import PRODUCTS, SEVERITIES, STATUSES, DetectionQuery, describe_detection_query, detection_filter
from falcon_axi.identity import is_account_subject
from falcon_axi.render import raw, redact, truncate
from falcon_axi.transport.types import RequestArgs, Transport
from falcon_axi.walk import Page, max_rows_of, offset_page, walk

#: Documented Alerts limits (docs/design/v1.md §7.3, §2.3).
QUERY_CEILING = 10_000
HYDRATE_CHUNK = 1_000
#: v1's defensive Alerts result stop; unverified and open in §17.12.
ALERTS_WALL = 10_000

EXTRA_FIELDS = ("status", "technique", "created_timestamp")

Alert = Mapping[str, Any]


def _hostname_of(alert: Alert) -> str | None:
    device = alert.get("device")
    from_device = text(device.get("hostname")) if isinstance(device, Mapping) else None
    return from_device or text(alert.get("hostname")) or text(alert.get("source_endpoint_host_name"))


def _account_of(alert: Alert) -> str | None:
    """The identity the alert is about. Endpoint alerts carry none; Identity Protection alerts carry `source_account_*`."""
    return text(alert.get("source_account_name")) or text(alert.get("source_account_upn"))


def _account_id_of(alert: Alert) -> str | None:
    return text(alert.get("source_account_object_guid"))


def _is_identity(alert: Alert) -> bool:
    return _account_of(alert) is not None or text(alert.get("product")) == "idp"


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
    max_rows: int | None = None,
    fields: Sequence[str] = (),
) -> CommandOutput:
    """`detection list`: query ids and hydrate them under the schema contract in docs/design/v1.md §10.2."""
    filter = detection_filter(query)
    context = _cursor_context(session, credential, filter)
    offset = 0 if cursor is None else decode_offset(cursor, context, credential.client_secret)
    headroom = ALERTS_WALL - offset
    wall_help = [
        f"Narrow the filter so the result set fits under {ALERTS_WALL}, for example by "
        "shortening `--since` or adding `--severity`",
        "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` "
        "pagination, which falcon-axi v1 does not register",
    ]
    if headroom <= 0:
        raise CliError(
            "PAGINATION_LIMIT",
            f"this read reached the {ALERTS_WALL} result boundary falcon-axi enforces for Alerts",
            wall_help,
        )

    def fetch(size: int, position: Position | None) -> Page[Alert]:
        assert isinstance(position, int)
        ids, count = _query_alert_ids(transport, session, filter, size, position)
        return offset_page(_hydrate_alerts(transport, session, ids), count, position, len(ids), size)

    result = walk(fetch, offset, limit, QUERY_CEILING, max_rows, ALERTS_WALL, tuple(wall_help))
    alerts, count = result.items, result.total
    describe = describe_detection_query(query)

    if not result.consumed:
        if offset > 0:
            return CommandOutput(value={"detections": raw("no more detections")}, help=())
        empty_help = (
            (f"Run `{suggestion} --since 7d` to widen the window",)
            if query.since
            else ("Run `falcon-axi detection list` without filters to see what is firing",)
        )
        detections = f"0 detections matching {describe}" if describe else "0 detections in this tenant"
        return CommandOutput(value={"detections": raw(detections)}, help=empty_help)

    with_identity = any(_is_identity(alert) for alert in alerts)
    all_rows = []
    for alert in alerts:
        row = {
            "id": _id_of(alert),
            "severity": text(alert.get("severity_name")) or "unknown",
            "tactic": text(alert.get("tactic")) or "unknown",
            "hostname": _hostname_of(alert) or ("n/a" if _is_identity(alert) else "unknown"),
        }
        if with_identity:
            row["account"] = _account_of(alert) or "n/a"
            row["account_id"] = _account_id_of(alert) or "n/a"
            row["device_id"] = _device_id_of(alert) or "n/a"
            row["product"] = text(alert.get("product")) or "n/a"
        for name in fields:
            row[name] = text(alert.get(name)) or "unknown"
        all_rows.append(row)
    shown = all_rows if rows is None else all_rows[:rows]
    reachable = result.next_position is not None

    help = ["Run `falcon-axi detection show <id>` for the full detection"]
    value: dict[str, Any] = {"count": raw(f"{len(shown)} of {count if count is not None else 'unknown'} total")}
    result.partial(value, help, reachable)
    if reachable:
        assert result.next_position is not None
        continuation = encode_cursor(result.next_position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    elif result.more_remain:
        help.append(wall_help[0])
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
                "A composite id looks like `<cid>:ind:<id>`; copy it from the id column of `detection list`",
            ],
        )
    alert = alerts[0]
    cmdline = text(alert.get("cmdline"))
    rendered = None if cmdline is None else (cmdline, False) if full else truncate(cmdline)
    help: list[str] = []
    if rendered is not None and rendered[1]:
        help.append(f"Run `falcon-axi detection show {id} --full` to see the complete command line")
    device = _device_id_of(alert)
    account = _account_of(alert)
    account_id = _account_id_of(alert)
    hostname = _hostname_of(alert)
    detail: dict[str, Any] = {
        "id": _id_of(alert),
        "severity": _severity_of(alert),
        "tactic": text(alert.get("tactic")) or "unknown",
        "technique": text(alert.get("technique")) or "unknown",
    }
    if hostname or not _is_identity(alert):
        detail["hostname"] = hostname or "unknown"
    if device:
        detail["device_id"] = device
    if text(alert.get("product")):
        detail["product"] = text(alert.get("product"))
    if account:
        detail["account"] = account
    if account_id:
        detail["account_id"] = account_id
    pivot = account_id or (account if account and is_account_subject(account) else None)
    if pivot:
        help.append(f"Run `falcon-axi identity activity {shlex.quote(pivot)}` to see what this account did")
    detail["status"] = text(alert.get("status")) or "unknown"
    detail["first_seen"] = text(alert.get("created_timestamp")) or "unknown"
    if rendered is not None:
        detail["cmdline"] = rendered[0]
    return CommandOutput(value={"detection": detail}, help=tuple(help))


def detection_process(transport: Transport, session: Session, id: str, full: bool) -> CommandOutput:
    """Project only the lineage recorded on the alert, without fetching a process graph."""
    alerts = _hydrate_alerts(transport, session, [id])
    if not alerts:
        raise CliError(
            "NOT_FOUND",
            "no detection matched that identifier",
            ["Run `falcon-axi detection list` to see current detection identifiers"],
        )
    alert = alerts[0]
    fields = ("filename", "filepath", "cmdline", "sha256", "process_id")
    value: dict[str, Any] = {
        "id": _id_of(alert),
        "triggering_process_graph_id": text(alert.get("triggering_process_graph_id")) or "unknown",
    }
    lineage = (
        ("triggering", alert),
        ("parent", alert.get("parent_details")),
        ("grandparent", alert.get("grandparent_details")),
    )
    if not any(text(alert.get(field)) for field in (*fields, "triggering_process_graph_id")) and not any(
        isinstance(entry, Mapping) and entry for _, entry in lineage[1:]
    ):
        value["processes"] = raw("no process recorded for this detection")
        return CommandOutput(value=value, help=())
    rows = []
    shortened = False
    for relation, entry in lineage:
        if not isinstance(entry, Mapping) or not entry:
            value[relation] = raw(f"no {relation} recorded")
            continue
        row = {"relation": relation, **{field: text(entry.get(field)) or "unknown" for field in fields}}
        # Redact before truncating so a preview cannot cut a secret's closing marker off.
        row["cmdline"] = redact(row["cmdline"])
        if not full:
            row["cmdline"], truncated = truncate(row["cmdline"])
            shortened |= truncated
        rows.append(row)
    value["processes"] = rows
    help = (f"Run `falcon-axi detection process {shlex.quote(id)} --full` to see complete command lines",) if shortened else ()
    return CommandOutput(value=value, help=help)


def summarize_detections(transport: Transport, session: Session, query: DetectionQuery) -> CommandOutput:
    """Count severity terms server-side without walking the Alerts result window (§10.3)."""
    spec: dict[str, Any] = {
        "name": "severity",
        "type": "terms",
        "field": "severity_name",
        "size": 100,
        "missing": "unknown",
    }
    filter = detection_filter(query)
    if filter:
        spec["filter"] = filter
    response = transport.request(
        "PostAggregatesAlertsV2",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            body=[spec],
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "PostAggregatesAlertsV2", "detection summary")
    invalid = CliError(
        "UPSTREAM_ERROR",
        "Falcon returned an incomplete detection summary",
        ["Retry shortly; report this command if the problem persists"],
    )
    body = response.body
    if not isinstance(body, Mapping) or body.get("errors") or not isinstance(body.get("resources"), list):
        raise invalid
    aggregates = body["resources"]
    if not aggregates:
        buckets: Any = []
        other = 0
    else:
        aggregate = next((item for item in aggregates if isinstance(item, Mapping) and item.get("name") == "severity"), {})
        buckets = aggregate.get("buckets")
        other = aggregate.get("sum_other_doc_count", 0)
        if not isinstance(buckets, list) or type(other) is not int or other < 0:
            raise invalid
    rows = []
    for bucket in buckets:
        if (
            not isinstance(bucket, Mapping)
            or not isinstance(bucket.get("label"), str)
            or type(bucket.get("count")) is not int
            or bucket["count"] < 0
        ):
            raise invalid
        rows.append({"severity": bucket["label"], "count": bucket["count"]})
    if not rows and not other:
        describe = describe_detection_query(query)
        empty = f"0 detections matching {describe}" if describe else "0 detections in this tenant"
        return CommandOutput(value={"detections": raw(empty)}, help=())
    value: dict[str, Any] = {"severities": rows}
    if other:
        value["other_count"] = other
    return CommandOutput(value=value, help=())


def _detection_summary(ctx: Invocation) -> CommandOutput:
    return summarize_detections(ctx.transport, ctx.session, _detection_query_of(ctx.flags))


def _detection_list(ctx: Invocation) -> CommandOutput:
    return list_detections(
        ctx.transport,
        ctx.session,
        query=_detection_query_of(ctx.flags),
        limit=ctx.limit,
        cursor=ctx.text("cursor"),
        credential=ctx.credential,
        suggestion=ctx.suggestion,
        max_rows=max_rows_of(ctx.flags),
        fields=parse_fields(ctx.text("fields") or "", ctx.spec.extra_fields, ctx.spec.default_fields)
        if "fields" in ctx.flags
        else (),
    )


def _detection_show(ctx: Invocation) -> CommandOutput:
    return show_detection(ctx.transport, ctx.session, ctx.positionals[0], bool(ctx.flags.get("full")))


def _detection_process(ctx: Invocation) -> CommandOutput:
    return detection_process(ctx.transport, ctx.session, ctx.positionals[0], bool(ctx.flags.get("full")))


def _detection_query_of(flags: Mapping[str, str | bool]) -> DetectionQuery:
    return DetectionQuery(
        filter=string(flags.get("filter")),
        severity=string(flags.get("severity")),
        status=string(flags.get("status")),
        since=string(flags.get("since")),
        product=string(flags.get("product")),
    )


COMMAND_SPECS = (
    CommandSpec(
        name="detection summary",
        help="\n".join(
            [
                "falcon-axi detection summary [--severity <name>] [--status <name>] [--product <name>] "
                "[--since <window>] [--filter <FQL>]",
                "",
                f"--severity   one of {', '.join(SEVERITIES)}",
                f"--status     one of {', '.join(STATUSES)}",
                f"--product    one of {', '.join(PRODUCTS)}",
                "--since      relative window such as 24h or 7d",
                "--filter     raw FQL, combined with the shorthand filters as in detection list",
                "",
                "Counts by severity across matching alerts, including hidden alerts, without listing them.",
                "other_count, when present, counts alerts in buckets omitted by Falcon.",
                "Examples:",
                "  falcon-axi detection summary --since 24h",
                "  falcon-axi detection summary --product idp --status new",
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        ),
        summary="  detection summary         counts of detections by severity",
        handler=_detection_summary,
        operations=("PostAggregatesAlertsV2",),
        flags=("filter", "severity", "status", "product", "since"),
        value_flags=("filter", "severity", "status", "product", "since"),
    ),
    CommandSpec(
        name="detection list",
        help="\n".join(
            [
                "falcon-axi detection list [--severity <name>] [--status <name>] [--product <name>] [--since <window>] "
                "[--filter <FQL>] [--limit N] [--cursor <token>] [--all] [--max-rows N] [--fields <names>]",
                "",
                f"--severity   one of {', '.join(SEVERITIES)}",
                f"--status     one of {', '.join(STATUSES)}",
                f"--product    one of {', '.join(PRODUCTS)}; epp is endpoint alerts, idp is Identity Protection",
                "--since      relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted, relative dates are lowercase",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "--all        walk pages; page size is independent of --limit",
                "--max-rows   row budget (default 1000; requires --all)",
                f"--fields     extra columns, comma-separated: {', '.join(EXTRA_FIELDS)}",
                "",
                "Filterable fields include severity_name, status, product, tactic, technique, created_timestamp,",
                "and device.hostname.",
                "Identity Protection alerts have no device: their rows show the endpoint they came from as hostname",
                "(or `n/a`) and add account, account_id, device_id, and product columns when the page holds any.",
                "Examples:",
                "  falcon-axi detection list --severity high --since 24h",
                "  falcon-axi detection list --product idp --since 7d",
                "  falcon-axi detection list --filter \"severity_name:'Critical'+status:'new'\"",
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        ),
        summary="  detection list            list detections from the Falcon Alerts collection",
        handler=_detection_list,
        operations=("GetQueriesAlertsV2", "PostEntitiesAlertsV2"),
        flags=("filter", "severity", "status", "product", "since", "limit", "cursor", "all", "max-rows", "fields"),
        value_flags=("filter", "severity", "status", "product", "since", "limit", "cursor", "max-rows", "fields"),
        limit_ceiling=(QUERY_CEILING, "Alerts query"),
        extra_fields=EXTRA_FIELDS,
        default_fields=("id", "severity", "tactic", "hostname"),
    ),
    CommandSpec(
        name="detection show",
        help="\n".join(
            [
                "falcon-axi detection show <composite id> [--full]",
                "",
                "--full       print long fields such as the command line without truncation",
                "",
                'Example: falcon-axi detection show "ldt:aid:1234"',
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        ),
        summary="  detection show <id>       the full detail for one detection",
        handler=_detection_show,
        operations=("PostEntitiesAlertsV2",),
        flags=("full",),
        positional=("detection identifier", "Run `falcon-axi detection list` to see current detection identifiers"),
    ),
    CommandSpec(
        name="detection process",
        help="\n".join(
            [
                "falcon-axi detection process <composite id> [--full]",
                "",
                "--full       print command lines without the default 800-character truncation",
                "",
                "Show the triggering process, parent, and grandparent recorded on the alert.",
                "Rows contain relation, filename, filepath, cmdline, sha256, and process_id.",
                "triggering_process_graph_id is the alert's graph pivot; this view does not fetch a graph.",
                "Absent ancestors and alerts without a process are stated explicitly.",
                "Examples:",
                "  falcon-axi detection process 'ldt:synthetic-agent:1001'",
                "  falcon-axi detection process 'ldt:synthetic-agent:1001' --full",
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        ),
        summary="  detection process <id>    process lineage recorded on one detection",
        handler=_detection_process,
        operations=("PostEntitiesAlertsV2",),
        flags=("full",),
        positional=("detection identifier", "Run `falcon-axi detection list` to see current detection identifiers"),
    ),
)
