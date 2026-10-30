"""Process details from IOCs and bounded lineage from ThreatGraph."""

import re
import shlex
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, encode_cursor
from falcon_axi.domain import CommandOutput, body_of, rate_limit_note
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, redact, truncate
from falcon_axi.response_diagnostics import upstream_invalid
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import QueryValue, RequestArgs

PROCESS_ID = re.compile(r"pid:[a-fA-F0-9]{32}:[0-9]+")
_FIELDS = (
    "command_line",
    "device_id",
    "file_name",
    "process_id",
    "process_id_local",
    "start_timestamp",
    "start_timestamp_raw",
    "stop_timestamp",
    "stop_timestamp_raw",
)
_FIND_PROCESSES = "Run `falcon-axi ioc processes <type:value> --host <device_id>` to find process identifiers"


def validate_process_id(value: str) -> None:
    if PROCESS_ID.fullmatch(value) is None:
        raise CliError("VALIDATION_ERROR", "process identifier must be pid:<32 hex device ID>:<decimal ID>", [_FIND_PROCESSES])


def _show(ctx: Invocation) -> CommandOutput:
    id = ctx.positionals[0]
    validate_process_id(id)
    response = ctx.transport.request(
        "entities_processes",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": (id,)},
        ),
    )
    if response.status == 404 or (response.status == 200 and response.body == []):
        raise CliError("NOT_FOUND", "no process matched that identifier", [_FIND_PROCESSES])
    if response.status != 200:
        raise translate_falcon_error(response, "entities_processes", "process details")
    if not isinstance(response.body, list) or any(not isinstance(entry, Mapping) for entry in response.body):
        raise upstream_invalid("Falcon returned malformed process details")
    record = next((entry for entry in response.body if entry.get("process_id") == id), None)
    if record is None:
        raise upstream_invalid("Falcon returned process details without the requested identifier")
    value = {field: record.get(field) if record.get(field) is not None else "unknown" for field in _FIELDS}
    value["command_line"] = redact(value["command_line"])
    shortened = False
    if not ctx.flags.get("full") and isinstance(value["command_line"], str):
        value["command_line"], shortened = truncate(value["command_line"])
    help = (f"Run `falcon-axi process show {id} --full` to see the complete command line",) if shortened else ()
    return CommandOutput({"process": value}, help)


def _tree_read(ctx: Invocation, operation: OperationId, query: dict[str, QueryValue]) -> Mapping[str, Any]:
    answer = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            query=query,
            path_params={"vertex_type": "processes"} if operation == "combined_summary_get" else None,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
        ),
    )
    if answer.status == 404:
        raise CliError("NOT_FOUND", "no process matched that graph identifier")
    if answer.status != 200:
        raise translate_falcon_error(answer, operation, "process trees")
    body = body_of(answer)
    records = body.get("resources")
    if body.get("errors") or not isinstance(records, list) or any(not isinstance(row, Mapping) for row in records):
        raise upstream_invalid("Falcon returned an invalid process graph response")
    return body


def _tree_summary(ctx: Invocation, identifier: str) -> Mapping[str, Any]:
    records = _tree_read(ctx, "combined_summary_get", {"ids": (identifier,)})["resources"]
    if not records:
        raise CliError("NOT_FOUND", "no process matched that graph identifier")
    for record in records:
        if record.get("id") == identifier:
            return record  # type: ignore[no-any-return]
    raise upstream_invalid("Falcon returned a different process graph identifier")


def _tree_parent(record: Mapping[str, Any]) -> str | None:
    edges = record.get("edges", {})
    parents = edges.get("parent_process", []) if isinstance(edges, Mapping) else None
    if not isinstance(parents, list) or len(parents) > 1:
        raise upstream_invalid("Falcon returned ambiguous process parent edges")
    if not parents:
        return None
    identifier = parents[0].get("id") if isinstance(parents[0], Mapping) else None
    if not isinstance(identifier, str) or not identifier:
        raise upstream_invalid("Falcon returned a process parent without an identifier")
    return identifier


def _tree_row(record: Mapping[str, Any], relation: str, full: bool) -> tuple[dict[str, Any], bool]:
    props = record.get("properties", {})
    if not isinstance(props, Mapping):
        raise upstream_invalid("Falcon returned invalid process properties")
    row = {"relation": relation, "id": record.get("id")}
    for key, source in (
        ("filename", "ImageFileName"),
        ("cmdline", "CommandLine"),
        ("sha256", "SHA256HashData"),
        ("start_time", "ProcessStartTime_formatted"),
    ):
        row[key] = props.get(source, "unknown")
    shortened = False
    if isinstance(row["cmdline"], str):
        row["cmdline"] = redact(row["cmdline"])
        if not full:
            row["cmdline"], shortened = truncate(row["cmdline"])
    return row, shortened


def _tree(ctx: Invocation) -> CommandOutput:
    identifier = ctx.positionals[0]
    context = CursorContext(
        operation="combined_edges_get",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=identifier,
        sort="child_process",
        model="token",
    )
    cursor = ctx.text("cursor")
    offset = decode_after(cursor, context, ctx.credential.client_secret) if cursor else None
    record = _tree_summary(ctx, identifier)
    rows = []
    seen = {identifier}
    shortened = False
    full = bool(ctx.flags.get("full"))
    for depth in range(6):
        row, cut = _tree_row(record, "process" if depth == 0 else f"ancestor_{depth}", full)
        rows.append(row)
        shortened |= cut
        parent = _tree_parent(record)
        if parent is None:
            ancestry = "no further parent recorded"
            break
        if parent in seen:
            ancestry = "cycle detected; ancestry stopped"
            break
        if depth == 5:
            ancestry = "depth limit reached; at most 5 ancestors shown"
            break
        seen.add(parent)
        record = _tree_summary(ctx, parent)
    query: dict[str, QueryValue] = {"ids": identifier, "edge_type": "child_process", "limit": 100}
    if offset is not None:
        query["offset"] = offset
    body = _tree_read(ctx, "combined_edges_get", query)
    children = []
    for child in body["resources"]:
        if not isinstance(child.get("id"), str) or not child["id"]:
            raise upstream_invalid("Falcon returned a process child without an identifier")
        row, cut = _tree_row(child, "child", full)
        children.append(row)
        shortened |= cut
    value: dict[str, Any] = {
        "lineage": rows,
        "ancestry": ancestry,
        "children": children if children else raw("no more child processes" if cursor else "0 child processes"),
        "child_count": len(children),
    }
    help = []
    meta = body.get("meta", {})
    pagination = meta.get("pagination", {}) if isinstance(meta, Mapping) else {}
    next_page = pagination.get("next_page") if isinstance(pagination, Mapping) else None
    if children and isinstance(next_page, str) and next_page:
        if next_page == offset:
            raise upstream_invalid("Falcon returned a non-advancing child cursor")
        token = encode_cursor(next_page, context, ctx.credential.client_secret)
        value["continuation_cursor"] = token
        suggestion = ctx.suggestion + (" --full" if full else "")
        help.append(f"Run `{suggestion} --cursor {token}` for the next child page")
    if shortened:
        suggestion = ctx.suggestion + (f" --cursor {shlex.quote(cursor)}" if cursor else "")
        help.append(f"Run `{suggestion} --full` for complete command lines")
    if note := rate_limit_note(ctx.session):
        value["rate_limit"] = raw(note)
    return CommandOutput(value, tuple(help))


COMMAND_SPECS = (
    CommandSpec(
        name="process show",
        handler=_show,
        operations=("entities_processes",),
        summary="  process show <pid-id>     read one observed process",
        positional=("process identifier", _FIND_PROCESSES),
        flags=("full",),
        help="\n".join(
            [
                "falcon-axi process show <pid-id> [--full]",
                "",
                "ID shape: pid:<32 hex device ID>:<decimal ID>; use ioc processes to find it.",
                "Returns command_line, device_id, file_name, process_id, process_id_local,",
                "start_timestamp, start_timestamp_raw, stop_timestamp, and stop_timestamp_raw.",
                "--full  expand the command line beyond its 800-character preview",
                "",
                "Examples:",
                "  falcon-axi process show pid:00000000000000000000000000000001:1234",
                "  falcon-axi process show pid:00000000000000000000000000000001:1234 --full",
                "",
                "Read-only; requires IOCs (Indicators of Compromise):read.",
                "Availability depends on the tenant's subscription and API client permissions.",
            ]
        ),
    ),
    CommandSpec(
        name="process tree",
        handler=_tree,
        operations=("combined_summary_get", "combined_edges_get"),
        summary="  process tree <pid-id>     process, up to five ancestors, and one child level",
        flags=("cursor", "full"),
        value_flags=("cursor",),
        positional=("process graph identifier", "Use the triggering_process_graph_id from `falcon-axi detection process <id>`"),
        help="\n".join(
            [
                "falcon-axi process tree <pid-id> [--cursor <token>] [--full]",
                "",
                "Shows the process first, then up to 5 ancestors in parent order, then one child level.",
                "Children use a fixed 100-edge page; --cursor continues children for the same process.",
                "--full    complete command lines (default preview 800 characters)",
                "--cursor  opaque child continuation token; lineage is read again on each page",
                "",
                "Examples:",
                "  falcon-axi process tree pid:synthetic-device:1234",
                "  falcon-axi process tree pid:synthetic-device:1234 --full",
                "",
                "Read-only; requires Threatgraph:read and a subscription with ThreatGraph API access.",
                "Response shape source: CrowdStrike SDK sample falconpy samples/threat_graph/threat_finder.py,",
                "not a resource schema in the API spec; source-matched and tested offline, not tenant-validated.",
            ]
        ),
    ),
)
