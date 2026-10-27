"""Discover inventory reads, distinct from the Falcon sensor-host collection."""

import shlex
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_after, decode_offset, encode_cursor
from falcon_axi.domain import (
    DEFAULT_LIMIT,
    EXACT_MATCH_HINT,
    CommandOutput,
    after_token,
    parse_fields,
    rate_limit_note,
    resources,
    text,
    total,
)
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, redact, truncate
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, RequestArgs

# CrowdStrike's domain.DiscoverAPIApplication schema; unknown response fields still pass through by default.
APPLICATION_FIELDS = (
    "id",
    "name",
    "version",
    "vendor",
    "host",
    "account_name",
    "account_type",
    "admin_privileges",
    "architectures",
    "browser_extension",
    "category",
    "cid",
    "dev_package",
    "discovery_methods",
    "extension_id",
    "first_seen_timestamp",
    "groups",
    "homepage",
    "host_application",
    "ide_extension",
    "installation_paths",
    "installation_timestamp",
    "is_malicious",
    "is_normalized",
    "is_suspicious",
    "last_published",
    "last_updated_timestamp",
    "last_used_file_hash",
    "last_used_file_name",
    "last_used_timestamp",
    "last_used_user_name",
    "last_used_user_sid",
    "local_admin_privileges",
    "malicious_indicators",
    "name_vendor",
    "name_vendor_version",
    "registry_latest_version_available",
    "software_type",
    "store_listing",
    "store_listing_status",
    "suspicious_indicators",
    "threat_level",
    "versioning_scheme",
)
APPLICATION_FACETS = ("browser_extension", "host_info", "install_usage", "dev_package", "ide_extension", "llm", "mcp")


def _application_rows(ctx: Invocation, entries: list[Any], help: list[str]) -> list[dict[str, Any]]:
    fields = parse_fields(ctx.text("fields") or "", APPLICATION_FIELDS, ()) if "fields" in ctx.flags else ()
    shortened = False

    def preview(value: Any) -> Any:
        nonlocal shortened
        if isinstance(value, str) and not ctx.flags.get("full"):
            result = truncate(value, 500)
            shortened |= result.truncated
            return result.text
        if isinstance(value, Mapping):
            return {key: preview(entry) for key, entry in value.items()}
        if isinstance(value, list):
            return [preview(entry) for entry in value]
        return value

    rows = [
        preview(redact({name: entry.get(name) for name in fields} if fields else dict(entry)))
        for entry in entries
        if isinstance(entry, Mapping)
    ]
    if shortened:
        cursor = ctx.text("cursor")
        page = f" --cursor {shlex.quote(cursor)}" if cursor else ""
        help.append(f"Run `{ctx.suggestion}{page} --full` for untruncated application fields")
    return rows


def _request(ctx: Invocation, operation: OperationId, query: Mapping[str, Any]) -> FalconResponse:
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, operation, ctx.spec.name.split()[0])
    return response


def _list(ctx: Invocation) -> CommandOutput:
    noun = ctx.spec.name.split()[0]
    operation = ctx.spec.operations[0]
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    token_model = noun != "login"
    if filter is None and token_model:
        filter = "id:'*'" if noun == "asset" else "name:'*'"
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=filter,
        model="token" if token_model else "offset",
    )
    query: dict[str, Any] = {"limit": ctx.limit}
    if noun == "application":
        query["facet"] = APPLICATION_FACETS
    cursor = ctx.text("cursor")
    offset = 0
    if token_model:
        if cursor:
            query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    else:
        offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
        query["offset"] = offset
    if filter:
        query["filter"] = filter
    response = _request(ctx, operation, query)
    entries = resources(response)
    count = total(response)
    position: str | int | None = after_token(response) if token_model else None
    if not token_model:
        ids = [entry for entry in entries if isinstance(entry, str)]
        next_offset = offset + len(ids)
        if ids and (next_offset < count if count is not None else len(ids) >= ctx.limit):
            position = next_offset
        if ids:
            hydrated = _request(ctx, "get_logins", {"ids": tuple(ids)})
            by_id = {entry.get("id"): entry for entry in resources(hydrated) if isinstance(entry, Mapping)}
            entries = [by_id[id] for id in ids if id in by_id]
        else:
            entries = []
    columns = {
        "asset": ("id", "hostname", "entity_type", "platform_name"),
        "login": ("id", "username", "hostname", "login_timestamp"),
    }.get(noun, ())
    key = f"{noun}s"
    help = ["Run `falcon-axi asset show <id>` for asset details"] if noun == "asset" else []
    if noun == "application":
        rows = _application_rows(ctx, entries, help)
        if not rows:
            help.append(EXACT_MATCH_HINT)
    else:
        rows = [
            {column: text(entry.get(column)) or "unknown" for column in columns}
            for entry in entries
            if isinstance(entry, Mapping)
        ]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    if position is not None:
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        full = " --full" if ctx.flags.get("full") else ""
        help.append(f"Run `{ctx.suggestion}{full} --cursor {continuation}` for the next page")
    value[key] = rows if rows else raw(f"0 {key} returned for this Discover query")
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def _show_asset(ctx: Invocation) -> CommandOutput:
    response = _request(ctx, "get_hosts", {"ids": (ctx.positionals[0],)})
    assets = [entry for entry in resources(response) if isinstance(entry, Mapping)]
    if not assets:
        raise CliError(
            "NOT_FOUND",
            "no asset matched that identifier",
            ["Run `falcon-axi asset list` to see current Discover asset identifiers"],
        )
    asset = assets[0]
    columns = (
        "id",
        "hostname",
        "entity_type",
        "platform_name",
        "os_version",
        "aid",
        "criticality",
        "current_local_ip",
        "external_ip",
        "first_seen_timestamp",
        "last_seen_timestamp",
    )
    value: dict[str, Any] = {key: text(asset.get(key)) or "unknown" for key in columns}
    interfaces = asset.get("network_interfaces")
    value["mac_addresses"] = (
        [
            address
            for interface in interfaces
            if isinstance(interface, Mapping)
            if (address := text(interface.get("mac_address")))
        ]
        if isinstance(interfaces, list)
        else []
    )
    return CommandOutput(value={"asset": value}, help=())


def _iot_list(ctx: Invocation) -> CommandOutput:
    context = CursorContext(
        operation="query_iot_hostsV2",
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=ctx.text("filter"),
        model="token",
    )
    query: dict[str, Any] = {"limit": ctx.limit}
    if ctx.text("filter"):
        query["filter"] = ctx.text("filter")
    cursor = ctx.text("cursor")
    if cursor:
        query["after"] = decode_after(cursor, context, ctx.credential.client_secret)
    args = RequestArgs(
        base_url=ctx.session.base_url,
        token=ctx.session.token,
        allow_unknown_origin=ctx.session.allow_unknown_origin,
        query=query,
    )
    response = ctx.transport.request("query_iot_hostsV2", args)
    if response.status != 200:
        raise translate_falcon_error(response, "query_iot_hostsV2", "IoT assets")
    ids = [entry for entry in resources(response) if isinstance(entry, str)]
    if not ids:
        return CommandOutput({"iot": raw("no more IoT assets" if cursor else "0 IoT assets matching this query")}, ())
    details = ctx.transport.request(
        "get_iot_hosts",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": tuple(ids)},
        ),
    )
    if details.status not in (200, 404):
        raise translate_falcon_error(details, "get_iot_hosts", "IoT assets")
    by_id = {entry["id"]: entry for entry in resources(details) if isinstance(entry, Mapping) and entry.get("id")}
    rows = [
        {
            "id": id,
            "hostname": by_id[id].get("hostname", "unknown"),
            "device_type": by_id[id].get("device_type", "unknown"),
            "device_family": by_id[id].get("device_family", "unknown"),
        }
        for id in ids
        if id in by_id
    ]
    count = total(response)
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total"), "iot": rows}
    help = []
    after = after_token(response)
    if after:
        continuation = encode_cursor(after, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value, tuple(help))


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec(
        name="asset list",
        help="\n".join(
            [
                "falcon-axi asset list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Discover managed and unmanaged assets, distinct from Falcon sensor hosts.",
                "--filter     raw FQL, including entity_type, hostname, platform_name, and criticality",
                "             default id:'*' (all Discover assets)",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 1000)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi asset list --filter \"entity_type:'managed'\"",
                "  falcon-axi asset list --filter \"entity_type:'unmanaged'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  asset list                list Discover managed and unmanaged assets",
        handler=_list,
        operations=("combined_hosts",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(1000, "Discover combined hosts"),
    ),
    CommandSpec(
        name="asset show",
        help="\n".join(
            [
                "falcon-axi asset show <id>",
                "",
                "Shows one Discover asset's platform, sensor association, network addresses, and observation times.",
                "Use the Discover id from asset list, which is distinct from a Falcon device id.",
                "Example: falcon-axi asset show synthetic-asset-01",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  asset show <id>           details for one Discover asset",
        handler=_show_asset,
        operations=("get_hosts",),
        positional=("asset identifier", "Run `falcon-axi asset list` to see current Discover asset identifiers"),
    ),
    CommandSpec(
        name="application list",
        help="\n".join(
            [
                "falcon-axi application list [--filter <FQL>] [--limit N] [--cursor <token>] [--fields <names>] [--full]",
                "",
                "Returns every available application field, including nested host and usage details.",
                "--filter     raw FQL on name, vendor, version, and host.hostname",
                "             default name:'*' (all named applications)",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 1000)",
                "--cursor     opaque continuation token from a previous call",
                "--fields     select comma-separated top-level response fields, e.g. id,name,version,host",
                "             replaces the full row; missing selected fields are null",
                "--full       print strings beyond the default 500-character preview",
                "",
                "Name/vendor/version matching is exact on the whole value and case-insensitive.",
                "Wildcards and partial names are not supported for searches; 0 rows does not prove absence.",
                "The default name:'*' is the broad inventory query, not a partial-name search.",
                "Use + for AND and lists for alternatives: name:['Node.js','Python'].",
                "Spotlight does not accept apps.* filters. For hosts affected by known CVEs, use:",
                "  falcon-axi vuln list --filter \"cve.id:['CVE-2026-0001']\" --fields product --all",
                "",
                "Examples:",
                "  falcon-axi application list --filter \"name:'Node.js'+version:'24.18.0'\" --fields name,version,host",
                "  falcon-axi application list --filter \"name:['Node.js','Python']\"",
                "  falcon-axi application list --filter \"host.hostname:'<hostname>'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  application list          list Discover applications",
        handler=_list,
        operations=("combined_applications",),
        flags=("filter", "limit", "cursor", "fields", "full"),
        value_flags=("filter", "limit", "cursor", "fields"),
        extra_fields=APPLICATION_FIELDS,
        limit_ceiling=(1000, "Discover combined applications"),
    ),
    CommandSpec(
        name="login list",
        help="\n".join(
            [
                "falcon-axi login list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Discover-observed logins across assets; host logins reads one sensor host's timeline.",
                "--filter     raw FQL, including username, hostname, login_status, and login_timestamp",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling 100)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi login list --filter \"login_type:'Interactive'\"",
                "  falcon-axi login list --filter \"login_status:'Failed'\"",
                "",
                "Read-only; requires Assets:read (Falcon Discover or Exposure Management).",
            ]
        ),
        summary="  login list                list Discover-observed logins across assets",
        handler=_list,
        operations=("query_logins", "get_logins"),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "Discover logins query"),
    ),
)

COMMAND_SPECS += (
    CommandSpec(
        name="iot list",
        handler=_iot_list,
        operations=("query_iot_hostsV2", "get_iot_hosts"),
        summary="  iot list                  list Discover IoT assets",
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "Discover IoT query"),
        help="\n".join(
            [
                "falcon-axi iot list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter  raw FQL, including device_family, device_class, and device_type",
                "--limit   rows in this call (default 20, ceiling 100)",
                "--cursor  opaque continuation token from a previous call",
                "",
                "Examples:",
                "  falcon-axi iot list",
                "  falcon-axi iot list --limit 50",
                "",
                "Read-only. Requires Falcon Discover IoT:read (license-gated).",
            ]
        ),
    ),
)
