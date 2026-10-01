"""The hosts domain: pure functions from arguments to requests and responses to rows.

`host list` is the documented two-step read (§2.3): `QueryDevicesByFilter` returns device ids and
`PostDeviceDetailsV2` hydrates them, with the query-step order reapplied afterwards because an
entity endpoint may answer in any order. `host show` is the hydrate step alone. `host logins` is
one request per ten hosts: `QueryDeviceLoginHistoryV2` takes the device ids in its body.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import falcon_messages, translate_falcon_error
from falcon_axi.fql import HostQuery, describe_host_query, host_filter, window
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs, Transport

#: Documented Hosts limits (docs/design/v1.md §7.3): query [1-5000], hydrate maximum 5000 ids.
QUERY_CEILING = 5_000
HYDRATE_CHUNK = 5_000
#: The cited Hosts wall: a captured 400 reads `limit + offset must be less than 10000` (§7.1).
HOSTS_WALL = 9_999
#: Documented login-history limits: at most 10 device ids per request, and a limit of [1-100] that
#: Falcon applies to each host separately (observed live: two hosts at limit 1 return two rows).
LOGIN_HISTORY_CHUNK = 10
LOGIN_CEILING = 100
#: Falcon's own window when `from` is omitted (documented default `now-7d`).
LOGIN_DEFAULT_SINCE = "7d"

Device = Mapping[str, Any]


def _device_id_of(device: Device) -> str:
    return text(device.get("device_id")) or ""


def _platform_of(device: Device) -> str:
    return text(device.get("platform_name")) or "unknown"


def _query_device_ids(
    transport: Transport, session: Session, filter: str | None, limit: int, offset: int
) -> tuple[list[str], int | None]:
    query: dict[str, str | int] = {"limit": limit, "offset": offset}
    if filter:
        query["filter"] = filter
    response = transport.request(
        "QueryDevicesByFilter",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "QueryDevicesByFilter", "hosts")
    return [id for id in resources(response) if isinstance(id, str)], total(response)


def _hydrate_devices(transport: Transport, session: Session, ids: Sequence[str]) -> list[Device]:
    by_id: dict[str, Device] = {}
    for index in range(0, len(ids), HYDRATE_CHUNK):
        chunk = list(ids[index : index + HYDRATE_CHUNK])
        response = transport.request(
            "PostDeviceDetailsV2",
            RequestArgs(
                base_url=session.base_url,
                token=session.token,
                allow_unknown_origin=session.allow_unknown_origin,
                body={"ids": chunk},
            ),
        )
        if response.status != 200:
            raise translate_falcon_error(response, "PostDeviceDetailsV2", "hosts")
        for entry in resources(response):
            if not isinstance(entry, Mapping):
                continue
            id = _device_id_of(entry)
            if id:
                by_id[id] = entry
    return [by_id[id] for id in ids if id in by_id]


def _cursor_context(session: Session, credential: Credential, filter: str | None) -> CursorContext:
    return CursorContext(
        operation="QueryDevicesByFilter",
        client_id=credential.client_id,
        query=filter,
        origin=session.base_url,
        member_cid=session.member_cid,
        model="offset",
    )


def _wall_help() -> list[str]:
    return [
        f"Narrow the filter so the result set fits under {HOSTS_WALL + 1}, for example with `--platform` or `--since`",
        f"This endpoint refuses a read whose limit plus offset reaches {HOSTS_WALL + 1}, so the "
        "rows past that point are not reachable through this CLI",
    ]


def list_hosts(
    transport: Transport,
    session: Session,
    query: HostQuery,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
) -> CommandOutput:
    """`host list`: query ids, hydrate them, and render the four-field schema (§10.2)."""
    filter = host_filter(query)
    context = _cursor_context(session, credential, filter)
    offset = 0 if cursor is None else decode_offset(cursor, context, credential.client_secret)
    headroom = HOSTS_WALL - offset
    if headroom <= 0:
        raise CliError(
            "PAGINATION_LIMIT",
            f"this read reached the {HOSTS_WALL + 1} limit plus offset boundary Falcon enforces for hosts",
            _wall_help(),
        )
    page = min(limit, headroom)
    ids, count = _query_device_ids(transport, session, filter, page, offset)
    describe = describe_host_query(query)

    if not ids:
        empty_help = (
            (f"Run `{suggestion} --since 30d` to widen the window",)
            if query.since
            else ("Run `falcon-axi host list` without filters to see the fleet",)
        )
        hosts = f"0 hosts matching {describe}" if describe else "0 hosts in this tenant"
        return CommandOutput(value={"hosts": raw(hosts)}, help=empty_help)

    devices = _hydrate_devices(transport, session, ids)
    rows = [
        {
            "device_id": _device_id_of(device),
            "hostname": text(device.get("hostname")) or "unknown",
            "platform": _platform_of(device),
            "last_seen": text(device.get("last_seen")) or "unknown",
        }
        for device in devices
    ]
    next_position = offset + len(ids)
    more_remain = len(ids) >= page if count is None else next_position < count
    reachable = more_remain and next_position < HOSTS_WALL

    help = [
        "Run `falcon-axi host show <device_id>` for full host details",
        "Run `falcon-axi vuln list --host <device_id>` for its open vulnerabilities",
    ]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    if reachable:
        continuation = encode_cursor(next_position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
        if session.member_cid:
            help.append("Supply the same tenant selection used for this invocation when continuing")
    elif more_remain:
        help.extend(_wall_help())
    value["hosts"] = rows
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def show_host(transport: Transport, session: Session, id: str) -> CommandOutput:
    """`host show <device_id>`: hydrate one device id into the detail view (§10.2)."""
    devices = _hydrate_devices(transport, session, [id])
    if not devices:
        raise CliError(
            "NOT_FOUND",
            "no host matched that identifier",
            [
                "Run `falcon-axi host list` to see current device identifiers",
                "A device id is the agent id Falcon calls the AID",
            ],
        )
    device = devices[0]
    device_id = _device_id_of(device)
    detail: dict[str, Any] = {
        "device_id": device_id,
        "hostname": text(device.get("hostname")) or "unknown",
        "platform": _platform_of(device),
        "os_version": text(device.get("os_version")) or "unknown",
        "agent_version": text(device.get("agent_version")) or "unknown",
        # Containment state is reported as data; falcon-axi cannot change it (§10.2).
        "status": text(device.get("status")) or "unknown",
        "first_seen": text(device.get("first_seen")) or "unknown",
        "last_seen": text(device.get("last_seen")) or "unknown",
    }
    group = text(device.get("machine_domain")) or text(device.get("site_name"))
    if group:
        detail["domain"] = group
    return CommandOutput(
        value={"host": detail},
        help=(
            f"Run `falcon-axi vuln list --host {device_id}` for this host's open vulnerabilities",
            f"Run `falcon-axi detection list --filter \"device.hostname:'{detail['hostname']}'\"` for its detections",
        ),
    )


def host_logins(
    transport: Transport, session: Session, ids: Sequence[str], limit: int, since: str | None = None
) -> CommandOutput:
    """`host logins <device_id>...`: recent interactive logins per host, newest first as Falcon returns them."""
    unique = list(dict.fromkeys(ids))
    query: dict[str, str | int] = {"limit": limit}
    if since is not None:
        query["from"] = window(since)
    rows: list[dict[str, str]] = []
    saturated = False
    for index in range(0, len(unique), LOGIN_HISTORY_CHUNK):
        response = transport.request(
            "QueryDeviceLoginHistoryV2",
            RequestArgs(
                base_url=session.base_url,
                token=session.token,
                allow_unknown_origin=session.allow_unknown_origin,
                query=query,
                body={"ids": unique[index : index + LOGIN_HISTORY_CHUNK]},
            ),
        )
        if response.status == 400 and any("invalid device id" in message for message in falcon_messages(response)):
            raise CliError(
                "NOT_FOUND",
                "no host matched one of those identifiers",
                [
                    "Run `falcon-axi host list` to see current device identifiers",
                    "A device id is the agent id Falcon calls the AID",
                ],
            )
        if response.status != 200:
            raise translate_falcon_error(response, "QueryDeviceLoginHistoryV2", "host login history")
        for entry in resources(response):
            if not isinstance(entry, Mapping):
                continue
            device_id = _device_id_of(entry)
            logins = entry.get("recent_logins")
            logins = logins if isinstance(logins, list) else []
            saturated = saturated or len(logins) >= limit
            rows.extend(
                {
                    "device_id": device_id,
                    "user_name": text(login.get("user_name")) or "unknown",
                    "login_time": text(login.get("login_time")) or "unknown",
                }
                for login in logins
                if isinstance(login, Mapping)
            )

    hosts = f"{len(unique)} host{'' if len(unique) == 1 else 's'}"
    if not rows:
        return CommandOutput(
            value={"logins": raw(f"0 logins on {hosts} in the last {since or LOGIN_DEFAULT_SINCE}")},
            help=(
                "Run `falcon-axi host logins <device_id> --since 30d` to widen the window",
                "Run `falcon-axi host show <device_id>` to check when the host was last seen",
            ),
        )
    help = [
        f"Run `falcon-axi host show {unique[0]}` for full host details",
        "Run `falcon-axi host list --filter \"last_login_user:'<user_name>'\"` to find where a user last logged in",
    ]
    if saturated:
        help.append(f"A host returned its limit of {limit} logins: raise --limit (ceiling {LOGIN_CEILING}) or narrow --since")
    value: dict[str, Any] = {"count": raw(f"{len(rows)} logins across {hosts}"), "logins": rows}
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))
