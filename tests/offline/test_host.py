"""The hosts domain (docs/design/v1.md §2.3, §7.1, §10.2)."""

import re

from falcon_axi.cli import run
from falcon_axi.host import HOSTS_WALL
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

PAGE = [
    serve("QueryDevicesByFilter", fixture("hosts/query-page.json")),
    serve("PostDeviceDetailsV2", fixture("hosts/details-page.json")),
]


def test_host_list_queries_then_hydrates_and_renders_the_four_field_schema() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, exit_code = run(["host", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^count: 2 of 1174 total$", stdout, re.MULTILINE)
    assert "hosts[2]{device_id,hostname,platform,last_seen}:" in stdout
    assert len(recorded.operation_requests("QueryDevicesByFilter")) == 1
    assert recorded.operation_requests("PostDeviceDetailsV2")[0].body == {"ids": ["synthetic-device-01", "synthetic-device-02"]}
    assert "Run `falcon-axi host show <device_id>` for full host details" in stdout
    assert "Run `falcon-axi vuln list --host <device_id>` for its open vulnerabilities" in stdout


def test_the_hydrate_step_cannot_reorder_the_rows_the_query_step_ranked() -> None:
    def reversed_details(args: RequestArgs):
        page = fixture("hosts/details-page.json")
        return response(200, {"resources": list(reversed(page.body["resources"]))})

    recorded = RecordedTransport(
        [serve("QueryDevicesByFilter", fixture("hosts/query-page.json")), serve("PostDeviceDetailsV2", reversed_details)]
    )
    stdout, _ = run(["host", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    rows = [line for line in stdout.split("\n") if line.startswith("  synthetic-device-")]
    assert rows[0].startswith("  synthetic-device-01")


def test_the_shorthands_compose_one_fql_string_and_hostname_keeps_its_wildcard() -> None:
    recorded = RecordedTransport(PAGE)
    run(
        ["host", "list", "--hostname", "WIN-*", "--platform", "windows", "--status", "contained", "--since", "24h"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert recorded.operation_requests("QueryDevicesByFilter")[0].query["filter"] == (
        "hostname:'WIN-*'+platform_name:'Windows'+status:'contained'+last_seen:>'now-24h'"
    )


def test_an_unknown_platform_or_status_is_rejected_before_any_request() -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["host", "list", "--platform", "solaris"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "valid values for --platform: windows, mac, linux" in stdout
    status, _ = run(["host", "list", "--status", "quarantined"], recorded, dict(CREDENTIAL_ENV))
    assert "valid values for --status: normal, containment_pending, contained, lift_containment_pending" in status
    assert recorded.operation_requests("QueryDevicesByFilter") == []


def test_containment_state_is_reported_as_data_and_no_command_can_change_it() -> None:
    recorded = RecordedTransport([serve("PostDeviceDetailsV2", fixture("hosts/details-page.json"))])
    stdout, exit_code = run(["host", "show", "synthetic-device-02"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "status: contained" in stdout
    for verb in ("contain", "release", "update", "delete"):
        _, refused = run(["host", verb, "synthetic-device-02"], recorded, dict(CREDENTIAL_ENV))
        assert refused == 2


def test_an_empty_result_states_the_filter_that_produced_it() -> None:
    recorded = RecordedTransport([serve("QueryDevicesByFilter", fixture("hosts/query-empty.json"))])
    stdout, exit_code = run(["host", "list", "--platform", "linux", "--since", "24h"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "hosts: 0 hosts matching linux seen in the last 24h" in stdout
    assert "--since 30d" in stdout
    assert recorded.operation_requests("PostDeviceDetailsV2") == []


def test_a_page_is_requested_at_the_wall_headroom_rather_than_overshooting_it() -> None:
    """The cited Hosts rule refuses `limit + offset` reaching 10000, so the last page lands on it (§7.1)."""
    walked = RecordedTransport(
        [
            serve(
                "QueryDevicesByFilter",
                response(
                    200,
                    {
                        "meta": {"pagination": {"total": 24310}},
                        "resources": [f"synthetic-device-{index}" for index in range(5000)],
                    },
                ),
            ),
            serve("PostDeviceDetailsV2", response(200, {"resources": []})),
        ]
    )
    stdout, _ = run(["host", "list", "--limit", "5000"], walked, dict(CREDENTIAL_ENV))
    assert walked.operation_requests("QueryDevicesByFilter")[0].query["limit"] == 5000
    marker = "continuation_cursor: "
    cursor = next(line for line in stdout.split("\n") if line.startswith(marker))[len(marker) :]
    second = RecordedTransport(
        [
            serve("QueryDevicesByFilter", response(200, {"meta": {"pagination": {"total": 24310}}, "resources": []})),
        ]
    )
    run(["host", "list", "--limit", "5000", "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    requested = second.operation_requests("QueryDevicesByFilter")[0].query
    assert requested["offset"] == 5000
    assert requested["limit"] == HOSTS_WALL - 5000


def test_a_continuation_that_would_cross_the_wall_fails_with_pagination_limit() -> None:
    from falcon_axi.cursor import CursorContext, encode_cursor

    context = CursorContext(
        operation="QueryDevicesByFilter",
        client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
        origin="https://api.crowdstrike.com",
        model="offset",
    )
    cursor = encode_cursor(HOSTS_WALL, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    recorded = RecordedTransport([])
    stdout, exit_code = run(["host", "list", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: PAGINATION_LIMIT" in stdout
    assert recorded.operation_requests("QueryDevicesByFilter") == []


def test_a_detection_cursor_does_not_continue_a_host_read() -> None:
    from falcon_axi.cursor import CursorContext, encode_cursor

    context = CursorContext(
        operation="GetQueriesAlertsV2",
        client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
        origin="https://api.crowdstrike.com",
    )
    cursor = encode_cursor(20, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    stdout, exit_code = run(["host", "list", "--cursor", cursor], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "this cursor does not continue the current query" in stdout


def test_host_show_without_a_match_is_not_found_and_names_where_to_look() -> None:
    recorded = RecordedTransport([serve("PostDeviceDetailsV2", response(200, {"resources": []}))])
    stdout, exit_code = run(["host", "show", "synthetic-device-99"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: NOT_FOUND" in stdout
    assert "Run `falcon-axi host list` to see current device identifiers" in stdout


def test_a_scope_failure_on_hosts_names_the_hosts_read_scope() -> None:
    recorded = RecordedTransport([serve("QueryDevicesByFilter", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["host", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: SCOPE_DENIED" in stdout
    assert "Hosts:read" in stdout
    assert "Alerts:read" not in stdout


LOGINS = [serve("QueryDeviceLoginHistoryV2", fixture("hosts/login-history.json"))]


def test_host_logins_renders_one_row_per_login_and_sends_the_documented_request() -> None:
    recorded = RecordedTransport(LOGINS)
    stdout, exit_code = run(
        ["host", "logins", "synthetic-device-01", "--since", "24h", "--limit", "5"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 0
    assert re.search(r"^count: 2 logins on 1 host$", stdout, re.MULTILINE)
    assert "logins[2]{device_id,user_name,login_time}:" in stdout
    assert 'synthetic-device-01,synthetic-svc-backup,"2026-10-01T13:07:57Z"' in stdout
    assert "synthetic-cid" not in stdout
    (request,) = recorded.operation_requests("QueryDeviceLoginHistoryV2")
    assert request.body == {"ids": ["synthetic-device-01"]}
    assert request.query == {"limit": 5, "from": "now-24h"}


def test_host_logins_without_since_leaves_falcons_own_window_in_force() -> None:
    recorded = RecordedTransport(LOGINS)
    run(["host", "logins", "synthetic-device-01"], recorded, dict(CREDENTIAL_ENV))
    assert recorded.operation_requests("QueryDeviceLoginHistoryV2")[0].query == {"limit": 20}


def test_host_logins_rejects_multiple_ids_including_duplicates_before_authentication() -> None:
    for second in ("synthetic-device-01", "synthetic-device-02"):
        recorded = RecordedTransport(LOGINS)
        stdout, exit_code = run(["host", "logins", "synthetic-device-01", second], recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 2
        assert "host logins requires exactly one device identifier" in stdout
        assert recorded.requests == []


def test_a_host_that_returns_its_limit_says_more_may_exist() -> None:
    recorded = RecordedTransport(LOGINS)
    stdout, _ = run(["host", "logins", "synthetic-device-01", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert "returned its limit of 2 logins" in stdout
    stdout, _ = run(["host", "logins", "synthetic-device-01", "--limit", "3"], RecordedTransport(LOGINS), dict(CREDENTIAL_ENV))
    assert "returned its limit" not in stdout


def test_an_empty_login_window_states_the_window_that_produced_it() -> None:
    recorded = RecordedTransport([serve("QueryDeviceLoginHistoryV2", fixture("hosts/login-history-empty.json"))])
    stdout, exit_code = run(["host", "logins", "synthetic-device-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "logins: 0 logins on 1 host in the last 7d" in stdout
    assert "--since 30d" in stdout


def test_an_unrecognised_device_id_is_not_found_without_echoing_falcons_message() -> None:
    recorded = RecordedTransport([serve("QueryDeviceLoginHistoryV2", fixture("hosts/login-history-invalid-id.json"))])
    stdout, exit_code = run(["host", "logins", "synthetic-device-99"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: NOT_FOUND" in stdout
    assert "invalid device id" not in stdout


def test_host_logins_is_refused_before_any_request_without_an_id_or_with_a_bad_window_or_limit() -> None:
    recorded = RecordedTransport([])
    _, none = run(["host", "logins"], recorded, dict(CREDENTIAL_ENV))
    _, window = run(["host", "logins", "synthetic-device-01", "--since", "yesterday"], recorded, dict(CREDENTIAL_ENV))
    _, ceiling = run(["host", "logins", "synthetic-device-01", "--limit", "101"], recorded, dict(CREDENTIAL_ENV))
    assert (none, window, ceiling) == (2, 2, 2)
    assert recorded.operation_requests("QueryDeviceLoginHistoryV2") == []


def test_host_logins_scope_denied_names_hosts_read() -> None:
    recorded = RecordedTransport([serve("QueryDeviceLoginHistoryV2", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["host", "logins", "synthetic-device-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: SCOPE_DENIED" in stdout
    assert 'required_scopes[1]: "Hosts:read"' in stdout
