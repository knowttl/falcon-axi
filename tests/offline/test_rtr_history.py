"""R1 history reads and the closed RTR transport boundary, wholly offline."""

from dataclasses import replace

import pytest
import requests_mock
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.operations import OPERATIONS, _seal
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

LISTS = (
    ("session", "RTR_ListAllSessions", "sessions", 5000),
    ("audit", "RTRAuditSessions", "audit_sessions", 1000),
)


def test_session_list_preserves_query_order_total_and_post_hydration() -> None:
    recorded = RecordedTransport(
        [
            serve("RTR_ListAllSessions", fixture("rtr/ids.json")),
            serve("RTR_ListSessions", fixture("rtr/sessions.json")),
        ]
    )
    stdout, code = run(
        ["rtr", "session", "list", "--filter", "hostname:'SYNTHETIC-*'", "--limit", "2"],
        recorded,
        {**CREDENTIAL_ENV, "FALCON_AXI_READ_ONLY": "1"},
    )
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == "2 of 2 total"
    assert [row["id"] for row in parsed["sessions"]] == ["synthetic-session-01", "synthetic-session-02"]
    assert recorded.operation_requests("RTR_ListAllSessions")[0].query == {
        "filter": "hostname:'SYNTHETIC-*'",
        "limit": 2,
        "offset": 0,
    }
    assert recorded.operation_requests("RTR_ListSessions")[0].body == {
        "ids": ["synthetic-session-01", "synthetic-session-02"],
    }


def test_hydration_is_chunked_and_missing_entities_do_not_change_cursor_position() -> None:
    ids = [f"synthetic-session-{index}" for index in range(101)]

    def hydrate(args: RequestArgs):
        return response(200, {"resources": [{"id": id} for id in reversed(args.body["ids"]) if id != ids[0]]})

    recorded = RecordedTransport(
        [
            serve("RTR_ListAllSessions", response(200, {"resources": ids, "meta": {"pagination": {"total": 200}}})),
            serve("RTR_ListSessions", hydrate),
        ]
    )
    stdout, code = run(["rtr", "session", "list", "--limit", "101"], recorded, CREDENTIAL_ENV)
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == "100 of 200 total"
    assert [row["id"] for row in parsed["sessions"]] == ids[1:]
    assert [len(args.body["ids"]) for args in recorded.operation_requests("RTR_ListSessions")] == [100, 1]
    continued = RecordedTransport([serve("RTR_ListAllSessions", response(200, {"resources": []}))])
    _, code = run(["rtr", "session", "list", "--cursor", parsed["continuation_cursor"]], continued, CREDENTIAL_ENV)
    assert code == 0
    assert continued.operation_requests("RTR_ListAllSessions")[0].query["offset"] == 101


@pytest.mark.parametrize("noun,op,key,ceiling", LISTS)
@pytest.mark.parametrize("count", (None, 2))
def test_bounded_continuation_and_cursor_binding(noun: str, op: str, key: str, ceiling: int, count: int | None) -> None:
    listed = ["synthetic-session-01"] if noun == "session" else [{"id": "synthetic-session-01"}]
    recorded = RecordedTransport(
        [
            serve(op, response(200, {"resources": listed, "meta": {"pagination": {"total": count}}})),
            serve("RTR_ListSessions", fixture("rtr/sessions.json")),
        ]
    )
    argv = ["rtr", noun, "list", "--limit", "1"]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == f"1 of {count if count is not None else 'unknown'} total"
    cursor = parsed["continuation_cursor"]
    continued = RecordedTransport([serve(op, response(200, {"resources": []}))])
    stdout, code = run([*argv, "--cursor", cursor], continued, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)[key] == f"no more {key}"
    assert "continuation_cursor" not in decode(stdout)
    assert continued.operation_requests(op)[0].query == {"limit": 1, "offset": 1}
    refused = RecordedTransport([])
    stdout, code = run([*argv, "--cursor", cursor, "--filter", "hostname:'changed'"], refused, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert not refused.operation_requests(op)


def test_audit_reads_combined_records_without_hydration() -> None:
    recorded = RecordedTransport([serve("RTRAuditSessions", fixture("rtr/audit.json"))])
    stdout, code = run(["rtr", "audit", "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["audit_sessions"][0]["id"] == "synthetic-session-01"
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("noun,op,key,ceiling", LISTS)
def test_empty_history_skips_hydration(noun: str, op: str, key: str, ceiling: int) -> None:
    recorded = RecordedTransport([serve(op, response(200, {"resources": []}))])
    stdout, code = run(["rtr", noun, "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)[key] == f"0 {key} matching this query"
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("noun,op,key,ceiling", LISTS)
def test_limit_ceiling_fails_before_auth(noun: str, op: str, key: str, ceiling: int) -> None:
    recorded = RecordedTransport([])
    _, code = run(["rtr", noun, "list", "--limit", str(ceiling + 1)], recorded, CREDENTIAL_ENV)
    assert code == 2
    assert recorded.requests == []


@pytest.mark.parametrize(
    ("argv", "op", "scope"),
    (
        (["rtr", "session", "list"], "RTR_ListAllSessions", "Real time response:read"),
        (["rtr", "session", "show", "synthetic-session-01"], "RTR_ListSessions", "Real time response:read"),
        (["rtr", "audit", "list"], "RTRAuditSessions", "Real time response audit:read"),
    ),
)
def test_denied_history_names_scope_and_licence_remedies(argv: list[str], op: str, scope: str) -> None:
    recorded = RecordedTransport([serve(op, fixture("errors/403-scope.json"))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 1
    parsed = decode(stdout)
    assert parsed["code"] == "SCOPE_DENIED"
    assert scope in stdout
    assert "subscription" in stdout
    assert "Falcon console" in stdout


@pytest.mark.parametrize("full", (False, True))
def test_session_detail_redacts_before_truncation(full: bool) -> None:
    recorded = RecordedTransport(
        [
            serve(
                "RTR_ListSessions",
                response(
                    200,
                    {
                        "resources": [
                            {
                                "id": "synthetic-session-01",
                                "cid": "synthetic-sensitive",
                                "origin": "x" * 801,
                            }
                        ]
                    },
                ),
            )
        ]
    )
    stdout, code = run(
        ["rtr", "session", "show", "synthetic-session-01", *(["--full"] if full else [])], recorded, CREDENTIAL_ENV
    )
    assert code == 0
    assert decode(stdout)["rtr_session"]["cid"] == "[redacted]"
    assert "synthetic-sensitive" not in stdout
    assert ("801 chars total" in stdout) is not full
    assert recorded.operation_requests("RTR_ListSessions")[0].body == {"ids": ["synthetic-session-01"]}


@pytest.mark.parametrize(
    "op",
    (
        "RTR_InitSession",
        "RTR_ExecuteCommand",
        "RTR_CheckCommandStatus",
        "RTR_DeleteSession",
        "RTR_PulseSession",
        "RTR_ListFiles",
        "RTR_GetExtractedFileContents",
        "RTR_AggregateSessions",
        "BatchInitSessions",
        "BatchActiveResponderCmd",
        "BatchGetCmdStatus",
        "BatchGetCmd",
        "BatchRefreshSessions",
        "BatchCmd",
        "RTR_CheckActiveResponderCommandStatus",
        "RTR_DeleteFile",
        "RTR_ListFilesV2",
        "RTR_DeleteFileV2",
        "RTR_ListQueuedSessions",
        "RTR_DeleteQueuedSession",
        "RTR_ExecuteAdminCommand",
        "RTR_ExecuteActiveResponderCommand",
    ),
)
def test_non_history_operations_are_refused_before_send(op: str) -> None:
    with requests_mock.Mocker() as network:
        with pytest.raises(CliError) as error:
            HttpTransport().request(op, RequestArgs(base_url="https://api.crowdstrike.com", token="synthetic"))
        assert error.value.code == "READ_ONLY_VIOLATION"
        assert network.call_count == 0


@pytest.mark.parametrize(
    "path",
    (
        "/real-time-response/entities/sessions/v1",
        "/real-time-response/entities/command/v1",
        "/real-time-response/entities/sessions/GET/v2",
        "/real-time-response/queries/sessions/v1/extra",
        "/real-time-response/entities/files/v1",
        "/real-time-response/aggregates/sessions/GET/v1",
        "/real-time-response/queries/queued-sessions/v1",
        "/real-time-response/combined/batch-active-responder-command/v1",
        "/real-time-response/combined/batch-command/v1",
        "/real-time-response/combined/batch-get-command/v1",
        "/real-time-response/combined/batch-init-session/v1",
        "/real-time-response/combined/batch-refresh-session/v1",
        "/real-time-response/entities/active-responder-command/v1",
        "/real-time-response/entities/extracted-file-contents/v1",
        "/real-time-response/entities/file/v1",
        "/real-time-response/entities/file/v2",
        "/real-time-response/entities/queued-sessions/GET/v1",
        "/real-time-response/entities/queued-sessions/command/v1",
        "/real-time-response/entities/refresh-session/v1",
        "/REAL-TIME-RESPONSE/queries/sessions/v1",
        "/real-time-response-audit/combined/sessions/v2",
    ),
)
def test_registry_rejects_non_history_routes_even_under_a_read_id(path: str) -> None:
    with pytest.raises(ValueError, match="exact RTR history"):
        _seal(replace(OPERATIONS["RTR_ListAllSessions"], path=path))


@pytest.mark.parametrize(
    "op,method", (("RTR_ListAllSessions", "POST"), ("RTR_ListSessions", "GET"), ("RTRAuditSessions", "POST"))
)
def test_history_route_admission_binds_method(op: str, method: str) -> None:
    with pytest.raises(ValueError, match="exact RTR history"):
        _seal(replace(OPERATIONS[op], method=method))


@pytest.mark.parametrize("op", ("RTR_ListAllSessions", "RTR_ListSessions", "RTRAuditSessions"))
@pytest.mark.parametrize("change", ({"id": "QueryDevicesByFilter"}, {"scopes": ("Hosts:read",)}))
def test_history_route_admission_binds_id_and_scope(op: str, change: dict) -> None:
    with pytest.raises(ValueError, match="exact RTR history"):
        _seal(replace(OPERATIONS[op], **change))


@pytest.mark.parametrize("noun,op,key,ceiling", LISTS)
def test_bad_filters_suggest_a_valid_history_filter(noun: str, op: str, key: str, ceiling: int) -> None:
    recorded = RecordedTransport([serve(op, response(400, {"errors": [{"message": "invalid filter"}]}))])
    stdout, code = run(["rtr", noun, "list", "--filter", "bad"], recorded, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "FQL_INVALID"
    assert f"falcon-axi rtr {noun} list" in stdout
    assert "name:'Synthetic*'" not in stdout


@pytest.mark.parametrize(
    "op,method,path,body",
    (
        ("RTR_ListAllSessions", "GET", "/real-time-response/queries/sessions/v1", None),
        ("RTR_ListSessions", "POST", "/real-time-response/entities/sessions/GET/v1", {"ids": ["synthetic-session"]}),
        ("RTRAuditSessions", "GET", "/real-time-response-audit/combined/sessions/v1", None),
    ),
)
def test_history_transport_sends_only_its_registered_route(op: str, method: str, path: str, body: dict | None) -> None:
    with requests_mock.Mocker(case_sensitive=True) as network:
        network.register_uri(method, "https://api.crowdstrike.com" + path, json={"resources": []})
        result = HttpTransport().request(
            op,
            RequestArgs(
                base_url="https://api.crowdstrike.com",
                token="synthetic-token",
                body=body,
            ),
        )
        assert result.status == 200
        assert network.call_count == 1
        assert network.last_request.method == method
        assert network.last_request.path == path
