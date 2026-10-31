"""Bounded hostname history through the public CLI, using wholly synthetic responses."""

import time
from typing import Any

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.transport.types import FalconResponse, RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

HISTORY = [
    serve("QueryDeviceLoginHistoryV2", fixture("hosts/login-history.json")),
    serve("QueryGetNetworkAddressHistoryV1", fixture("discover/network-history.json")),
]
ONE = {"resources": ["synthetic-device-01"], "meta": {"pagination": {"total": 1}}}


@pytest.mark.parametrize("command", ["network", "logins"])
def test_hostname_history_preserves_the_aid_output_and_history_bounds(command: str) -> None:
    recorded = RecordedTransport([serve("QueryDevicesByFilter", response(200, ONE)), *HISTORY])
    options = ["--since", "24h", "--limit", "2"] if command == "logins" else []
    env = {**CREDENTIAL_ENV, "FALCON_AXI_READ_ONLY": "1"}
    stdout, code = run(["host", command, "--hostname", "synthetic-host-*", *options], recorded, env)
    direct, direct_code = run(["host", command, "synthetic-device-01", *options], RecordedTransport(HISTORY), env)
    assert (stdout, code) == (direct, direct_code)
    assert code == 0
    assert "synthetic-device-01" in stdout
    (lookup,) = recorded.operation_requests("QueryDevicesByFilter")
    assert lookup.query == {"filter": "hostname:'synthetic-host-*'", "limit": 2, "offset": 0}
    assert recorded.operation_requests("PostDeviceDetailsV2") == []
    if command == "logins":
        (history,) = recorded.operation_requests("QueryDeviceLoginHistoryV2")
        assert history.query == {"limit": 2, "from": "now-24h"}
        assert "returned its limit of 2 logins" in stdout


@pytest.mark.parametrize("command", ["network", "logins"])
@pytest.mark.parametrize(
    ("ids", "count"),
    [(["synthetic-device-01", "synthetic-device-02"], 2), (["synthetic-device-01"], 200)],
)
def test_ambiguous_hostname_never_reads_history(command: str, ids: list[str], count: int) -> None:
    recorded = RecordedTransport(
        [serve("QueryDevicesByFilter", response(200, {"resources": ids, "meta": {"pagination": {"total": count}}}))]
    )
    stdout, code = run(["host", command, "--hostname", "synthetic-host-*"], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "hostname matches more than one host; history was not read" in stdout
    assert "host list --hostname '<pattern>' --limit 2" in stdout
    assert recorded.operation_requests("QueryDeviceLoginHistoryV2") == []
    assert recorded.operation_requests("QueryGetNetworkAddressHistoryV1") == []


@pytest.mark.parametrize("command", ["network", "logins"])
@pytest.mark.parametrize(
    "body",
    [
        {"resources": ["synthetic-device-01"]},
        {"resources": [], "meta": {"pagination": {"total": 1}}},
        {**ONE, "errors": [{"code": 500, "message": "synthetic partial lookup"}]},
    ],
)
def test_incomplete_lookup_fails_without_reading_history(command: str, body: Any) -> None:
    recorded = RecordedTransport([serve("QueryDevicesByFilter", response(200, body))])
    stdout, code = run(["host", command, "--hostname", "synthetic-host-*"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 1
    assert document["code"] == "UPSTREAM_ERROR"
    assert document["partial"] is True
    assert "history was not read" in document["error"]
    assert recorded.operation_requests("QueryDeviceLoginHistoryV2") == []
    assert recorded.operation_requests("QueryGetNetworkAddressHistoryV1") == []


@pytest.mark.parametrize("command", ["network", "logins"])
def test_zero_hostname_matches_is_not_empty_history(command: str) -> None:
    recorded = RecordedTransport(
        [serve("QueryDevicesByFilter", response(200, {"resources": [], "meta": {"pagination": {"total": 0}}}))]
    )
    stdout, code = run(["host", command, "--hostname", "synthetic-missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: NOT_FOUND" in stdout
    assert "no host matched that hostname; history was not read" in stdout


@pytest.mark.parametrize(
    ("command", "operation"), [("network", "QueryGetNetworkAddressHistoryV1"), ("logins", "QueryDeviceLoginHistoryV2")]
)
@pytest.mark.parametrize("status", [200, 503])
def test_lookup_success_and_history_failure_are_disclosed(command: str, operation: str, status: int) -> None:
    recorded = RecordedTransport(
        [
            serve("QueryDevicesByFilter", response(200, ONE)),
            serve(operation, response(status, {"resources": [], "errors": [{"code": 500, "message": "synthetic failure"}]})),
        ]
    )
    stdout, code = run(["host", command, "--hostname", "synthetic-host-*"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 1
    assert document["code"] == ("UPSTREAM_ERROR" if status == 200 else "UPSTREAM_UNAVAILABLE")
    assert document["device_id"] == "synthetic-device-01"
    assert document["partial"] is True
    assert document["stop_reason"] == "history_failed"
    assert "0 logins" not in stdout
    assert "0 network address history" not in stdout


@pytest.mark.parametrize("command", ["network", "logins"])
@pytest.mark.parametrize("phase", ["lookup", "history"])
def test_total_deadline_stops_work_and_discloses_expiry(command: str, phase: str, monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    def lookup(_: RequestArgs) -> FalconResponse:
        now[0] = 60.0 if phase == "lookup" else 30.0
        return response(200, ONE)

    def history(_: RequestArgs) -> FalconResponse:
        now[0] = 60.0
        return fixture("hosts/login-history.json" if command == "logins" else "discover/network-history.json")

    operation = "QueryDeviceLoginHistoryV2" if command == "logins" else "QueryGetNetworkAddressHistoryV1"
    recorded = RecordedTransport([serve("QueryDevicesByFilter", lookup), serve(operation, history)])
    stdout, code = run(["host", command, "--hostname", "synthetic-host-*"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 1
    assert document["code"] == "WAIT_TIMEOUT"
    assert "60-second total deadline" in document["error"]
    assert "search" not in document["error"]
    if phase == "lookup":
        assert recorded.operation_requests(operation) == []
    else:
        assert document["device_id"] == "synthetic-device-01"
        assert document["partial"] is True


@pytest.mark.parametrize("command", ["network", "logins"])
@pytest.mark.parametrize("args", [["synthetic-device-01", "--hostname", "synthetic-host"], ["--hostname", "   "]])
def test_hostname_selector_is_validated_before_authentication(command: str, args: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["host", command, *args], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "code: VALIDATION_ERROR" in stdout
    assert recorded.requests == []
