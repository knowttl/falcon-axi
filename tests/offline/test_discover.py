"""Discover shapes follow the official API reference and SDKs, without tenant validation."""

import re

import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize(
    ("noun", "operation", "filename", "limit", "next_position"),
    [
        ("asset", "combined_hosts", "assets-page", "2", "synthetic-assets-next"),
        ("application", "combined_applications", "applications-page", "1", "synthetic-applications-next"),
    ],
)
def test_combined_lists_continue_with_the_server_after_token(
    noun: str, operation: str, filename: str, limit: str, next_position: str
) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"discover/{filename}.json"))])
    argv = [noun, "list", "--limit", limit, "--filter", "hostname:'SYNTHETIC-*'"]
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "total" in stdout
    assert recorded.operation_requests(operation)[0].query == {
        "limit": int(limit),
        "filter": "hostname:'SYNTHETIC-*'",
    }
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert cursor
    followed = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    empty, code = run([*argv, "--cursor", cursor[1]], followed, dict(CREDENTIAL_ENV))
    assert code == 0
    assert followed.operation_requests(operation)[0].query["after"] == next_position
    assert f"0 {noun}s" in empty
    assert "continuation_cursor" not in empty
    refused = RecordedTransport([])
    output, code = run([noun, "list", "--cursor", cursor[1]], refused, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in output
    assert not refused.operation_requests(operation)


def test_login_list_restores_query_order_and_keeps_query_total_when_hydration_is_short() -> None:
    recorded = RecordedTransport(
        [
            serve("query_logins", fixture("discover/logins-query.json")),
            serve("get_logins", fixture("discover/logins-details.json")),
        ]
    )
    stdout, code = run(["login", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 2 of 3 total" in stdout
    assert stdout.index("synthetic-login-01") < stdout.index("synthetic-login-02")
    assert recorded.operation_requests("get_logins")[0].query == {
        "ids": ("synthetic-login-01", "synthetic-login-02"),
    }
    assert "synthetic-cid" not in stdout
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert cursor
    followed = RecordedTransport(
        [
            serve("query_logins", response(200, {"resources": ["synthetic-login-03"], "meta": {"pagination": {"total": 3}}})),
            serve("get_logins", response(200, {"resources": []})),
        ]
    )
    output, code = run(["login", "list", "--limit", "2", "--cursor", cursor[1]], followed, dict(CREDENTIAL_ENV))
    assert code == 0
    assert followed.operation_requests("query_logins")[0].query == {"limit": 2, "offset": 2}
    assert "count: 0 of 3 total" in output
    assert "continuation_cursor" not in output


def test_empty_login_query_does_not_hydrate() -> None:
    recorded = RecordedTransport([serve("query_logins", response(200, {"resources": []}))])
    stdout, code = run(["login", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 logins" in stdout
    assert not recorded.operation_requests("get_logins")


def test_asset_show_uses_discover_id_and_renders_platform_and_sensor_association() -> None:
    recorded = RecordedTransport([serve("get_hosts", fixture("discover/asset-one.json"))])
    stdout, code = run(["asset", "show", "synthetic-asset-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "aid: synthetic-device-01" in stdout
    assert "entity_type: managed" in stdout
    assert "192.0.2.10" in stdout
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests("get_hosts")[0].query == {"ids": ("synthetic-asset-01",)}


def test_missing_asset_has_actionable_not_found_error() -> None:
    recorded = RecordedTransport([serve("get_hosts", response(200, {"resources": []}))])
    stdout, code = run(["asset", "show", "missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "NOT_FOUND" in stdout
    assert "falcon-axi asset list" in stdout


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["asset", "list"], "combined_hosts"),
        (["asset", "show", "missing"], "get_hosts"),
        (["application", "list"], "combined_applications"),
        (["login", "list"], "query_logins"),
        (["host", "network", "synthetic-device-01"], "QueryGetNetworkAddressHistoryV1"),
    ],
)
def test_scope_denied_is_structured(argv: list[str], operation: str) -> None:
    recorded = RecordedTransport([serve(operation, response(403, {"errors": [{"message": "access denied"}]}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout


@pytest.mark.parametrize("noun", ["asset", "application", "login"])
def test_blank_filter_is_rejected_without_an_operation_request(noun: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run([noun, "list", "--filter", " "], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not [entry for entry in recorded.requests if entry[0] == "operation"]


@pytest.mark.parametrize("enveloped", [False, True])
def test_network_history_posts_one_id_and_omits_tenant_cid(enveloped: bool) -> None:
    answer = fixture("discover/network-history.json")
    body = {"resources": answer.body} if enveloped else answer.body
    recorded = RecordedTransport([serve("QueryGetNetworkAddressHistoryV1", response(200, body))])
    stdout, code = run(["host", "network", "synthetic-device-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "192.0.2.10" in stdout
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests("QueryGetNetworkAddressHistoryV1")[0].body == {"ids": ["synthetic-device-01"]}


@pytest.mark.parametrize("body", [[], [{"device_id": "synthetic-device-01", "history": []}]])
def test_network_history_empty_is_definitive(body: object) -> None:
    recorded = RecordedTransport([serve("QueryGetNetworkAddressHistoryV1", response(200, body))])
    stdout, code = run(["host", "network", "synthetic-device-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 network address history entries" in stdout
