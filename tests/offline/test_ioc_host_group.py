"""IOC and host-group CLI reads through the recorded transport boundary."""

import re
import shlex

import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

CASES = [
    (["ioc", "list"], "indicator_search_v1", "ioc/query-page.json"),
    (["ioc", "hosts", "domain:example.invalid"], "DevicesRanOn", "ioc/hosts-page.json"),
    (["ioc", "processes", "domain:example.invalid", "--host", "synthetic-device"], "ProcessesRanOn", "ioc/processes-page.json"),
    (["host-group", "list"], "queryCombinedHostGroups", "host-groups/groups-page.json"),
    (["host-group", "members", "synthetic-group-01"], "queryCombinedGroupMembers", "host-groups/members-page.json"),
]


def test_ioc_list_restores_query_order_and_uses_after_cursor() -> None:
    recorded = RecordedTransport(
        [
            serve("indicator_search_v1", fixture("ioc/query-page.json")),
            serve("indicator_get_v1", fixture("ioc/details-page.json")),
        ]
    )
    stdout, code = run(["ioc", "list", "--filter", "type:'domain'", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 2 of 3 total" in stdout
    assert stdout.index("synthetic-ioc-01") < stdout.index("synthetic-ioc-02")
    assert recorded.operation_requests("indicator_search_v1")[0].query == {"filter": "type:'domain'", "limit": 2}
    assert recorded.operation_requests("indicator_get_v1")[0].query == {"ids": ("synthetic-ioc-01", "synthetic-ioc-02")}
    cursor = re.search(r"continuation_cursor: (\S+)", stdout)[1]
    _, code = run(["ioc", "list", "--filter", "type:'domain'", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests("indicator_search_v1")[-1].query["after"] == "synthetic-after"
    _, code = run(["ioc", "list", "--filter", "type:'md5'", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert len(recorded.operation_requests("indicator_search_v1")) == 2


def test_ioc_show_preserves_configuration_fields() -> None:
    recorded = RecordedTransport([serve("indicator_get_v1", fixture("ioc/details-page.json"))])
    stdout, code = run(["ioc", "show", "synthetic-ioc-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "description: Synthetic custom indicator" in stdout
    assert "applied_globally: false" in stdout
    assert "filename: sample.bin" in stdout
    assert recorded.operation_requests("indicator_get_v1")[0].query == {"ids": ("synthetic-ioc-01",)}


@pytest.mark.parametrize("answer", [response(200, {"resources": []}), response(404, {})])
def test_ioc_show_not_found(answer) -> None:
    recorded = RecordedTransport([serve("indicator_get_v1", answer)])
    stdout, code = run(["ioc", "show", "missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "NOT_FOUND" in stdout
    assert "falcon-axi ioc list" in stdout


@pytest.mark.parametrize("argv,operation,path", CASES)
def test_empty_reads_are_definitive(argv, operation, path) -> None:
    recorded = RecordedTransport([serve(operation, response(200, {"resources": [], "meta": {"pagination": {"total": 0}}}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 0 of 0 total" in stdout
    assert "continuation_cursor" not in stdout
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("argv,operation,path", CASES)
def test_read_scope_failures_name_the_required_permission(argv, operation, path) -> None:
    recorded = RecordedTransport([serve(operation, response(403, {}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "read" in stdout
    assert "write" not in stdout


@pytest.mark.parametrize("argv,operation,path", CASES[1:])
def test_offset_continuation_replays_the_original_query(argv, operation, path) -> None:
    recorded = RecordedTransport([serve(operation, fixture(path))])
    stdout, code = run([*argv, "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    hint = re.search(r"Run `(falcon-axi [^`]* --cursor \S+)` for the next page", stdout)[1]
    _, code = run(shlex.split(hint)[1:], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    requests = recorded.operation_requests(operation)
    assert requests[0].query["offset"] == 0
    assert requests[1].query["offset"] in (1, 2)


@pytest.mark.parametrize(
    "argv",
    [
        ["ioc", "hosts", "bad"],
        ["ioc", "hosts", "bad:value"],
        ["ioc", "hosts", "domain:"],
        ["ioc", "processes", "domain:example.invalid"],
        ["ioc", "processes", "domain:example.invalid", "--host", " "],
        ["ioc", "list", "--filter", " "],
        ["host-group", "members"],
        ["ioc", "list", "--limit", "501"],
        ["ioc", "hosts", "domain:x", "--limit", "101"],
        ["host-group", "list", "--limit", "5001"],
        ["ioc", "list", "--action", "detect"],
    ],
)
def test_invalid_input_fails_before_authentication(argv) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


def test_ipv6_indicator_and_required_host_reach_only_query_parameters() -> None:
    recorded = RecordedTransport([serve("ProcessesRanOn", fixture("ioc/processes-page.json"))])
    stdout, code = run(["ioc", "processes", "ipv6:2001:db8::1", "--host", "synthetic-device"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "process_id" in stdout
    assert recorded.operation_requests("ProcessesRanOn")[0].query == {
        "type": "ipv6",
        "value": "2001:db8::1",
        "device_id": "synthetic-device",
        "limit": 20,
        "offset": 0,
    }


def test_host_group_member_cursor_rejects_a_different_group() -> None:
    recorded = RecordedTransport([serve("queryCombinedGroupMembers", fixture("host-groups/members-page.json"))])
    stdout, _ = run(["host-group", "members", "one", "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    cursor = re.search(r"continuation_cursor: (\S+)", stdout)[1]
    stdout, code = run(["host-group", "members", "two", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert len(recorded.operation_requests("queryCombinedGroupMembers")) == 1


@pytest.mark.parametrize(
    "argv,operation,example",
    [
        (["ioc", "list", "--filter", "bad"], "indicator_search_v1", "ioc list --help"),
        (["host-group", "list", "--filter", "bad"], "queryCombinedHostGroups", "host-group list --help"),
    ],
)
def test_invalid_fql_suggests_the_correct_domain(argv, operation, example) -> None:
    recorded = RecordedTransport([serve(operation, response(400, {"errors": [{"message": "invalid filter"}]}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "FQL_INVALID" in stdout
    assert example in stdout
