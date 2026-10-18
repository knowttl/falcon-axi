"""Read-only malware, identity rules, and Discover IoT through the CLI interface."""

import re

import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize(
    ("argv", "responders", "expected"),
    [
        (
            ["malware", "list"],
            [serve("QueryMalwareEntities", fixture("intel/malware.json"))],
            "synthetic-family,SYNTHETIC FAMILY",
        ),
        (
            ["malware", "show", "synthetic-family"],
            [serve("GetMalwareEntities", fixture("intel/malware.json"))],
            "description: Wholly synthetic",
        ),
        (
            ["identity", "rule", "list"],
            [
                serve("get_policy_rules_query", fixture("identity/rules-query.json")),
                serve("get_policy_rules", fixture("identity/rules.json")),
            ],
            "synthetic-rule,Synthetic access rule,true,false",
        ),
        (
            ["identity", "rule", "show", "synthetic-rule"],
            [serve("get_policy_rules", fixture("identity/rules.json"))],
            "action: ALLOW",
        ),
        (
            ["iot", "list"],
            [
                serve("query_iot_hostsV2", fixture("discover/iot-query.json")),
                serve("get_iot_hosts", fixture("discover/iot.json")),
            ],
            "synthetic-iot,SYNTHETIC-PRINTER,Printer,Office",
        ),
    ],
)
def test_inventory_reads(argv: list, responders: list, expected: str) -> None:
    stdout, code = run(argv, RecordedTransport(responders), dict(CREDENTIAL_ENV))
    assert code == 0
    assert expected in stdout


@pytest.mark.parametrize(
    ("argv", "operation", "label"),
    [
        (["malware", "list"], "QueryMalwareEntities", "0 malware families"),
        (["identity", "rule", "list"], "get_policy_rules_query", "0 identity policy rules"),
        (["iot", "list"], "query_iot_hostsV2", "0 IoT assets"),
    ],
)
def test_empty_query_skips_hydration(argv: list, operation: str, label: str) -> None:
    recorded = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert label in stdout
    assert len(recorded.requests) == 2


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["malware", "show", "missing"], "GetMalwareEntities"),
        (["identity", "rule", "show", "missing"], "get_policy_rules"),
    ],
)
@pytest.mark.parametrize("status", [200, 404])
def test_missing_detail(argv: list, operation: str, status: int) -> None:
    stdout, code = run(argv, RecordedTransport([serve(operation, response(status, {"resources": []}))]), dict(CREDENTIAL_ENV))
    assert code == 1
    assert "NOT_FOUND" in stdout


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["malware", "list"], "QueryMalwareEntities"),
        (["identity", "rule", "list"], "get_policy_rules_query"),
        (["iot", "list"], "query_iot_hostsV2"),
    ],
)
def test_scope_denied(argv: list, operation: str) -> None:
    stdout, code = run(
        argv,
        RecordedTransport([serve(operation, response(403, {"errors": [{"code": 403, "message": "denied"}]}))]),
        dict(CREDENTIAL_ENV),
    )
    assert code == 1
    assert "SCOPE_DENIED" in stdout


def test_malware_description_preview_can_be_expanded() -> None:
    description = "x" * 801
    recorded = RecordedTransport(
        [
            serve(
                "GetMalwareEntities",
                response(
                    200,
                    {
                        "resources": [{"slug": "synthetic-family", "description": description}],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["malware", "show", "synthetic-family"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "truncated, 801 chars total" in stdout
    assert "--full" in stdout
    stdout, code = run(["malware", "show", "synthetic-family", "--full"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert description in stdout
    assert "truncated" not in stdout


def test_rule_filters_use_rest_parameter_names_and_boolean_values() -> None:
    recorded = RecordedTransport([serve("get_policy_rules_query", response(200, {"resources": []}))])
    _, code = run(
        ["identity", "rule", "list", "--name", "Synthetic", "--enabled", "false", "--simulation-mode", "true"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    assert recorded.operation_requests("get_policy_rules_query")[0].query == {
        "name": "Synthetic",
        "enabled": False,
        "simulation_mode": True,
    }


def test_rule_hydration_chunks_and_reorders() -> None:
    ids = [f"rule-{index}" for index in range(101)]
    recorded = RecordedTransport(
        [
            serve("get_policy_rules_query", response(200, {"resources": ids})),
            serve(
                "get_policy_rules",
                lambda args: response(200, {"resources": [{"id": id, "name": id} for id in reversed(args.query["ids"])]}),
            ),
        ]
    )
    stdout, code = run(["identity", "rule", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert [len(args.query["ids"]) for args in recorded.operation_requests("get_policy_rules")] == [100, 1]
    assert stdout.index("rule-0,rule-0") < stdout.index("rule-1,rule-1")


@pytest.mark.parametrize(
    ("argv", "operation", "page", "parameter", "position"),
    [
        (
            ["malware", "list"],
            "QueryMalwareEntities",
            {"meta": {"pagination": {"total": 2}}, "resources": [{"slug": "synthetic-family"}]},
            "offset",
            1,
        ),
        (
            ["iot", "list"],
            "query_iot_hostsV2",
            {"meta": {"pagination": {"after": "synthetic-next"}}, "resources": ["synthetic-iot"]},
            "after",
            "synthetic-next",
        ),
    ],
)
def test_cursor_continuation_and_query_binding(
    argv: list, operation: str, page: dict, parameter: str, position: object
) -> None:
    responders = [serve(operation, response(200, page)), serve("get_iot_hosts", fixture("discover/iot.json"))]
    stdout, code = run(argv, RecordedTransport(responders), dict(CREDENTIAL_ENV))
    assert code == 0
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert cursor
    recorded = RecordedTransport(responders)
    _, code = run([*argv, "--cursor", cursor[1]], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests(operation)[0].query[parameter] == position
    refused = RecordedTransport(responders)
    stdout, code = run([*argv, "--cursor", cursor[1], "--filter", "name:'changed'"], refused, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not refused.operation_requests(operation)


@pytest.mark.parametrize(
    "argv",
    [
        ["identity", "rule", "show"],
        ["identity", "rule", "list", "--filter", "x"],
        ["identity", "rule", "list", "--limit", "1"],
        ["iot", "list", "--limit", "101"],
        ["malware", "list", "--limit", "5001"],
        ["identity", "rule", "list", "--enabled", "maybe"],
    ],
)
def test_invalid_arguments(argv: list) -> None:
    stdout, code = run(argv, RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
