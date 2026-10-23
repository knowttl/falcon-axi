"""Policy combined reads match falcon-mcp modules/policies.py and FalconPy query contracts."""

import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport.operations import operation
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

# Independent expected mapping from CrowdStrike falcon-mcp modules/policies.py _OPERATIONS.
POLICIES = [
    ("prevention", "queryCombinedPreventionPolicies", "queryCombinedPreventionPolicyMembers"),
    ("sensor-update", "queryCombinedSensorUpdatePoliciesV2", "queryCombinedSensorUpdatePolicyMembers"),
    ("firewall", "queryCombinedFirewallPolicies", "queryCombinedFirewallPolicyMembers"),
    ("device-control", "queryDeviceControlPolicies", "queryCombinedDeviceControlPolicyMembers"),
    ("response", "queryCombinedRTResponsePolicies", "queryCombinedRTResponsePolicyMembers"),
    ("content-update", "queryCombinedContentUpdatePolicies", "queryCombinedContentUpdatePolicyMembers"),
]


@pytest.mark.parametrize("policy_type,list_op,members_op", POLICIES)
@pytest.mark.parametrize("members", [False, True], ids=["list", "members"])
def test_each_type_reads_the_combined_operation_and_projects_compact_rows(
    policy_type: str, list_op: str, members_op: str, members: bool
) -> None:
    operation = members_op if members else list_op
    responders = (
        [
            serve(operation, fixture("policies/device-control-query.json")),
            serve("getDeviceControlPoliciesV2", fixture("policies/device-control-details.json")),
        ]
        if policy_type == "device-control" and not members
        else [serve(operation, fixture(f"policies/{operation}.json"))]
    )
    recorded = RecordedTransport(responders)
    argv = ["policy", "members", "synthetic-policy-01"] if members else ["policy", "list"]
    stdout, code = run(argv + ["--type", policy_type, "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == "2 of 3 total"
    key = "members" if members else "policies"
    assert len(parsed[key]) == 2
    assert parsed[key][0] == (
        {"device_id": "synthetic-device-01", "hostname": "SYNTHETIC-HOST-01", "platform_name": "Windows", "status": "normal"}
        if members
        else {
            "id": "synthetic-policy-01",
            "name": "Synthetic policy one",
            "platform_name": "all" if policy_type == "content-update" else "Windows",
            "enabled": True,
        }
    )
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests(operation)[0].query == (
        {"limit": 2, "offset": 0, "id": "synthetic-policy-01"} if members else {"limit": 2, "offset": 0}
    )


@pytest.mark.parametrize(
    "policy_type,list_op,members_op,members",
    [(*policy, False) for policy in POLICIES] + [(*POLICIES[0], True)],
)
def test_rejected_filter_remedy_preserves_policy_command_and_type(
    policy_type: str, list_op: str, members_op: str, members: bool
) -> None:
    operation = members_op if members else list_op
    recorded = RecordedTransport([serve(operation, response(400, {"errors": [{"message": "invalid filter"}]}))])
    argv = ["policy", "members", "synthetic-policy-01"] if members else ["policy", "list"]
    stdout, code = run(argv + ["--type", policy_type, "--filter", "invalid"], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    parsed = decode(stdout)
    assert parsed["code"] == "FQL_INVALID"
    command = "policy members" if members else "policy list"
    example = "hostname:'WIN-*'" if members else "enabled:true"
    assert parsed["help"] == [
        "FQL uses + for AND, `,` for OR, and values must be quoted",
        f'Example: `--filter "{example}"`',
        f"Run `falcon-axi {command} --type {policy_type} --help` for the filterable fields",
    ]


@pytest.mark.parametrize(
    "policy_type,list_op,members_op,members",
    [(*policy, False) for policy in POLICIES] + [(*POLICIES[0], True)],
)
def test_missing_policy_remedy_lists_identifiers_for_the_selected_type(
    policy_type: str, list_op: str, members_op: str, members: bool
) -> None:
    operation = members_op if members else list_op
    recorded = RecordedTransport([serve(operation, response(404, {"errors": [{"message": "policy not found"}]}))])
    argv = ["policy", "members", "synthetic-policy-99"] if members else ["policy", "list"]
    stdout, code = run(argv + ["--type", policy_type], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    parsed = decode(stdout)
    assert parsed["code"] == "NOT_FOUND"
    assert parsed["help"] == [f"Run `falcon-axi policy list --type {policy_type}` to see current identifiers"]


@pytest.mark.parametrize("members", [False, True], ids=["list", "members"])
def test_continuation_replays_filter_type_and_policy_id_and_stops_on_empty_page(members: bool) -> None:
    operation = "queryCombinedPreventionPolicyMembers" if members else "queryCombinedPreventionPolicies"
    first = RecordedTransport([serve(operation, fixture(f"policies/{operation}.json"))])
    argv = ["policy", "members", "synthetic-policy-01"] if members else ["policy", "list"]
    argv += ["--type", "prevention", "--filter", "hostname:'SYNTHETIC-*'" if members else "enabled:true", "--limit", "2"]
    stdout, code = run(argv, first, dict(CREDENTIAL_ENV))
    assert code == 0
    hint = decode(stdout)["help"][-1]
    continuation = shlex.split(hint.split("`")[1])[1:]
    second = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, code = run(continuation, second, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "no more prevention" in stdout
    assert "continuation_cursor" not in stdout
    assert second.operation_requests(operation)[0].query == {**first.operation_requests(operation)[0].query, "offset": 2}


@pytest.mark.parametrize("change", ["type", "filter", "id"])
def test_members_cursor_rejects_changed_query_before_a_scoped_request(change: str) -> None:
    operation = "queryCombinedPreventionPolicyMembers"
    argv = ["policy", "members", "synthetic-policy-01", "--type", "prevention", "--filter", "status:'normal'", "--limit", "2"]
    stdout, _ = run(argv, RecordedTransport([serve(operation, fixture(f"policies/{operation}.json"))]), dict(CREDENTIAL_ENV))
    cursor = decode(stdout)["continuation_cursor"]
    index = {"type": 4, "filter": 6, "id": 2}[change]
    changed = argv.copy()
    changed[index] = {"type": "response", "filter": "status:'contained'", "id": "synthetic-policy-02"}[change]
    recorded = RecordedTransport([])
    stdout, code = run(changed + ["--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "this cursor does not continue the current query" in stdout
    assert len(recorded.requests) == 1  # OAuth only, no scoped operation.


@pytest.mark.parametrize("count,limit,continues", [(None, 2, True), (None, 3, False), (2, 2, False)])
def test_pagination_uses_total_when_available_and_page_size_otherwise(count: int | None, limit: int, continues: bool) -> None:
    body = {"resources": [{"id": "synthetic-policy-01"}, {"id": "synthetic-policy-02"}]}
    if count is not None:
        body["meta"] = {"pagination": {"total": count}}
    recorded = RecordedTransport([serve("queryCombinedPreventionPolicies", response(200, body))])
    stdout, code = run(["policy", "list", "--type", "prevention", "--limit", str(limit)], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert ("continuation_cursor" in decode(stdout)) == continues
    assert decode(stdout)["count"] == f"2 of {count if count is not None else 'unknown'} total"


@pytest.mark.parametrize(
    "argv",
    [
        ["policy", "list"],
        ["policy", "list", "--type", "unknown"],
        ["policy", "members", "--type", "prevention"],
        ["policy", "list", "--type", "prevention", "--limit", "5001"],
        ["policy", "list", "--type", "prevention", "--filter", " "],
        ["policy", "list", "--type", "prevention", "--enabled"],
        ["policy", "enable", "synthetic-policy-01"],
        ["policy", "show", "synthetic-policy-01"],
        ["policy", "show", "synthetic-policy-01", "--type", "prevention"],
        ["policy", "show", "--type", "device-control"],
    ],
)
def test_invalid_policy_commands_fail_before_authentication(argv: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize("policy_type,list_op,members_op", POLICIES)
def test_scope_denial_names_only_the_selected_types_read_scope(policy_type: str, list_op: str, members_op: str) -> None:
    recorded = RecordedTransport([serve(list_op, fixture("errors/403-scope.json"))])
    stdout, code = run(["policy", "list", "--type", policy_type], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    parsed = decode(stdout)
    assert parsed["code"] == "SCOPE_DENIED"
    assert len(parsed["required_scopes"]) == 1
    assert parsed["required_scopes"][0].endswith(":read")


def test_device_control_list_restores_query_order_and_preserves_query_pagination() -> None:
    recorded = RecordedTransport(
        [
            serve("queryDeviceControlPolicies", fixture("policies/device-control-query.json")),
            serve("getDeviceControlPoliciesV2", fixture("policies/device-control-details.json")),
        ]
    )
    stdout, code = run(
        ["policy", "list", "--type", "device-control", "--limit", "2", "--filter", "enabled:true"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    parsed = decode(stdout)
    assert parsed["policies"] == [
        {"id": "synthetic-policy-01", "name": "Synthetic policy one", "platform_name": "Windows", "enabled": True},
        {"id": "synthetic-policy-02", "name": "Synthetic policy two", "platform_name": "Mac", "enabled": False},
    ]
    assert parsed["count"] == "2 of 3 total"
    assert recorded.operation_requests("getDeviceControlPoliciesV2")[0].query == {
        "ids": ("synthetic-policy-01", "synthetic-policy-02")
    }
    continuation = shlex.split(parsed["help"][-1].split("`")[1])[1:]
    second = RecordedTransport([serve("queryDeviceControlPolicies", response(200, {"resources": []}))])
    stdout, code = run(continuation, second, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "no more device-control policies" in stdout
    assert "continuation_cursor" not in stdout
    assert second.operation_requests("queryDeviceControlPolicies")[0].query == {
        "limit": 2,
        "offset": 2,
        "filter": "enabled:true",
    }


def test_device_control_show_exposes_usb_classes_and_exceptions() -> None:
    recorded = RecordedTransport([serve("getDeviceControlPoliciesV2", fixture("policies/device-control-details.json"))])
    stdout, code = run(["policy", "show", "synthetic-policy-01", "--type", "device-control"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    settings = decode(stdout)["policy"]["usb_settings"]
    assert settings["enforcement_mode"] == "MONITOR_ENFORCE"
    assert [entry["class"] for entry in settings["classes"]] == ["MASS_STORAGE", "IMAGING"]
    assert settings["classes"][0]["action"] == "BLOCK_ALL"
    assert settings["classes"][0]["exceptions"][0]["serial_number"] == "SYNTHETIC-USB-01"
    assert settings["classes"][0]["exceptions"][0]["action"] == "FULL_ACCESS"
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests("getDeviceControlPoliciesV2")[0].query == {"ids": ("synthetic-policy-01",)}


@pytest.mark.parametrize("verb,op", [("list", "queryDeviceControlPolicies"), ("show", "getDeviceControlPoliciesV2")])
def test_device_control_scope_denial_explains_licensing(verb: str, op: str) -> None:
    recorded = RecordedTransport([serve(op, fixture("errors/403-scope.json"))])
    argv = ["policy", verb] + (["synthetic-policy-01"] if verb == "show" else []) + ["--type", "device-control"]
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"
    assert "Device Control Policies:read needs Falcon Device Control" in stdout
    assert "tenant lacks that subscription" in stdout


@pytest.mark.parametrize("verb,body,code", [("list", {"resources": []}, 0), ("show", [], 1)])
def test_device_control_empty_result_explains_not_licensed_or_no_data(verb: str, body: object, code: int) -> None:
    op = "queryDeviceControlPolicies" if verb == "list" else "getDeviceControlPoliciesV2"
    recorded = RecordedTransport([serve(op, response(200, body))])
    argv = ["policy", verb] + (["synthetic-policy-01"] if verb == "show" else []) + ["--type", "device-control"]
    stdout, actual_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert actual_code == code
    assert "not licensed or no data" in stdout


@pytest.mark.parametrize(
    "body", [{}, [{"id": "synthetic-other-policy"}], {"errors": [{"message": "partial response"}], "resources": []}]
)
def test_device_control_show_rejects_malformed_or_mismatched_details(body: object) -> None:
    recorded = RecordedTransport([serve("getDeviceControlPoliciesV2", response(200, body))])
    stdout, code = run(["policy", "show", "synthetic-policy-01", "--type", "device-control"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


def test_deprecated_device_control_operation_is_refused() -> None:
    with pytest.raises(CliError):
        operation("queryCombinedDeviceControlPolicies")


def test_device_control_list_refuses_missing_hydrated_policies() -> None:
    recorded = RecordedTransport(
        [
            serve("queryDeviceControlPolicies", fixture("policies/device-control-query.json")),
            serve("getDeviceControlPoliciesV2", response(200, [])),
        ]
    )
    stdout, code = run(["policy", "list", "--type", "device-control"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"
    assert "omitted a requested device-control policy" in stdout


def test_device_control_show_not_found_remedy_preserves_type() -> None:
    recorded = RecordedTransport([serve("getDeviceControlPoliciesV2", response(404, {"errors": []}))])
    stdout, code = run(["policy", "show", "synthetic-policy-01", "--type", "device-control"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"
    assert decode(stdout)["help"] == ["Run `falcon-axi policy list --type device-control` to see current identifiers"]
