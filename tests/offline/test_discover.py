"""Discover shapes follow the official API reference and SDKs, without tenant validation."""

import re
import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

INVENTORY_ERROR_CASES = [
    (["asset", "list"], "combined_hosts", "asset", "entity_type:'managed'"),
    (["asset", "show", "synthetic-id"], "get_hosts", "asset", "entity_type:'managed'"),
    (["application", "list"], "combined_applications", "application", "name:'Chrome'"),
    (["login", "list"], "query_logins", "login", "login_status:'Failed'"),
    (["login", "list"], "get_logins", "login", "login_status:'Failed'"),
    (["host", "network", "synthetic-id"], "QueryGetNetworkAddressHistoryV1", "host", "hostname:'WIN-*'"),
]


def test_application_list_preserves_all_returned_fields_and_host_details() -> None:
    answer = fixture("discover/applications-page.json")
    recorded = RecordedTransport([serve("combined_applications", answer)])
    stdout, code = run(["application", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["applications"] == answer.body["resources"]


def test_application_fields_selects_columns_instead_of_adding_them() -> None:
    recorded = RecordedTransport([serve("combined_applications", fixture("discover/applications-page.json"))])
    stdout, code = run(["application", "list", "--fields", "name,host,name"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["applications"] == [
        {
            "name": "Synthetic Browser",
            "host": {
                "id": "synthetic-asset-01",
                "aid": "synthetic-device-01",
                "hostname": "SYNTHETIC-HOST",
                "platform_name": "Linux",
                "last_seen_date": "2026-10-20T12:00:00Z",
            },
        }
    ]


def test_application_selected_optional_fields_remain_null_when_missing() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "combined_applications",
                response(
                    200,
                    {
                        "resources": [{"id": "synthetic-application"}],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["application", "list", "--fields", "id,host"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["applications"] == [{"id": "synthetic-application", "host": None}]


@pytest.mark.parametrize("full", [False, True])
def test_application_raw_output_redacts_before_recursive_preview(full: bool) -> None:
    record = {
        "id": "synthetic-application",
        "cid": "synthetic-cid",
        "host": {"hostname": "SYNTHETIC-HOST", "token": "synthetic-token"},
        "future_details": [False, 0, None, {"description": "x" * 501, "client_secret": "synthetic-secret"}],
    }
    recorded = RecordedTransport([serve("combined_applications", response(200, {"resources": [record]}))])
    stdout, code = run(["application", "list", *(["--full"] if full else [])], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    row = decode(stdout)["applications"][0]
    assert row["cid"] == "[redacted]"
    assert row["host"]["token"] == "[redacted]"
    assert row["future_details"][:3] == [False, 0, None]
    assert row["future_details"][3]["client_secret"] == "[redacted]"
    assert row["future_details"][3]["description"] == ("x" * 501 if full else "x" * 500 + "… (truncated, 501 chars total)")
    assert ("--full" in stdout) is not full
    assert "synthetic-cid" not in stdout
    assert "synthetic-token" not in stdout
    assert "synthetic-secret" not in stdout


@pytest.mark.parametrize("fields", [None, "id,name,host"])
def test_application_expansion_hint_replays_current_page_and_next_hint_advances(fields: str | None) -> None:
    argv = ["application", "list", "--filter", "name:'Synthetic Browser'", "--limit", "1"]
    if fields is not None:
        argv.extend(["--fields", fields])
    first = RecordedTransport([serve("combined_applications", fixture("discover/applications-page.json"))])
    stdout, code = run(argv, first, dict(CREDENTIAL_ENV))
    assert code == 0
    incoming = decode(stdout)["continuation_cursor"]
    record = {
        "id": "synthetic-second-page",
        "name": "x" * 501,
        "host": {"hostname": "SYNTHETIC-HOST", "token": "synthetic-token"},
        "vendor": "Synthetic Vendor",
    }
    answer = response(
        200,
        {"resources": [record], "meta": {"pagination": {"after": "synthetic-third-page"}}},
    )
    page = RecordedTransport([serve("combined_applications", answer)])
    stdout, code = run([*argv, "--cursor", incoming], page, dict(CREDENTIAL_ENV))
    assert code == 0
    preview = decode(stdout)
    assert preview["applications"][0]["name"] == "x" * 500 + "… (truncated, 501 chars total)"
    expansion = shlex.split(preview["help"][0].split("`")[1])[1:]
    expanded = RecordedTransport([serve("combined_applications", answer)])
    stdout, code = run(expansion, expanded, dict(CREDENTIAL_ENV))
    assert code == 0
    document = decode(stdout)
    expected = {
        "id": "synthetic-second-page",
        "name": "x" * 501,
        "host": {"hostname": "SYNTHETIC-HOST", "token": "[redacted]"},
    }
    if fields is None:
        expected["vendor"] = "Synthetic Vendor"
    assert document["applications"] == [expected]
    assert "synthetic-token" not in stdout
    assert (
        expanded.operation_requests("combined_applications")[0].query
        == page.operation_requests("combined_applications")[0].query
    )
    assert document["continuation_cursor"] != incoming
    assert document["continuation_cursor"] == preview["continuation_cursor"]
    next_argv = shlex.split(document["help"][0].split("`")[1])[1:]
    assert "--full" in next_argv
    assert next_argv[next_argv.index("--cursor") + 1] == document["continuation_cursor"]
    following = RecordedTransport([serve("combined_applications", response(200, {"resources": []}))])
    _, code = run(next_argv, following, dict(CREDENTIAL_ENV))
    assert code == 0
    assert following.operation_requests("combined_applications")[0].query == {
        **page.operation_requests("combined_applications")[0].query,
        "after": "synthetic-third-page",
    }


@pytest.mark.parametrize("fields", ["", "name,", "hostname", "not_a_field"])
def test_invalid_application_fields_are_rejected_before_authentication(fields: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["application", "list", "--fields", fields], recorded, {})
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not recorded.requests


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["application", "list", "--filter", "name:'Node*'"], "combined_applications"),
        (["vuln", "list", "--filter", "cve.id:'CVE-2026-0001'"], "combinedQueryVulnerabilities"),
    ],
)
def test_empty_application_and_vulnerability_results_warn_against_absence_inference(argv: list[str], operation: str) -> None:
    recorded = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "exact whole-value" in stdout
    assert "wildcards and partial names are not supported" in stdout
    assert "0 rows does not prove absence" in stdout


@pytest.mark.parametrize(("argv", "operation", "noun", "example"), INVENTORY_ERROR_CASES)
def test_inventory_filter_rejection_teaches_its_own_domain(argv: list[str], operation: str, noun: str, example: str) -> None:
    recorded = RecordedTransport(
        [
            serve(operation, fixture("errors/400-fql.json")),
            serve("query_logins", fixture("discover/logins-query.json")),
        ]
    )
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"] == [
        "FQL uses + for AND, `,` for OR, and values must be quoted",
        f'Example: `--filter "{example}"`',
        f"Run `falcon-axi {noun} list --help` for the filterable fields",
    ]


@pytest.mark.parametrize(("argv", "operation", "noun", "example"), INVENTORY_ERROR_CASES)
def test_inventory_not_found_points_to_its_own_identifiers(argv: list[str], operation: str, noun: str, example: str) -> None:
    recorded = RecordedTransport(
        [
            serve(operation, response(404, {})),
            serve("query_logins", fixture("discover/logins-query.json")),
        ]
    )
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 1
    assert document["code"] == "NOT_FOUND"
    assert document["help"] == [f"Run `falcon-axi {noun} list` to see current identifiers"]


@pytest.mark.parametrize(
    ("noun", "operation", "filename", "default_filter", "facets"),
    [
        ("asset", "combined_hosts", "assets-page", "id:'*'", {}),
        (
            "application",
            "combined_applications",
            "applications-page",
            "name:'*'",
            {
                "facet": ("browser_extension", "host_info", "install_usage", "dev_package", "ide_extension", "llm", "mcp"),
            },
        ),
    ],
)
def test_default_inventory_filter_is_sent_and_bound_to_continuation(
    noun: str, operation: str, filename: str, default_filter: str, facets: dict[str, tuple[str, ...]]
) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"discover/{filename}.json"))])
    stdout, code = run([noun, "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests(operation)[0].query == {"limit": 20, "filter": default_filter, **facets}
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert cursor
    followed = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    _, code = run([noun, "list", "--cursor", cursor[1]], followed, dict(CREDENTIAL_ENV))
    assert code == 0
    assert followed.operation_requests(operation)[0].query["filter"] == default_filter
    explicit = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    _, code = run([noun, "list", "--filter", default_filter, "--cursor", cursor[1]], explicit, dict(CREDENTIAL_ENV))
    assert code == 0
    refused = RecordedTransport([])
    output, code = run([noun, "list", "--filter", "name:'other'", "--cursor", cursor[1]], refused, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in output
    assert not refused.operation_requests(operation)


@pytest.mark.parametrize(
    ("noun", "operation", "filename", "limit", "next_position", "facets"),
    [
        ("asset", "combined_hosts", "assets-page", "2", "synthetic-assets-next", {}),
        (
            "application",
            "combined_applications",
            "applications-page",
            "1",
            "synthetic-applications-next",
            {
                "facet": ("browser_extension", "host_info", "install_usage", "dev_package", "ide_extension", "llm", "mcp"),
            },
        ),
    ],
)
def test_combined_lists_continue_with_the_server_after_token(
    noun: str, operation: str, filename: str, limit: str, next_position: str, facets: dict[str, tuple[str, ...]]
) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"discover/{filename}.json"))])
    argv = [noun, "list", "--limit", limit, "--filter", "hostname:'SYNTHETIC-*'"]
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "total" in stdout
    assert recorded.operation_requests(operation)[0].query == {
        "limit": int(limit),
        "filter": "hostname:'SYNTHETIC-*'",
        **facets,
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
    assert 'mac_addresses[1]: "02:00:00:00:00:01"' in stdout
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests("get_hosts")[0].query == {"ids": ("synthetic-asset-01",)}


def test_missing_asset_has_actionable_not_found_error() -> None:
    recorded = RecordedTransport([serve("get_hosts", response(200, {"resources": []}))])
    stdout, code = run(["asset", "show", "missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "NOT_FOUND" in stdout
    assert "falcon-axi asset list" in stdout


@pytest.mark.parametrize(
    ("network", "expected"),
    [
        ({}, "mac_addresses: []"),
        ({"network_interfaces": None}, "mac_addresses: []"),
        ({"network_interfaces": []}, "mac_addresses: []"),
        (
            {
                "network_interfaces": [
                    {"mac_address": "02:00:00:00:00:01"},
                    {"local_ip": "192.0.2.10"},
                    {"mac_address": "02:00:00:00:00:02"},
                ]
            },
            'mac_addresses[2]: "02:00:00:00:00:01","02:00:00:00:00:02"',
        ),
    ],
)
def test_asset_show_preserves_available_interface_mac_addresses(network: dict[str, object], expected: str) -> None:
    recorded = RecordedTransport([serve("get_hosts", response(200, {"resources": [{"id": "synthetic-asset", **network}]}))])
    stdout, code = run(["asset", "show", "synthetic-asset"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert expected in stdout


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
