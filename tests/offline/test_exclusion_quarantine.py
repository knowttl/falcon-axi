"""Read-only inventories matched to falcon-mcp modules/exclusions.py and modules/quarantine.py."""

import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

CASES = [
    ("ml", "exclusions_search_v2", "exclusions_get_v2"),
    ("ioa", "ss_ioa_exclusions_search_v2", "ss_ioa_exclusions_get_v2"),
    ("sensor-visibility", "querySensorVisibilityExclusionsV1", "getSensorVisibilityExclusionsV1"),
    ("certificate", "cb_exclusions_query_v1", "cb_exclusions_get_v1"),
    ("quarantine", "QueryQuarantineFiles", "GetQuarantineFiles"),
]


def inventory(type: str, query: str, entity: str) -> RecordedTransport:
    directory = "quarantine" if type == "quarantine" else "exclusions"
    return RecordedTransport(
        [
            serve(query, fixture(f"{directory}/{type}-query.json")),
            serve(entity, fixture(f"{directory}/{type}-details.json")),
        ]
    )


def argv(type: str, verb: str = "list", *extra: str) -> list[str]:
    return ["quarantine", verb, *extra] if type == "quarantine" else ["exclusion", verb, *extra, "--type", type]


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
def test_lists_preserve_query_order_total_and_parameter_shapes(type: str, query: str, entity: str) -> None:
    recorded = inventory(type, query, entity)
    stdout, code = run(argv(type, "list", "--limit", "2", "--filter", "applied_globally:true"), recorded, CREDENTIAL_ENV)
    assert code == 0
    result = decode(stdout)
    assert result["count"] == "2 of 3 total"
    key = "quarantined_files" if type == "quarantine" else "exclusions"
    assert [entry["id"] for entry in result[key]] == [f"synthetic-{type}-01", f"synthetic-{type}-02"]
    request = recorded.operation_requests(query)[0]
    assert request.query == {"offset": "0" if type == "quarantine" else 0, "limit": 2, "filter": "applied_globally:true"}
    hydrate = recorded.operation_requests(entity)[0]
    assert hydrate.body == ({"ids": [f"synthetic-{type}-01", f"synthetic-{type}-02"]} if type == "quarantine" else None)
    assert hydrate.query == (None if type == "quarantine" else {"ids": (f"synthetic-{type}-01", f"synthetic-{type}-02")})


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
def test_continuation_replays_context_and_stops_on_last_page(type: str, query: str, entity: str) -> None:
    stdout, _ = run(argv(type, "list", "--limit", "2"), inventory(type, query, entity), CREDENTIAL_ENV)
    next_hint = decode(stdout)["help"][-1]
    next_argv = shlex.split(next_hint.split("`")[1])[1:]
    followed = inventory(type, query, entity)
    continued, code = run(next_argv, followed, CREDENTIAL_ENV)
    assert code == 0
    assert followed.operation_requests(query)[0].query["offset"] == ("2" if type == "quarantine" else 2)
    assert "continuation_cursor" not in decode(continued)
    refused = inventory(type, query, entity)
    _, code = run([*next_argv, "--filter", "applied_globally:false"], refused, CREDENTIAL_ENV)
    assert code == 2
    assert refused.operation_requests(query) == []


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
def test_show_selects_requested_id_and_redacts_tenant_fields(type: str, query: str, entity: str) -> None:
    recorded = inventory(type, query, entity)
    stdout, code = run(argv(type, "show", f"synthetic-{type}-01"), recorded, CREDENTIAL_ENV)
    assert code == 0
    record = decode(stdout)["quarantine" if type == "quarantine" else "exclusion"]
    assert record["id"] == f"synthetic-{type}-01"
    assert "synthetic-tenant-cid" not in stdout
    assert "synthetic-child-cid" not in stdout
    assert recorded.operation_requests(query) == []


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
def test_empty_inventory_skips_hydration(type: str, query: str, entity: str) -> None:
    recorded = RecordedTransport([serve(query, response(200, {"resources": []}))])
    stdout, code = run(argv(type), recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "0 " in stdout
    assert recorded.operation_requests(entity) == []


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
@pytest.mark.parametrize("status", [200, 404])
def test_missing_detail_is_not_found(type: str, query: str, entity: str, status: int) -> None:
    recorded = RecordedTransport([serve(entity, response(status, {"resources": []}))])
    stdout, code = run(argv(type, "show", "missing"), recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"


@pytest.mark.parametrize(
    "args",
    [
        ["exclusion", "list"],
        ["exclusion", "show", "id"],
        ["exclusion", "list", "--type", "unknown"],
        ["exclusion", "list", "--type", "certificate", "--limit", "101"],
        ["exclusion", "list", "--type", "ml", "--limit", "501"],
        ["quarantine", "list", "--limit", "501"],
        ["quarantine", "release", "id"],
        ["quarantine", "delete", "id"],
        ["exclusion", "delete", "id", "--type", "ml"],
    ],
)
def test_invalid_arguments_fail_before_authentication(args: list[str]) -> None:
    recorded = RecordedTransport([])
    _, code = run(args, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert recorded.requests == []


@pytest.mark.parametrize(("type", "query", "entity"), CASES)
def test_scope_denied_reports_the_selected_inventory_scope(type: str, query: str, entity: str) -> None:
    recorded = RecordedTransport([serve(query, fixture("errors/403-scope.json"))])
    stdout, code = run(argv(type), recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"
    assert recorded.operation_requests(entity) == []


@pytest.mark.parametrize("type", ["quarantine", "ml"])
def test_bad_fql_help_points_to_the_same_domain(type: str) -> None:
    query = "QueryQuarantineFiles" if type == "quarantine" else "exclusions_search_v2"
    recorded = RecordedTransport([serve(query, response(400, {"errors": [{"message": "invalid filter"}]}))])
    stdout, code = run(argv(type, "list", "--filter", "bad:'value'"), recorded, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "FQL_INVALID"
    assert f"falcon-axi {'quarantine' if type == 'quarantine' else 'exclusion'} list --help" in stdout


def test_exclusion_cursor_cannot_select_another_type() -> None:
    stdout, _ = run(argv("ml", "list", "--limit", "2"), inventory(*CASES[0]), CREDENTIAL_ENV)
    recorded = inventory(*CASES[1])
    stdout, code = run(argv("ioa", "list", "--cursor", decode(stdout)["continuation_cursor"]), recorded, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert recorded.operation_requests(CASES[1][1]) == []


def test_hydration_failure_does_not_become_an_empty_success() -> None:
    recorded = RecordedTransport(
        [
            serve("QueryQuarantineFiles", fixture("quarantine/quarantine-query.json")),
            serve("GetQuarantineFiles", fixture("errors/403-scope.json")),
        ]
    )
    stdout, code = run(["quarantine", "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["required_scopes"] == ["Quarantined Files:read"]


def test_missing_entities_keep_the_query_cursor_position() -> None:
    recorded = RecordedTransport(
        [
            serve("QueryQuarantineFiles", fixture("quarantine/quarantine-query.json")),
            serve("GetQuarantineFiles", response(404, {"resources": []})),
        ]
    )
    stdout, code = run(["quarantine", "list", "--limit", "2"], recorded, CREDENTIAL_ENV)
    assert code == 0
    result = decode(stdout)
    assert result["count"] == "0 of 3 total"
    followed = inventory(*CASES[-1])
    run(["quarantine", "list", "--cursor", result["continuation_cursor"]], followed, CREDENTIAL_ENV)
    assert followed.operation_requests("QueryQuarantineFiles")[0].query["offset"] == "2"


@pytest.mark.parametrize(("limit", "has_cursor"), [(1, True), (2, False)])
def test_missing_total_uses_the_query_page_size(limit: int, has_cursor: bool) -> None:
    recorded = RecordedTransport(
        [
            serve("exclusions_search_v2", response(200, {"resources": ["synthetic-ml-01"]})),
            serve("exclusions_get_v2", fixture("exclusions/ml-details.json")),
        ]
    )
    stdout, code = run(argv("ml", "list", "--limit", str(limit)), recorded, CREDENTIAL_ENV)
    assert code == 0
    result = decode(stdout)
    assert result["count"] == "1 of unknown total"
    assert ("continuation_cursor" in result) is has_cursor
