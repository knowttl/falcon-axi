"""D10 command behavior through the real CLI and sealed recorded transport."""

import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

LISTS = (
    ("firewall rule", "query_rules", "get_rules", "firewall/rule-ids.json", "firewall/rules.json", "firewall_rules"),
    (
        "firewall group",
        "query_rule_groups",
        "get_rule_groups",
        "firewall/group-ids.json",
        "firewall/groups.json",
        "firewall_groups",
    ),
    ("ioa group", "query_rule_groups_full", None, "ioa/groups.json", None, "ioa_groups"),
    ("correlation-rule", "combined_rules_get_v2", None, "correlation/rules.json", None, "correlation_rules"),
    ("case", "queries_cases_get_v1", "entities_cases_post_v2", "cases/ids.json", "cases/details.json", "cases"),
)


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS)
def test_lists_read_the_documented_operations_and_preserve_query_order(
    noun: str, query: str, hydrate: str | None, query_fixture: str, details_fixture: str | None, key: str
) -> None:
    responders = [serve(query, fixture(query_fixture))]
    if hydrate and details_fixture:
        responders.append(serve(hydrate, fixture(details_fixture)))
    recorded = RecordedTransport(responders)
    stdout, code = run([*noun.split(), "list", "--limit", "2", "--filter", "name:'Synthetic*'"], recorded, CREDENTIAL_ENV)
    assert code == 0, stdout
    parsed = decode(stdout)
    records = parsed[key]
    assert len(records) >= 1
    request = recorded.operation_requests(query)[0]
    assert request.query["filter"] == "name:'Synthetic*'"
    assert request.query["limit"] == 2
    if hydrate:
        assert [row["id"] for row in records] == fixture(query_fixture).body["resources"]
        args = recorded.operation_requests(hydrate)[0]
        if noun == "case":
            assert args.body == {"ids": ["synthetic-case-01", "synthetic-case-02"]}
            assert args.query is None
        else:
            assert args.query == {"ids": tuple(fixture(query_fixture).body["resources"])}
            assert args.body is None


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS)
def test_empty_lists_skip_hydration(
    noun: str, query: str, hydrate: str | None, query_fixture: str, details_fixture: str | None, key: str
) -> None:
    recorded = RecordedTransport([serve(query, response(200, {"resources": []}))])
    stdout, code = run([*noun.split(), "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)[key] == f"0 {key} matching this query"
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS)
def test_scope_denials_name_the_required_scope(
    noun: str, query: str, hydrate: str | None, query_fixture: str, details_fixture: str | None, key: str
) -> None:
    recorded = RecordedTransport([serve(query, fixture("errors/403-scope.json"))])
    stdout, code = run([*noun.split(), "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", (LISTS[0], LISTS[2], LISTS[4]))
def test_cursor_continues_the_correct_pagination_model(
    noun: str, query: str, hydrate: str | None, query_fixture: str, details_fixture: str | None, key: str
) -> None:
    responders = [serve(query, fixture(query_fixture))]
    if hydrate and details_fixture:
        responders.append(serve(hydrate, fixture(details_fixture)))
    recorded = RecordedTransport(responders)
    argv = [*noun.split(), "list", "--limit", "1"]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    cursor = decode(stdout)["continuation_cursor"]
    continued = RecordedTransport(responders)
    stdout, code = run([*argv, "--cursor", cursor], continued, CREDENTIAL_ENV)
    assert code == 0
    expected = (
        {"limit": 1, "after": "synthetic-next-rule"}
        if noun == "firewall rule"
        else {"limit": 1, "offset": len(fixture(query_fixture).body["resources"])}
    )
    assert continued.operation_requests(query)[0].query == expected
    rejected = RecordedTransport([])
    stdout, code = run([*argv, "--filter", "name:'changed'", "--cursor", cursor], rejected, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert rejected.operation_requests(query) == []


@pytest.mark.parametrize(
    "noun,hydrate,id", (("firewall rule", "get_rules", "1001"), ("case", "entities_cases_post_v2", "synthetic-case-01"))
)
def test_show_selects_the_requested_record_and_truncates_long_fields(noun: str, hydrate: str, id: str) -> None:
    record = {"id": id, "description": "x" * 1000, "nested": {"text": "y" * 900}, "cid": "synthetic-sensitive-cid"}
    recorded = RecordedTransport([serve(hydrate, response(200, {"resources": [{"id": "other"}, record]}))])
    stdout, code = run([*noun.split(), "show", id], recorded, CREDENTIAL_ENV)
    assert code == 0, stdout
    parsed = decode(stdout)
    assert parsed[noun.replace(" ", "_")]["id"] == id
    assert "1000 chars total" in stdout
    assert "synthetic-sensitive-cid" not in stdout
    full_command = shlex.split(parsed["help"][0].split("`")[1])[1:]
    stdout, code = run(full_command, recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "x" * 1000 in stdout
    assert "y" * 900 in stdout


@pytest.mark.parametrize("full", (False, True))
def test_firewall_customer_id_is_redacted_in_default_tenant_detail(full: bool) -> None:
    recorded = RecordedTransport([serve("get_rules", fixture("firewall/rules.json"))])
    argv = ["firewall", "rule", "show", "1001", *(["--full"] if full else [])]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["firewall_rule"]["customer_id"] == "[redacted]"
    assert "synthetic-sensitive-customer" not in stdout


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS[:2])
@pytest.mark.parametrize("total", (3, None))
def test_firewall_offset_pages_continue_until_exhausted(
    noun: str, query: str, hydrate: str, query_fixture: str, details_fixture: str, key: str, total: int | None
) -> None:
    ids = ["first", "second", "third"]

    def page(args: RequestArgs):
        offset = args.query.get("offset", 0)
        return response(
            200,
            {
                "resources": ids[offset : offset + 1],
                "meta": {"pagination": {"offset": offset, "limit": 1, "total": total}},
            },
        )

    recorded = RecordedTransport(
        [serve(query, page), serve(hydrate, response(200, {"resources": [{"id": id} for id in ids]}))]
    )
    argv = [*noun.split(), "list", "--limit", "1"]
    first, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    second, code = run([*argv, "--cursor", decode(first)["continuation_cursor"]], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(second)[key][0]["id"] == "second"
    third, code = run([*argv, "--cursor", decode(second)["continuation_cursor"]], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(third)[key][0]["id"] == "third"
    assert recorded.operation_requests(query)[1].query == {"limit": 1, "offset": 1}
    assert recorded.operation_requests(query)[2].query == {"limit": 1, "offset": 2}
    if total is None:
        empty, code = run([*argv, "--cursor", decode(third)["continuation_cursor"]], recorded, CREDENTIAL_ENV)
        assert code == 0
        assert decode(empty)[key] == f"no more {key}"
        assert "continuation_cursor" not in decode(empty)
    else:
        assert "continuation_cursor" not in decode(third)


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS[:2])
@pytest.mark.parametrize("token_field", ("next", "after"))
def test_firewall_server_tokens_take_precedence_over_offsets(
    noun: str, query: str, hydrate: str, query_fixture: str, details_fixture: str, key: str, token_field: str
) -> None:
    first = response(
        200,
        {"resources": ["first"], "meta": {"pagination": {"offset": 0, "total": 2, token_field: "next-page"}}},
    )
    details = response(200, {"resources": [{"id": "first"}, {"id": "last"}]})
    initial = RecordedTransport([serve(query, first), serve(hydrate, details)])
    argv = [*noun.split(), "list", "--limit", "1"]
    stdout, code = run(argv, initial, CREDENTIAL_ENV)
    assert code == 0
    continued = RecordedTransport(
        [serve(query, response(200, {"resources": ["last"]})), serve(hydrate, details)]
    )
    stdout, code = run([*argv, "--cursor", decode(stdout)["continuation_cursor"]], continued, CREDENTIAL_ENV)
    assert code == 0
    assert continued.operation_requests(query)[0].query == {"limit": 1, "after": "next-page"}
    assert decode(stdout)[key][0]["id"] == "last"
    assert "continuation_cursor" not in decode(stdout)


@pytest.mark.parametrize("noun,query,hydrate,query_fixture,details_fixture,key", LISTS)
def test_rejected_filters_suggest_the_failed_domain(
    noun: str, query: str, hydrate: str | None, query_fixture: str, details_fixture: str | None, key: str
) -> None:
    recorded = RecordedTransport([serve(query, response(400, {"errors": [{"message": "invalid filter"}]}))])
    stdout, code = run([*noun.split(), "list", "--filter", "bad"], recorded, CREDENTIAL_ENV)
    assert code == 2
    parsed = decode(stdout)
    assert parsed["code"] == "FQL_INVALID"
    assert f"Run `falcon-axi {noun} list --help` for the filterable fields" in parsed["help"]
    assert "detection" not in stdout


@pytest.mark.parametrize(
    "noun,query,hydrate,query_fixture,details_fixture,key", (LISTS[0], LISTS[1], LISTS[4])
)
@pytest.mark.parametrize("status,expected_code", ((400, 2), (404, 1)))
def test_hydration_errors_suggest_the_failed_domain(
    noun: str, query: str, hydrate: str, query_fixture: str, details_fixture: str, key: str, status: int, expected_code: int
) -> None:
    recorded = RecordedTransport(
        [
            serve(query, fixture(query_fixture)),
            serve(hydrate, response(status, {"errors": [{"message": "invalid filter"}]})),
        ]
    )
    stdout, code = run([*noun.split(), "list"], recorded, CREDENTIAL_ENV)
    assert code == expected_code
    assert f"falcon-axi {noun} list" in stdout
    assert "detection" not in stdout


@pytest.mark.parametrize("noun,hydrate", (("firewall rule", "get_rules"), ("case", "entities_cases_post_v2")))
def test_detail_404_suggests_the_failed_domain(noun: str, hydrate: str) -> None:
    recorded = RecordedTransport([serve(hydrate, response(404, {}))])
    stdout, code = run([*noun.split(), "show", "missing"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"
    assert f"Run `falcon-axi {noun} list` to see current identifiers" in decode(stdout)["help"]


@pytest.mark.parametrize("noun,hydrate", (("firewall rule", "get_rules"), ("case", "entities_cases_post_v2")))
def test_show_reports_a_missing_record(noun: str, hydrate: str) -> None:
    recorded = RecordedTransport([serve(hydrate, response(200, {"resources": []}))])
    stdout, code = run([*noun.split(), "show", "missing"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"


@pytest.mark.parametrize(
    "argv",
    (
        ["firewall", "rule", "delete"],
        ["firewall", "rule list"],
        ["ioa", "group", "list", "--action", "enable"],
        ["case", "show"],
        ["case", "list", "--limit", "501"],
    ),
)
def test_invalid_nested_commands_fail_before_authentication(argv: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert recorded.requests == []


def test_case_hydration_chunks_ids_and_keeps_the_query_total() -> None:
    ids = [f"synthetic-case-{index}" for index in range(201)]

    def details(args: RequestArgs):
        return response(
            200,
            {
                "resources": [
                    {"id": id, "name": "Synthetic", "status": "new", "severity": 25} for id in reversed(args.body["ids"])
                ]
            },
        )

    recorded = RecordedTransport(
        [
            serve("queries_cases_get_v1", response(200, {"resources": ids, "meta": {"pagination": {"total": 400}}})),
            serve("entities_cases_post_v2", details),
        ]
    )
    stdout, code = run(["case", "list", "--limit", "201"], recorded, CREDENTIAL_ENV)
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == "201 of 400 total"
    assert [row["id"] for row in parsed["cases"]] == ids
    assert [len(args.body["ids"]) for args in recorded.operation_requests("entities_cases_post_v2")] == [100, 100, 1]


def test_hydration_errors_are_not_returned_as_partial_success() -> None:
    recorded = RecordedTransport(
        [
            serve("query_rules", fixture("firewall/rule-ids.json")),
            serve("get_rules", fixture("errors/500-internal.json")),
        ]
    )
    stdout, code = run(["firewall", "rule", "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"
