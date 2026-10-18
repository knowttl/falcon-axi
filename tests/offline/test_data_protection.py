"""Data Protection reads match falcon-mcp modules/data_security.py at ece8575.

The fixtures use its classification_properties and policy_properties shapes;
falconpy's generated endpoint table supplies query and hydration limits.
"""

import shlex
from typing import Any

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize(
    "noun,query_op,get_op,ids_file,entities_file,flags",
    [
        (
            "classification",
            "queries_classification_get_v2",
            "entities_classification_get_v2",
            "classification-ids",
            "classifications",
            [],
        ),
        ("data-policy", "queries_policy_get_v2", "entities_policy_get_v2", "policy-ids", "policies", ["--platform", "win"]),
    ],
)
def test_list_queries_then_hydrates_in_query_order(
    noun: str, query_op: str, get_op: str, ids_file: str, entities_file: str, flags: list[str]
) -> None:
    recorded = RecordedTransport(
        [
            serve(query_op, fixture(f"data-protection/{ids_file}.json")),
            serve(get_op, fixture(f"data-protection/{entities_file}.json")),
        ]
    )
    stdout, code = run([noun, "list", *flags, "--filter", "name:'Synthetic*'", "--sort", "name.asc"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "synthetic-sensitive-cid" not in stdout
    assert "synthetic-classification-01" in stdout or "synthetic-policy-01" in stdout
    query = recorded.operation_requests(query_op)[0].query
    assert query == {
        "limit": 20,
        "offset": 0,
        "filter": "name:'Synthetic*'",
        "sort": "name.asc",
        **({"platform_name": "win"} if flags else {}),
    }
    if noun == "classification":
        assert stdout.index("synthetic-classification-01") < stdout.index("synthetic-classification-02")
    assert len(recorded.operation_requests(get_op)) == 1


@pytest.mark.parametrize(
    "noun,get_op,id,filename,detail",
    [
        ("classification", "entities_classification_get_v2", "synthetic-classification-01", "classifications", "block,true"),
        ("data-policy", "entities_policy_get_v2", "synthetic-policy-01", "policies", "enable_content_inspection: true"),
    ],
)
def test_show_retains_properties_and_redacts_cid(noun: str, get_op: str, id: str, filename: str, detail: str) -> None:
    recorded = RecordedTransport([serve(get_op, fixture(f"data-protection/{filename}.json"))])
    stdout, code = run([noun, "show", id], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert detail in stdout
    assert "synthetic-sensitive-cid" not in stdout
    assert recorded.operation_requests(get_op)[0].query == {"ids": (id,)}


@pytest.mark.parametrize(
    "noun,plural,flags,query_op,get_op",
    [
        ("classification", "classifications", [], "queries_classification_get_v2", "entities_classification_get_v2"),
        ("data-policy", "policies", ["--platform", "mac"], "queries_policy_get_v2", "entities_policy_get_v2"),
        ("data-policy", "policies", ["--platform", "win"], "queries_policy_get_v2", "entities_policy_get_v2"),
    ],
)
def test_empty_list_skips_hydration(noun: str, plural: str, flags: list[str], query_op: str, get_op: str) -> None:
    recorded = RecordedTransport([serve(query_op, response(200, {"resources": []}))])
    stdout, code = run([noun, "list", *flags], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout) == {plural: f"0 {plural} matching this query"}
    assert recorded.operation_requests(get_op) == []


@pytest.mark.parametrize(
    "noun,plural,flags,query_op,get_op",
    [
        ("classification", "classifications", [], "queries_classification_get_v2", "entities_classification_get_v2"),
        ("data-policy", "policies", ["--platform", "mac"], "queries_policy_get_v2", "entities_policy_get_v2"),
        ("data-policy", "policies", ["--platform", "win"], "queries_policy_get_v2", "entities_policy_get_v2"),
    ],
)
def test_empty_continuation_reports_exhaustion(
    noun: str, plural: str, flags: list[str], query_op: str, get_op: str
) -> None:
    ids = [f"synthetic-{noun}-{i}" for i in range(20)]
    recorded = RecordedTransport(
        [
            serve(query_op, lambda args: response(200, {"resources": ids if args.query["offset"] == 0 else []})),
            serve(get_op, response(200, {"resources": [{"id": id, "name": id} for id in ids]})),
        ]
    )
    stdout, code = run([noun, "list", *flags], recorded, CREDENTIAL_ENV)
    assert code == 0
    first_page = decode(stdout)
    assert first_page["count"] == "20 of unknown total"
    assert len(first_page[plural]) == 20
    next_argv = shlex.split(first_page["help"][-1].split("`")[1])[1:]
    stdout, code = run(next_argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout) == {plural: f"no more {plural}"}
    assert [args.query["offset"] for args in recorded.operation_requests(query_op)] == [0, 20]
    assert len(recorded.operation_requests(get_op)) == 1


@pytest.mark.parametrize(
    "status,body,expected,exit_code",
    [
        (403, {}, "SCOPE_DENIED", 1),
        (404, {}, "NOT_FOUND", 1),
        (200, {"resources": []}, "NOT_FOUND", 1),
        (400, {"errors": [{"message": "Invalid FQL filter"}]}, "FQL_INVALID", 2),
    ],
)
def test_errors_offer_data_protection_guidance(status: int, body: dict[str, Any], expected: str, exit_code: int) -> None:
    recorded = RecordedTransport([serve("entities_classification_get_v2", response(status, body))])
    stdout, code = run(["classification", "show", "synthetic-missing"], recorded, CREDENTIAL_ENV)
    assert code == exit_code
    assert expected in stdout
    assert "detection list" not in stdout


def test_large_query_chunks_hydration_at_100_ids() -> None:
    ids = [f"synthetic-classification-{i}" for i in range(205)]
    recorded = RecordedTransport(
        [
            serve("queries_classification_get_v2", response(200, {"resources": ids})),
            serve(
                "entities_classification_get_v2",
                lambda args: response(200, {"resources": [{"id": id, "name": id} for id in reversed(args.query["ids"])]}),
            ),
        ]
    )
    stdout, code = run(["classification", "list", "--limit", "500"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "count: 205 of unknown total" in stdout
    assert [len(args.query["ids"]) for args in recorded.operation_requests("entities_classification_get_v2")] == [100, 100, 5]


def test_policy_cursor_preserves_platform_filter_and_sort() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "queries_policy_get_v2",
                response(200, {"resources": ["synthetic-policy-01"], "meta": {"pagination": {"total": 3}}}),
            ),
            serve("entities_policy_get_v2", fixture("data-protection/policies.json")),
        ]
    )
    argv = [
        "data-policy",
        "list",
        "--platform",
        "mac",
        "--filter",
        "is_enabled:true",
        "--sort",
        "precedence.asc",
        "--limit",
        "1",
    ]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    suggestion = decode(stdout)["help"][-1].split("`")[1]
    next_argv = shlex.split(suggestion)[1:]
    _, code = run(next_argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    assert recorded.operation_requests("queries_policy_get_v2")[-1].query == {
        "platform_name": "mac",
        "filter": "is_enabled:true",
        "sort": "precedence.asc",
        "limit": 1,
        "offset": 1,
    }
    altered = ["win" if arg == "mac" else arg for arg in next_argv]
    stdout, code = run(altered, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert "this cursor does not continue" in stdout
    assert len(recorded.operation_requests("queries_policy_get_v2")) == 2


@pytest.mark.parametrize("offset,has_cursor", [(9999, True), (10000, False)])
def test_offset_wall_discloses_remaining_results(offset: int, has_cursor: bool) -> None:
    context = CursorContext(
        operation="queries_classification_get_v2",
        client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
        origin="https://api.crowdstrike.com",
        query="[null,null]",
    )
    token = encode_cursor(offset, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    recorded = RecordedTransport(
        [
            serve(
                "queries_classification_get_v2",
                response(200, {"resources": ["synthetic-classification-01"], "meta": {"pagination": {"total": 10002}}}),
            ),
            serve("entities_classification_get_v2", fixture("data-protection/classifications.json")),
        ]
    )
    stdout, code = run(["classification", "list", "--limit", "1", "--cursor", token], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert ("continuation_cursor:" in stdout) == has_cursor
    assert ("stop_reason: pagination_limit" in stdout) == (not has_cursor)


@pytest.mark.parametrize(
    "argv",
    [
        ["data-policy", "list"],
        ["data-policy", "list", "--platform", "linux"],
        ["classification", "list", "--sort", "precedence.asc"],
        ["classification", "list", "--cursor", "tampered"],
    ],
)
def test_invalid_input_makes_no_operation_request(argv: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not any(kind == "operation" for kind, _ in recorded.requests)
