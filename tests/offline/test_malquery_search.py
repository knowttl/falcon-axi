"""N4's CLI lifecycle and sealed boundary, using synthetic documented responses only."""

from dataclasses import replace

import pytest
import requests_mock
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.harness import mint_permit, send_permitted_request
from falcon_axi.transport.malquery import search_body
from falcon_axi.transport.operations import MALQUERY_SEARCH_IDS, _seal, operation
from falcon_axi.transport.types import PreparedOperation, RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

REQUEST_ID = "00000000-0000-4000-8000-000000000001"


def test_fuzzy_search_returns_bounded_metadata_and_sends_only_literal_patterns() -> None:
    recorded = RecordedTransport([serve("PostMalQueryFuzzySearchV1", fixture("malquery/fuzzy.json"))])
    stdout, code = run(
        ["malquery", "search", "--string", "SYNTHETIC", "--hex", "4D 5A", "--fuzzy", "--limit", "1"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    parsed = decode(stdout)
    assert parsed["samples"] == [{"sha256": "0" * 64, "family": "synthetic-family", "filetype": "pe64", "filesize": 4096}]
    assert parsed["partial"] is True
    assert recorded.operation_requests("PostMalQueryFuzzySearchV1")[0].body == {
        "patterns": [{"type": "ascii", "value": "SYNTHETIC"}, {"type": "hex", "value": "4d5a"}],
        "options": {"limit": 1},
    }


def test_exact_search_returns_a_request_id_and_status_reads_it_once() -> None:
    recorded = RecordedTransport(
        [
            serve("PostMalQueryExactSearchV1", fixture("malquery/exact.json")),
            serve("GetMalQueryRequestV1", fixture("malquery/status.json")),
        ]
    )
    stdout, code = run(["malquery", "search", "--string", "SYNTHETIC"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["request"] == {"id": REQUEST_ID, "status": "pending"}
    assert f"falcon-axi malquery status {REQUEST_ID}" in stdout
    stdout, code = run(["malquery", "status", REQUEST_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["request"] == {"id": REQUEST_ID, "status": "done"}
    assert decode(stdout)["samples"][0]["sha256"] == "0" * 64
    assert recorded.operation_requests("GetMalQueryRequestV1")[0].query == {"ids": (REQUEST_ID,)}
    assert len(recorded.requests) == 4


def test_status_caps_metadata_rows_and_preserves_request_status() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "GetMalQueryRequestV1",
                response(
                    200,
                    {
                        "meta": {"reqid": REQUEST_ID, "status": "done"},
                        "resources": [
                            {"sha256": "0" * 64, "family": "synthetic-family", "filetype": "pe64", "filesize": 4096},
                            {"sha256": "1" * 64, "family": "synthetic-other", "filetype": "pe32", "filesize": 2048},
                        ],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["malquery", "status", REQUEST_ID, "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    parsed = decode(stdout)
    assert parsed["request"] == {"id": REQUEST_ID, "status": "done"}
    assert parsed["samples"] == [{"sha256": "0" * 64, "family": "synthetic-family", "filetype": "pe64", "filesize": 4096}]
    assert parsed["partial"] is True
    assert "Results reached the requested limit; narrow the patterns to avoid an incomplete result" in parsed["help"]


@pytest.mark.parametrize(
    "flags",
    [
        [],
        ["--string", ""],
        ["--string", " "],
        ["--string", "a\nb"],
        ["--string", "é"],
        ["--string", "x" * 4097],
        ["--hex", "abc"],
        ["--hex", "??"],
        ["--hex", "0g"],
        ["--hex", "00" * 4097],
        ["--string", "valid", "--limit", "101"],
        ["--string", "valid", "--limit", "0"],
        ["--body", "{}"],
        ["--yara", "rule x {}"],
    ],
)
def test_invalid_search_inputs_make_no_request(flags) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["malquery", "search", *flags], recorded, {})
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert recorded.requests == []


@pytest.mark.parametrize("fuzzy", [[], ["--fuzzy"]])
def test_read_only_switch_blocks_both_searches_before_authentication(fuzzy) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["malquery", "search", "--string", "SYNTHETIC", *fuzzy], recorded, {"FALCON_AXI_READ_ONLY": "1"})
    assert code == 1
    assert decode(stdout)["code"] == "READ_ONLY_VIOLATION"
    assert recorded.requests == []


def test_status_is_permitted_under_read_only() -> None:
    recorded = RecordedTransport([serve("GetMalQueryRequestV1", fixture("malquery/status.json"))])
    stdout, code = run(["malquery", "status", REQUEST_ID], recorded, {**CREDENTIAL_ENV, "FALCON_AXI_READ_ONLY": "1"})
    assert code == 0
    assert decode(stdout)["request"]["status"] == "done"


@pytest.mark.parametrize("fuzzy,operation_id", [([], "PostMalQueryExactSearchV1"), (["--fuzzy"], "PostMalQueryFuzzySearchV1")])
def test_search_403_names_scope_license_and_exception(fuzzy, operation_id) -> None:
    recorded = RecordedTransport([serve(operation_id, fixture("errors/403-scope.json"))])
    stdout, code = run(["malquery", "search", "--string", "SYNTHETIC", *fuzzy], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["required_scopes"] == ["MalQuery:write"]
    assert "not licensed or not permitted" in stdout
    assert "exception N4" in stdout


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "PostMalQueryHuntV1"},
        {"scopes": ("MalQuery:read",)},
        {"scopes": ("MalQuery:write", "Hosts:read")},
        {"evidence": replace(operation("PostMalQueryExactSearchV1").evidence, doc_scope="Hosts: WRITE")},
        {"method": "GET"},
        {"path": "/malquery/queries/hunt/v1"},
        {"effect": "read"},
    ],
)
def test_n4_seal_rejects_wider_or_relabelled_descriptors(changes) -> None:
    assert MALQUERY_SEARCH_IDS == {"PostMalQueryExactSearchV1", "PostMalQueryFuzzySearchV1"}
    with pytest.raises(ValueError):
        _seal(replace(operation("PostMalQueryExactSearchV1"), **changes))


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"yara_rule": "rule x {}"},
        {"patterns": [{"type": "wide", "value": "x"}], "options": {"limit": 20}},
        {"patterns": [{"type": "hex", "value": "??"}], "options": {"limit": 20}},
        {"patterns": [{"type": "ascii", "value": "x"}], "options": {"limit": 101}},
        {"patterns": [{"type": "ascii", "value": "x"}], "options": {"limit": True}},
        {"patterns": [{"type": "ascii", "value": "x"}], "options": {"limit": 20, "app": "hunt"}},
    ],
)
def test_sink_refuses_unchecked_body_even_with_a_valid_permit(body) -> None:
    with requests_mock.Mocker() as mock:
        with pytest.raises(CliError) as error:
            send_permitted_request(
                PreparedOperation(
                    operation_id="PostMalQueryExactSearchV1",
                    origin="https://api.crowdstrike.com",
                    token="synthetic-token",
                    body=body,
                ),
                mint_permit(),
            )
        assert mock.request_history == []
    assert error.value.code == "READ_ONLY_VIOLATION"


@pytest.mark.parametrize("status", [429, 500, 503])
def test_search_posts_are_never_replayed(status) -> None:
    with requests_mock.Mocker() as mock:
        mock.post("https://api.crowdstrike.com/malquery/queries/exact-search/v1", json={}, status_code=status)
        answer = HttpTransport().request(
            "PostMalQueryExactSearchV1",
            RequestArgs(
                base_url="https://api.crowdstrike.com",
                token="synthetic-token",
                body=search_body("SYNTHETIC", None, 20),
            ),
        )
        assert answer.status == status
        assert len(mock.request_history) == 1


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"meta": {}},
        {"meta": {"reqid": "bad", "status": "pending"}},
        {"meta": {"reqid": REQUEST_ID, "status": "done"}, "errors": [{"code": 500}]},
        {"meta": {"reqid": REQUEST_ID, "status": "done"}, "resources": [None]},
    ],
)
def test_malformed_status_is_not_reported_as_no_matches(body) -> None:
    recorded = RecordedTransport([serve("GetMalQueryRequestV1", response(200, body))])
    stdout, code = run(["malquery", "status", REQUEST_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


def test_invalid_request_id_is_refused_before_authentication() -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["malquery", "status", "not-a-request"], recorded, {})
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert recorded.requests == []


@pytest.mark.parametrize(
    "operation_id,route",
    [
        ("PostMalQueryExactSearchV1", "queries/exact-search"),
        ("PostMalQueryFuzzySearchV1", "combined/fuzzy-search"),
    ],
)
def test_sink_sends_only_canonical_bounded_search_body(operation_id, route) -> None:
    body = search_body("SYNTHETIC", "4D 5A", 20)
    with requests_mock.Mocker() as mock:
        mock.post(f"https://api.crowdstrike.com/malquery/{route}/v1", json={"meta": {}}, status_code=200)
        answer = HttpTransport().request(
            operation_id,
            RequestArgs(
                base_url="https://api.crowdstrike.com",
                token="synthetic-token",
                body=body,
            ),
        )
        assert answer.status == 200
        assert mock.last_request.json() == body


def test_query_parameters_are_refused_at_preparation_and_at_sink() -> None:
    body = search_body("SYNTHETIC", None, 20)
    query = {"yara_rule": "rule x {}"}
    with requests_mock.Mocker() as mock:
        with pytest.raises(CliError, match="N4"):
            HttpTransport().request(
                "PostMalQueryExactSearchV1",
                RequestArgs(
                    base_url="https://api.crowdstrike.com",
                    token="synthetic-token",
                    body=body,
                    query=query,
                ),
            )
        with pytest.raises(CliError, match="N4"):
            send_permitted_request(
                PreparedOperation(
                    operation_id="PostMalQueryExactSearchV1",
                    origin="https://api.crowdstrike.com",
                    token="synthetic-token",
                    body=body,
                    query=query,
                ),
                mint_permit(),
            )
        assert mock.request_history == []


def test_status_rejects_a_different_request_id() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "GetMalQueryRequestV1",
                response(
                    200,
                    {
                        "meta": {"reqid": "00000000-0000-4000-8000-000000000002", "status": "done"},
                        "resources": [],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["malquery", "status", REQUEST_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


def test_empty_fuzzy_search_is_explicit() -> None:
    recorded = RecordedTransport([serve("PostMalQueryFuzzySearchV1", response(200, {"meta": {}, "resources": []}))])
    stdout, code = run(["malquery", "search", "--string", "SYNTHETIC", "--fuzzy"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 samples matched" in stdout
    assert "missing Falcon MalQuery licensing" in stdout


def test_fuzzy_search_preserves_the_upstream_total_without_claiming_completeness() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "PostMalQueryFuzzySearchV1",
                response(
                    200,
                    {
                        "meta": {"pagination": {"total": 5}},
                        "resources": [{"sha256": "0" * 64}],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["malquery", "search", "--string", "SYNTHETIC", "--fuzzy"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["count"] == "1 of 5 total"
    assert decode(stdout)["partial"] is True
