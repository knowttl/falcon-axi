"""Resource-envelope validation preserves command-specific HTTP error behavior."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, Responder, response, serve

CASES = [
    (["actor", "show", "123456"], "GetIntelActorEntities", [], "Actors (Falcon Intelligence):read"),
    (["report", "show", "123456"], "GetIntelReportEntities", [], "Reports (Falcon Intelligence):read"),
    (["vuln", "show", "synthetic-id"], "getVulnerabilities", [], "Vulnerabilities:read"),
    (
        ["cve", "list"],
        "GetVulnerabilities",
        [serve("QueryVulnerabilities", response(200, {"resources": ["CVE-2099-0001"]}))],
        "Vulnerabilities (Falcon Intelligence):read",
    ),
    (
        ["iot", "list"],
        "get_iot_hosts",
        [serve("query_iot_hostsV2", response(200, {"resources": ["synthetic-id"]}))],
        "Falcon Discover IoT:read",
    ),
]


@pytest.mark.parametrize("argv,operation,prior,scope", CASES)
@pytest.mark.parametrize("status,expected", [(401, "AUTH_FAILED"), (403, "SCOPE_DENIED")])
def test_http_errors_precede_resource_validation(
    argv: list[str], operation: str, prior: list[Responder], scope: str, status: int, expected: str
) -> None:
    recorded = RecordedTransport([*prior, serve(operation, response(status, {"errors": []}))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == expected


@pytest.mark.parametrize("argv,operation,prior,scope", CASES)
def test_scope_denied_keeps_required_scope_guidance(
    argv: list[str], operation: str, prior: list[Responder], scope: str
) -> None:
    recorded = RecordedTransport([*prior, serve(operation, response(403, {"errors": []}))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["required_scopes"] == [scope]
    assert scope in decode(stdout)["help"][0]


@pytest.mark.parametrize("argv,operation,prior,scope", CASES)
@pytest.mark.parametrize("body", [{}, {"resources": None}, {"resources": "invalid"}])
def test_successful_envelopes_still_require_resource_arrays(
    argv: list[str], operation: str, prior: list[Responder], scope: str, body: object
) -> None:
    recorded = RecordedTransport([*prior, serve(operation, response(200, body))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


@pytest.mark.parametrize(
    "noun,operation",
    [("actor", "GetIntelActorEntities"), ("report", "GetIntelReportEntities"), ("vuln", "getVulnerabilities")],
)
def test_detail_404_without_resources_is_not_found(noun: str, operation: str) -> None:
    recorded = RecordedTransport([serve(operation, response(404, {"errors": []}))])
    stdout, code = run([noun, "show", "synthetic-id"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"
    assert f"falcon-axi {noun} list" in decode(stdout)["help"][0]


@pytest.mark.parametrize(
    "noun,query,entity,identifier,key",
    [
        ("cve", "QueryVulnerabilities", "GetVulnerabilities", "CVE-2099-0001", "cves"),
        ("iot", "query_iot_hostsV2", "get_iot_hosts", "synthetic-id", "iot"),
    ],
)
def test_hydration_404_without_resources_keeps_empty_rows(
    noun: str, query: str, entity: str, identifier: str, key: str
) -> None:
    recorded = RecordedTransport(
        [
            serve(query, response(200, {"resources": [identifier], "meta": {"pagination": {"total": 1}}})),
            serve(entity, response(404, {"errors": []})),
        ]
    )
    stdout, code = run([noun, "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)[key] == []
    assert decode(stdout)["count"] == "0 of 1 total"
