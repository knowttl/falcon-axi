"""SARIF parity with falcon-mcp ece8575 modules/serverless.py and its unit fixture.

The resources envelope follows CrowdStrike/gofalcon 29988d8
falcon/models/vulnerabilities_vulnerability_entity_s_a_r_i_f_response.go.
"""

import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

OPERATION = "GetCombinedVulnerabilitiesSARIF"
ARGV = ["serverless", "list", "--filter", "cloud_provider:'aws'"]


@pytest.mark.parametrize("envelope", ["direct", "resources"])
def test_sarif_runs_preserve_rules_and_results_without_inventing_a_vulnerability_count(envelope: str) -> None:
    answer = fixture("serverless/vulnerabilities-page.json")
    body = answer.body if envelope == "direct" else {"resources": answer.body}
    recorded = RecordedTransport([serve(OPERATION, response(200, body))])
    stdout, code = run([*ARGV, "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    document = decode(stdout)
    assert document["count"] == "1 SARIF runs; vulnerability total unknown"
    assert document["runs"] == answer.body["runs"]
    assert recorded.operation_requests(OPERATION)[0].query == {
        "filter": "cloud_provider:'aws'",
        "sort": "cve_id",
        "limit": 2,
        "offset": 0,
    }


def test_sarif_continuation_advances_by_source_record_budget_instead_of_run_count() -> None:
    recorded = RecordedTransport([serve(OPERATION, fixture("serverless/vulnerabilities-page.json"))])
    stdout, code = run([*ARGV, "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    next_command = shlex.split(decode(stdout)["help"][-1].split("`", 2)[1])[1:]
    resumed = RecordedTransport([serve(OPERATION, response(200, {"runs": []}))])
    next_stdout, next_code = run(next_command, resumed, dict(CREDENTIAL_ENV))
    assert next_code == 0
    assert "0 serverless SARIF runs" in next_stdout
    assert "continuation_cursor" not in next_stdout
    assert resumed.operation_requests(OPERATION)[0].query == {
        "filter": "cloud_provider:'aws'",
        "sort": "cve_id",
        "limit": 2,
        "offset": 2,
    }


@pytest.mark.parametrize("argv", [["serverless", "list"], ["serverless", "list", "--filter", " "]])
def test_serverless_requires_a_nonblank_filter_before_authentication(argv: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert not recorded.requests


@pytest.mark.parametrize("body", [{}, {"runs": {}}, {"runs": ["invalid"]}, {"resources": []}])
def test_malformed_sarif_fails_instead_of_reporting_no_vulnerabilities(body: dict) -> None:
    recorded = RecordedTransport([serve(OPERATION, response(200, body))])
    stdout, code = run(ARGV, recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


@pytest.mark.parametrize(
    "status,body,error,exit_code",
    [
        (403, {}, "SCOPE_DENIED", 1),
        (400, {"errors": [{"message": "invalid FQL filter"}]}, "FQL_INVALID", 2),
        (500, {}, "UPSTREAM_ERROR", 1),
    ],
)
def test_serverless_failures_are_structured(status: int, body: dict, error: str, exit_code: int) -> None:
    recorded = RecordedTransport([serve(OPERATION, response(status, body))])
    stdout, code = run(ARGV, recorded, dict(CREDENTIAL_ENV))
    assert code == exit_code
    assert decode(stdout)["code"] == error


def test_sarif_cursor_cannot_continue_a_different_filter() -> None:
    recorded = RecordedTransport([serve(OPERATION, fixture("serverless/vulnerabilities-page.json"))])
    stdout, code = run(ARGV, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    cursor = decode(stdout)["continuation_cursor"]
    resumed = RecordedTransport([])
    _, next_code = run(["serverless", "list", "--filter", "severity:'HIGH'", "--cursor", cursor], resumed, dict(CREDENTIAL_ENV))
    assert next_code == 2
    assert not resumed.operation_requests(OPERATION)
