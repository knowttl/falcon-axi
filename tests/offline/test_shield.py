"""Exercise Shield through the CLI with wholly synthetic responses, never a tenant."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

OP = "GetSecurityChecksV3"


def test_list_sends_documented_filters_and_minimal_rows() -> None:
    recorded = RecordedTransport([serve(OP, fixture("shield/checks.json"))])
    stdout, code = run(["shield", "list", "--status", "failed", "--impact", "HIGH"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "1 of unknown total" in stdout
    assert "{id,name,status,impact}" in stdout
    assert "remediation_plan" not in stdout
    assert "continuation_cursor" not in stdout
    assert recorded.operation_requests(OP)[0].query == {"status": "Failed", "impact": "High", "limit": 20, "offset": 0}


@pytest.mark.parametrize("flag,value", [("status", "made-up"), ("impact", "critical"), ("limit", "101")])
def test_invalid_values_fail_before_authentication(flag: str, value: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["shield", "list", f"--{flag}", value], recorded, CREDENTIAL_ENV)
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


def test_cursor_continues_the_same_query_and_preserves_filters() -> None:
    recorded = RecordedTransport([serve(OP, response(200, [{"id": "synthetic-check-01"}]))])
    argv = ["shield", "list", "--status", "failed", "--impact", "high", "--limit", "1"]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "1 of unknown total" in stdout
    cursor = stdout.split("continuation_cursor: ")[1].splitlines()[0]
    assert "--status failed --impact high --limit 1 --cursor" in stdout
    continued = RecordedTransport([serve(OP, response(200, []))])
    empty, code = run([*argv, "--cursor", cursor], continued, CREDENTIAL_ENV)
    assert code == 0
    assert "no more Shield checks" in empty
    assert continued.operation_requests(OP)[0].query == {"status": "Failed", "impact": "High", "limit": 1, "offset": 1}
    refused = RecordedTransport([])
    bad, code = run(["shield", "list", "--status", "passed", "--cursor", cursor], refused, CREDENTIAL_ENV)
    assert code == 2
    assert "VALIDATION_ERROR" in bad
    assert refused.operation_requests(OP) == []


def test_show_requests_one_id_and_redacts_detail() -> None:
    recorded = RecordedTransport([serve(OP, fixture("shield/checks.json"))])
    stdout, code = run(["shield", "show", "synthetic-check-01"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "remediation_plan: Enable MFA" in stdout
    assert "synthetic-shield-cid" not in stdout
    assert "[redacted]" in stdout
    assert recorded.operation_requests(OP)[0].query == {"id": "synthetic-check-01"}


@pytest.mark.parametrize(
    "status,records,expected",
    [(200, [], "NOT_FOUND"), (404, [], "NOT_FOUND"), (200, [{"id": "other"}], "UPSTREAM_ERROR")],
)
def test_show_refuses_absent_or_mismatched_checks(status: int, records: list, expected: str) -> None:
    recorded = RecordedTransport([serve(OP, response(status, records))])
    stdout, code = run(["shield", "show", "synthetic-check-01"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert expected in stdout


def test_show_truncation_has_a_full_escape_hatch() -> None:
    record = {"id": "check", "remediation_plan": {"text": "x" * 900}}
    recorded = RecordedTransport([serve(OP, response(200, [record]))])
    short, code = run(["shield", "show", "check"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "900 chars total" in short
    assert "shield show check --full" in short
    full, code = run(["shield", "show", "check", "--full"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "x" * 900 in full
    assert "truncated" not in full


@pytest.mark.parametrize("flags", [[], ["--full"]])
def test_show_redacts_complete_private_keys_before_preview(flags: list[str]) -> None:
    private_key = "-----BEGIN PRIVATE KEY-----\n" + "synthetic-key-material" * 60 + "\n-----END PRIVATE KEY-----"
    record = {
        "id": "check",
        "remediation_plan": private_key,
        "details": {"content": private_key},
        "matches": [private_key, {"content": private_key}],
    }
    recorded = RecordedTransport([serve(OP, response(200, [record]))])
    stdout, code = run(["shield", "show", "check", *flags], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout) == {
        "check": {
            "id": "check",
            "remediation_plan": "[redacted]",
            "details": {"content": "[redacted]"},
            "matches": ["[redacted]", {"content": "[redacted]"}],
        }
    }


def test_scope_denied_names_the_required_read_scope() -> None:
    recorded = RecordedTransport([serve(OP, fixture("errors/403-scope.json"))])
    stdout, code = run(["shield", "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "SaaS Security:read" in stdout


def test_empty_array_is_a_successful_empty_list() -> None:
    recorded = RecordedTransport([serve(OP, response(200, []))])
    stdout, code = run(["shield", "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "0 Shield checks matching this query" in stdout


@pytest.mark.parametrize("argv", [["shield", "list"], ["shield", "show", "check"]])
@pytest.mark.parametrize(
    "body",
    [
        None,
        {},
        {"resources": []},
        {"resources": [{"id": "check"}], "meta": {"pagination": {"total": 1}}},
        "invalid",
        [None],
        [{}],
        [{"id": 1}],
        [{"id": ""}],
        [{"id": "check"}, {}],
    ],
)
def test_malformed_success_body_fails_instead_of_hiding_checks(argv: list[str], body: object) -> None:
    recorded = RecordedTransport([serve(OP, response(200, body))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout
    assert "NOT_FOUND" not in stdout
    assert "0 Shield checks" not in stdout


@pytest.mark.parametrize("supplied,canonical", [("na", "NA"), ("not available", "Not Available")])
def test_additional_statuses_are_sent_and_rendered(supplied: str, canonical: str) -> None:
    recorded = RecordedTransport([serve(OP, response(200, [{"id": "check", "status": canonical}]))])
    stdout, code = run(["shield", "list", "--status", supplied], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert canonical in stdout
    assert recorded.operation_requests(OP)[0].query["status"] == canonical
    detail, code = run(["shield", "show", "check"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert f"status: {canonical}" in detail
