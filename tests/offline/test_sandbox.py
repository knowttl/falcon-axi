"""Existing report lookup through the CLI, with no Falcon network access."""

import re

import pytest

from falcon_axi.cli import run
from falcon_axi.transport.operations import OPERATIONS
from falcon_axi.transport.types import FalconResponse
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

HASH = "0" * 64


@pytest.mark.parametrize("hash", ["", "0" * 63, "0" * 65, "g" * 64, "０" * 64, "'" + "0" * 63])
def test_invalid_hash_is_rejected_before_authentication(hash: str) -> None:
    transport = RecordedTransport([])
    stdout, code = run(["sandbox", "list", "--sha256", hash], transport, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert transport.requests == []


@pytest.mark.parametrize("flags", [[], ["--sha256", HASH, "--filter", "verdict:'malicious'"], ["--filter", " "]])
def test_exactly_one_nonempty_selector_is_required(flags: list[str]) -> None:
    transport = RecordedTransport([])
    stdout, code = run(["sandbox", "list", *flags], transport, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert transport.requests == []


def test_hash_lookup_hydrates_in_query_order_and_projects_only_safe_fields() -> None:
    transport = RecordedTransport(
        [
            serve("QueryReports", fixture("sandbox/query.json")),
            serve("GetSummaryReports", fixture("sandbox/summaries.json")),
        ]
    )
    stdout, code = run(["sandbox", "list", "--sha256", HASH], transport, dict(CREDENTIAL_ENV))
    assert code == 0
    assert transport.operation_requests("QueryReports")[0].query == {
        "filter": f"sandbox.sha256:'{HASH}'",
        "limit": 20,
        "offset": "0",
    }
    assert transport.operation_requests("GetSummaryReports")[0].query == {
        "ids": ("synthetic-report-01", "synthetic-report-02"),
    }
    assert stdout.index("synthetic-report-01") < stdout.index("synthetic-report-02")
    assert "sandbox_reports[3]{id,verdict,threat_score,environment_description,submit_name,created_timestamp}" in stdout
    assert "2 of 2 total reports" in stdout
    assert "Synthetic Windows alternate" in stdout
    assert "synthetic-user" not in stdout
    assert "synthetic-artifact" not in stdout
    assert "submit_url" not in stdout


def test_show_keeps_each_environment_and_adds_selected_details() -> None:
    transport = RecordedTransport([serve("GetSummaryReports", fixture("sandbox/summaries.json"))])
    stdout, code = run(["sandbox", "show", "synthetic-report-01"], transport, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "PE executable" in stdout
    assert "synthetic-classification" in stdout
    assert "https://example.invalid/synthetic" in stdout
    assert HASH in stdout
    assert "Synthetic Windows alternate" in stdout
    assert "synthetic-report-02" not in stdout
    assert "synthetic-user" not in stdout
    assert "synthetic-artifact" not in stdout


def test_empty_query_explains_license_and_data_without_hydrating() -> None:
    transport = RecordedTransport([serve("QueryReports", fixture("sandbox/empty.json"))])
    stdout, code = run(["sandbox", "list", "--sha256", HASH], transport, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "not licensed or no data" in stdout
    assert "Falcon Intelligence" in stdout
    assert transport.operation_requests("GetSummaryReports") == []


@pytest.mark.parametrize(
    "operation,argv",
    [
        ("QueryReports", ["sandbox", "list", "--sha256", HASH]),
        ("GetSummaryReports", ["sandbox", "show", "synthetic-report-01"]),
    ],
)
def test_scope_denied_explains_falcon_intelligence_license(operation: str, argv: list[str]) -> None:
    transport = RecordedTransport([serve(operation, fixture("errors/403-scope.json"))])
    stdout, code = run(argv, transport, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Sandbox (Falcon Intelligence):read" in stdout
    assert "Falcon Intelligence (Sandbox)" in stdout
    assert "subscription" in stdout


@pytest.mark.parametrize(
    "answer,expected",
    [
        (response(404, {}), "NOT_FOUND"),
        (response(200, {"resources": []}), "NOT_FOUND"),
        (response(200, {"resources": [{"id": "different-report"}]}), "UPSTREAM_ERROR"),
    ],
)
def test_show_never_attributes_missing_or_different_reports(answer: FalconResponse, expected: str) -> None:
    transport = RecordedTransport([serve("GetSummaryReports", answer)])
    stdout, code = run(["sandbox", "show", "synthetic-report-01"], transport, dict(CREDENTIAL_ENV))
    assert code == 1
    assert expected in stdout


def test_cursor_preserves_hash_and_continues_query_offsets() -> None:
    transport = RecordedTransport(
        [
            serve("QueryReports", response(200, {"resources": ["synthetic-report-01"]})),
            serve("GetSummaryReports", fixture("sandbox/summaries.json")),
        ]
    )
    stdout, code = run(["sandbox", "list", "--sha256", HASH, "--limit", "1"], transport, dict(CREDENTIAL_ENV))
    assert code == 0
    cursor = re.search(r"continuation_cursor: (\S+)", stdout)
    assert cursor is not None
    assert f"--sha256 {HASH} --cursor" in stdout
    next_page = RecordedTransport([serve("QueryReports", fixture("sandbox/empty.json"))])
    _, code = run(["sandbox", "list", "--sha256", HASH, "--cursor", cursor[1]], next_page, dict(CREDENTIAL_ENV))
    assert code == 0
    assert next_page.operation_requests("QueryReports")[0].query["offset"] == "1"  # type: ignore[index]
    refused = RecordedTransport([])
    stdout, code = run(["sandbox", "list", "--sha256", "1" * 64, "--cursor", cursor[1]], refused, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "does not continue" in stdout
    assert refused.operation_requests("QueryReports") == []


def test_submission_upload_and_downloads_are_not_registered() -> None:
    assert {"Submit", "UploadSampleV2", "GetArtifacts", "GetSampleV2"}.isdisjoint(OPERATIONS)


def test_fql_selector_is_passed_through() -> None:
    transport = RecordedTransport([serve("QueryReports", fixture("sandbox/empty.json"))])
    stdout, code = run(["sandbox", "list", "--filter", "verdict:'malicious'"], transport, dict(CREDENTIAL_ENV))
    assert code == 0
    assert transport.operation_requests("QueryReports")[0].query == {
        "filter": "verdict:'malicious'",
        "limit": 20,
        "offset": "0",
    }
    assert "not licensed or no data" in stdout


def test_missing_hydrated_report_is_not_presented_as_a_complete_page() -> None:
    transport = RecordedTransport(
        [
            serve("QueryReports", fixture("sandbox/query.json")),
            serve("GetSummaryReports", response(200, {"resources": [{"id": "synthetic-report-01"}]})),
        ]
    )
    stdout, code = run(["sandbox", "list", "--sha256", HASH], transport, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout
    assert "omitted a requested" in stdout
