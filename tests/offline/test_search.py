"""The NG-SIEM search domain and captain exception N1 (docs/design/v1.md §3.3, §4.3, §10.2)."""

import re

import pytest

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport.operations import OPERATIONS, path_arguments
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

QUERY = "#event_simpleName=ProcessRollup2 | head(2)"
STARTED = [serve("StartSearchV1", fixture("ngsiem/start-search.json"))]
DONE = [serve("GetSearchStatusV1", fixture("ngsiem/search-status-done.json"))]


def test_search_start_is_one_request_that_returns_the_job_identifier() -> None:
    recorded = RecordedTransport(STARTED)
    stdout, exit_code = run(["search", "start", "--query", QUERY], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "search_id: synthetic-search-job-01" in stdout
    assert "repository: search-all" in stdout
    assert len(recorded.requests) == 2  # the token mint and one start
    args = recorded.operation_requests("StartSearchV1")[0]
    assert args.path_params == {"repository": "search-all"}
    assert args.body["queryString"] == QUERY


def test_the_since_window_reaches_the_api_as_an_epoch_millisecond_span() -> None:
    recorded = RecordedTransport(STARTED)
    run(["search", "start", "--query", QUERY, "--since", "7d"], recorded, dict(CREDENTIAL_ENV))
    body = recorded.operation_requests("StartSearchV1")[0].body
    assert body["end"] - body["start"] == 7 * 86_400 * 1_000


def test_a_missing_or_blank_query_is_refused_before_the_job_is_started() -> None:
    recorded = RecordedTransport([])
    for argv in (["search", "start"], ["search", "start", "--query", "   "]):
        stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 2
        assert "search start requires a CQL query" in stdout
    assert recorded.operation_requests("StartSearchV1") == []


def test_search_status_renders_the_events_and_the_query_the_api_actually_parsed() -> None:
    recorded = RecordedTransport(DONE)
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^state: done$", stdout, re.MULTILINE)
    assert re.search(r"^count: 2 of 2 matching events$", stdout, re.MULTILINE)
    assert re.search(r"^events_scanned: 148231$", stdout, re.MULTILINE)
    assert f"parsed_query: {QUERY}" in stdout
    assert "events[2]{ComputerName,FileName,UserName,timestamp}:" in stdout
    assert recorded.operation_requests("GetSearchStatusV1")[0].path_params == {
        "repository": "search-all",
        "id": "synthetic-search-job-01",
    }


def test_search_events_redact_the_tenant_cid_fields() -> None:
    """A real-shaped event carries the tenant CID in `cid` and `#repo.cid`; neither value is printed."""
    cid = "0123456789abcdef0123456789abcdef"
    body = {
        "cancelled": False,
        "done": True,
        "events": [
            {
                "#repo.cid": cid,
                "cid": cid,
                "ComputerName": "WIN-DC-01",
                "FileName": "powershell.exe",
                "timestamp": "2026-07-28T09:14:02Z",
            }
        ],
        "metaData": {
            "eventCount": 1,
            "filterQuery": {"queryString": "#event_simpleName=ProcessRollup2 | head(1)"},
            "isAggregate": False,
            "processedEvents": 12,
        },
    }
    recorded = RecordedTransport([serve("GetSearchStatusV1", response(200, body))])
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert cid not in stdout
    assert "[redacted]" in stdout
    assert "WIN-DC-01" in stdout


def test_a_running_job_says_so_rather_than_reporting_zero_events() -> None:
    recorded = RecordedTransport([serve("GetSearchStatusV1", fixture("ngsiem/search-status-running.json"))])
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^state: running$", stdout, re.MULTILINE)
    assert "count:" not in stdout
    assert "again in a few seconds" in stdout


def test_a_done_job_with_no_rows_is_a_definitive_empty_state() -> None:
    recorded = RecordedTransport([serve("GetSearchStatusV1", fixture("ngsiem/search-status-empty.json"))])
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "events: 0 events matched this search" in stdout


def test_a_cancelled_job_reports_cancelled_rather_than_an_empty_result() -> None:
    body = {"cancelled": True, "done": False, "events": []}
    recorded = RecordedTransport([serve("GetSearchStatusV1", response(200, body))])
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^state: cancelled$", stdout, re.MULTILINE)


def test_search_stop_cancels_one_job_and_confirms_it() -> None:
    recorded = RecordedTransport([serve("StopSearchV1", fixture("ngsiem/stop-search.json"))])
    stdout, exit_code = run(["search", "stop", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "stopped: synthetic-search-job-01" in stdout
    assert recorded.operation_requests("StopSearchV1")[0].path_params["id"] == "synthetic-search-job-01"


def test_an_unknown_job_is_reported_without_fql_advice() -> None:
    for command, id in (("status", "GetSearchStatusV1"), ("stop", "StopSearchV1")):
        recorded = RecordedTransport([serve(id, fixture("ngsiem/job-not-found.json"))])
        stdout, exit_code = run(["search", command, "synthetic-missing-job"], recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 1
        assert "code: NOT_FOUND" in stdout
        assert "no NG-SIEM search job matched that identifier" in stdout
        assert "FQL" not in stdout


def test_a_rejected_search_is_answered_in_cql_terms_rather_than_fql_terms() -> None:
    rejected = response(400, {"errors": [{"code": 400, "message": "invalid query string"}]})
    recorded = RecordedTransport([serve("StartSearchV1", rejected)])
    stdout, exit_code = run(["search", "start", "--query", "SELECT * FROM events"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "NG-SIEM rejected this search" in stdout
    assert "CQL is pipe-based" in stdout
    assert "FQL uses + for AND" not in stdout


def test_a_scope_failure_on_a_write_scoped_operation_asks_for_the_write_scope() -> None:
    recorded = RecordedTransport([serve("StartSearchV1", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["search", "start", "--query", QUERY], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: SCOPE_DENIED" in stdout
    assert "not permitted to run NG-SIEM searches" in stdout
    assert "NGSIEM:write" in stdout
    assert "read only" not in stdout


def test_a_scope_failure_on_the_poll_step_asks_only_for_the_read_scope() -> None:
    recorded = RecordedTransport([serve("GetSearchStatusV1", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "NGSIEM:read" in stdout
    assert "NGSIEM:write" not in stdout


def test_a_path_variable_that_could_retarget_the_route_is_refused_before_the_request() -> None:
    recorded = RecordedTransport(STARTED)
    for repository in ("../devices/entities", "search%2Fall", "search\\all", ".", ".."):
        stdout, exit_code = run(
            ["search", "start", "--query", QUERY, "--repository", repository], recorded, dict(CREDENTIAL_ENV)
        )
        assert exit_code == 2, repository
        assert "must be a plain name" in stdout
    assert recorded.operation_requests("StartSearchV1") == []


def test_the_path_guard_rejects_a_variable_set_that_does_not_match_the_route() -> None:
    for id, supplied in (
        ("StartSearchV1", {}),
        ("StartSearchV1", {"repository": "search-all", "id": "job"}),
        ("GetSearchStatusV1", {"repository": "search-all"}),
        ("combinedQueryVulnerabilities", {"repository": "search-all"}),
    ):
        with pytest.raises(CliError) as error:
            path_arguments(OPERATIONS[id], supplied)
        assert error.value.code == "READ_ONLY_VIOLATION"


def test_a_non_default_repository_is_replayed_into_every_follow_up_command() -> None:
    recorded = RecordedTransport(STARTED)
    stdout, _ = run(["search", "start", "--query", QUERY, "--repository", "xdr"], recorded, dict(CREDENTIAL_ENV))
    assert "search status synthetic-search-job-01 --repository xdr" in stdout
    assert "search stop synthetic-search-job-01 --repository xdr" in stdout

    polled = RecordedTransport([serve("GetSearchStatusV1", fixture("ngsiem/search-status-running.json"))])
    stdout, _ = run(["search", "status", "synthetic-search-job-01", "--repository", "xdr"], polled, dict(CREDENTIAL_ENV))
    assert "search status synthetic-search-job-01 --repository xdr" in stdout
    assert polled.operation_requests("GetSearchStatusV1")[0].path_params["repository"] == "xdr"
