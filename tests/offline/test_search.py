"""The NG-SIEM search domain and captain exception N1 (docs/design/v1.md §3.3, §4.3, §10.2)."""

import json
import re
import subprocess
from typing import Any

import pytest
import requests_mock

from falcon_axi import search
from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport import HttpTransport, harness
from falcon_axi.transport.operations import OPERATIONS, path_arguments
from falcon_axi.transport.types import FalconResponse, RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

QUERY = "#event_simpleName=ProcessRollup2 | head(2)"
STARTED = [serve("StartSearchV1", fixture("ngsiem/start-search.json"))]
DONE = [serve("GetSearchStatusV1", fixture("ngsiem/search-status-done.json"))]


@pytest.mark.parametrize(("flags", "span"), [([], 86_400_000), (["--since", "7d"], 604_800_000)])
def test_host_usb_starts_the_fixed_bounded_search(flags: list[str], span: int) -> None:
    recorded = RecordedTransport(STARTED)
    stdout, exit_code = run(["host", "usb", "000000000000000000000000000000AB", *flags], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    request = recorded.operation_requests("StartSearchV1")[0]
    assert request.path_params == {"repository": "search-all"}
    assert request.body["queryString"] == (
        "#event_simpleName=/^(DcUsbDeviceConnected|DcUsbDeviceDisconnected|DcUsbDevicePolicyViolation)$/ "
        "aid=000000000000000000000000000000ab "
        "| table([@timestamp, #event_simpleName, ComputerName, DeviceManufacturer, DeviceProduct, "
        "DevicePropertyDeviceDescription, DeviceUsbClass, DcPolicyAction, event_platform], "
        "limit=200, sortby=@timestamp, order=desc)"
    )
    assert request.body["end"] - request.body["start"] == span
    assert "search status synthetic-search-job-01" in stdout
    assert recorded.operation_requests("GetSearchStatusV1") == []


@pytest.mark.parametrize("value", ["1", "true", "TRUE"])
def test_host_usb_read_only_refuses_job_creation_before_authentication(value: str) -> None:
    recorded = RecordedTransport(STARTED)
    stdout, exit_code = run(["host", "usb", "0" * 32], recorded, {**CREDENTIAL_ENV, "FALCON_AXI_READ_ONLY": value})
    assert exit_code == 1
    assert "READ_ONLY_VIOLATION" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "device_id",
    ["abc123", "0" * 31, "0" * 33, "g" * 32, "０" * 32, "0" * 32 + "\n", "*", "x | head(1)", '" OR aid=*'],
)
def test_host_usb_refuses_invalid_ids_before_authentication(device_id: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["host", "usb", device_id], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "32-character hexadecimal device id" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "args",
    [[], ["0" * 32, "extra"], ["0" * 32, "--repository", "other"], ["0" * 32, "--since", "invalid"]],
)
def test_host_usb_refuses_invalid_arguments_before_authentication(args: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["host", "usb", *args], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


def test_host_usb_help_explains_empty_results_and_licensing() -> None:
    stdout, exit_code = run(["host", "usb", "--help"], RecordedTransport([]), {})
    assert exit_code == 0
    assert "An empty result can mean no USB events or no Device Control licence" in stdout


def test_host_usb_scope_failure_names_the_search_scope() -> None:
    recorded = RecordedTransport([serve("StartSearchV1", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["host", "usb", "0" * 32], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "SCOPE_DENIED" in stdout
    assert "NGSIEM:write" in stdout


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    now = [0.0]
    monkeypatch.setattr(search.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(search.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))

    def run_worker(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        reply = harness._worker_reply(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(reply))

    monkeypatch.setattr(harness.subprocess, "run", run_worker)
    return now


@pytest.mark.parametrize("verb", ["start", "status"])
def test_wait_returns_events_when_the_job_finishes(verb: str, clock: list[float]) -> None:
    answers = iter(
        [
            fixture("ngsiem/search-status-running.json"),
            fixture("ngsiem/search-status-running.json"),
            fixture("ngsiem/search-status-done.json"),
        ]
    )
    recorded = RecordedTransport([*STARTED, serve("GetSearchStatusV1", lambda _: next(answers))])
    args = ["--query", "#event_simpleName=ProcessRollup2 | head(5)"] if verb == "start" else ["synthetic-job"]
    stdout, exit_code = run(["search", verb, *args, "--wait", "10"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "state: done" in stdout
    assert "events[2]" in stdout
    assert clock == [2.0]


@pytest.mark.parametrize("verb", ["start", "status"])
@pytest.mark.parametrize("wait", ["1", "50"])
def test_wait_expiry_preserves_the_job_and_repository(verb: str, wait: str, clock: list[float]) -> None:
    recorded = RecordedTransport([*STARTED, serve("GetSearchStatusV1", fixture("ngsiem/search-status-running.json"))])
    args = ["--query", QUERY] if verb == "start" else ["synthetic-search-job-01"]
    stdout, exit_code = run(
        ["search", verb, *args, "--repository", "synthetic-view", "--wait", wait], recorded, dict(CREDENTIAL_ENV)
    )
    assert exit_code == 0
    assert "state: running" in stdout
    assert "search_id: synthetic-search-job-01" in stdout
    assert "search status synthetic-search-job-01 --repository synthetic-view --wait 30" in stdout
    assert clock == [float(wait)]
    assert recorded.operation_requests("StopSearchV1") == []
    assert len(recorded.operation_requests("GetSearchStatusV1")) == int(wait)


@pytest.mark.parametrize("prior_polls", [0, 1])
@pytest.mark.parametrize(
    ("failure", "code"),
    [("scope", "SCOPE_DENIED"), ("upstream", "UPSTREAM_ERROR"), ("network", "NETWORK_UNREACHABLE")],
)
@pytest.mark.parametrize("verb", ["start", "status"])
def test_polling_errors_preserve_job_recovery(verb: str, failure: str, code: str, prior_polls: int, clock: list[float]) -> None:
    answers = iter([fixture("ngsiem/search-status-running.json")] * prior_polls)

    def poll(_: RequestArgs) -> FalconResponse:
        answer = next(answers, None)
        if answer is not None:
            return answer
        if failure == "network":
            raise CliError("NETWORK_UNREACHABLE", "the endpoint could not be reached")
        return response(403 if failure == "scope" else 500, {})

    recorded = RecordedTransport([*STARTED, serve("GetSearchStatusV1", poll)])
    args = ["--query", QUERY] if verb == "start" else ["synthetic-search-job-01"]
    stdout, exit_code = run(
        ["search", verb, *args, "--repository", "synthetic-view", "--wait", "10"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 1
    assert f"code: {code}" in stdout
    assert "search_id: synthetic-search-job-01" in stdout
    assert "repository: synthetic-view" in stdout
    assert "search status synthetic-search-job-01 --repository synthetic-view" in stdout
    assert "search stop synthetic-search-job-01 --repository synthetic-view" in stdout
    assert recorded.operation_requests("StopSearchV1") == []


def test_wait_includes_authentication_creation_and_inflight_polls(clock: list[float]) -> None:
    def token(request: Any, context: Any) -> dict[str, Any]:
        clock[0] += 2
        return {"access_token": "synthetic-token"}

    def start(request: Any, context: Any) -> dict[str, Any]:
        clock[0] += 3
        return {"id": "synthetic-job"}

    def poll(request: Any, context: Any) -> dict[str, Any]:
        clock[0] += 1
        return {"done": False}

    with requests_mock.Mocker() as mock:
        mock.post("https://api.crowdstrike.com/oauth2/token", json=token)
        mock.post("https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs", json=start)
        mock.get("https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs/synthetic-job", json=poll)
        stdout, exit_code = run(["search", "start", "--query", QUERY, "--wait", "10"], HttpTransport(), dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "state: running" in stdout
    assert "search_id: synthetic-job" in stdout
    assert clock == [10.0]
    assert [request.timeout.total for request in mock.request_history] == [10, 8, 5, 3, 1]


@pytest.mark.parametrize("phase", ["auth", "start", "poll"])
def test_retry_after_cannot_extend_wait_budget(phase: str, clock: list[float]) -> None:
    token_url = "https://api.crowdstrike.com/oauth2/token"
    start_url = "https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs"
    with requests_mock.Mocker() as mock:
        mock.post(token_url, json={"access_token": "synthetic-token"})
        mock.post(start_url, json={"id": "synthetic-job"})
        mock.get(f"{start_url}/synthetic-job", json={"done": False})
        url = {"auth": token_url, "start": start_url, "poll": f"{start_url}/synthetic-job"}[phase]
        mock.register_uri(
            "GET" if phase == "poll" else "POST",
            url,
            status_code=429,
            headers={"X-RateLimit-RetryAfter": str(search.time.time() + 3600)},
            json={},
        )
        stdout, exit_code = run(["search", "start", "--query", QUERY, "--wait", "5"], HttpTransport(), dict(CREDENTIAL_ENV))
    assert clock == [5.0]
    assert len([request for request in mock.request_history if request.url == url]) == 1
    assert exit_code == (0 if phase == "poll" else 1)
    assert ("state: running" if phase == "poll" else "reached its --wait deadline") in stdout


@pytest.mark.parametrize("verb", ["start", "status"])
def test_worker_deadline_returns_recoverable_running_job(
    verb: str, clock: list[float], monkeypatch: pytest.MonkeyPatch
) -> None:
    def run_worker(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        payload = json.loads(kwargs["input"])
        if payload["request"].get("operation_id") == "GetSearchStatusV1":
            clock[0] += kwargs["timeout"]
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(harness._worker_reply(payload)))

    monkeypatch.setattr(harness.subprocess, "run", run_worker)

    with requests_mock.Mocker() as mock:
        mock.post("https://api.crowdstrike.com/oauth2/token", json={"access_token": "synthetic-token"})
        mock.post("https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs", json={"id": "synthetic-job"})
        args = ["--query", QUERY] if verb == "start" else ["synthetic-job"]
        stdout, exit_code = run(["search", verb, *args, "--wait", "5"], HttpTransport(), dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "state: running" in stdout
    assert "search_id: synthetic-job" in stdout
    assert "search stop synthetic-job" in stdout
    assert clock == [5.0]


@pytest.mark.parametrize("verb", ["start", "status"])
def test_no_poll_begins_if_authentication_or_creation_uses_the_budget(verb: str, clock: list[float]) -> None:
    def consume_budget(request: Any, context: Any) -> dict[str, Any]:
        clock[0] += request.timeout.total
        return {"id": "synthetic-job", "access_token": "synthetic-token"}

    with requests_mock.Mocker() as mock:
        mock.post("https://api.crowdstrike.com/oauth2/token", json={"access_token": "synthetic-token"})
        mock.post("https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs", json=consume_budget)
        if verb == "status":
            mock.post("https://api.crowdstrike.com/oauth2/token", json=consume_budget)
        args = ["--query", QUERY] if verb == "start" else ["synthetic-job"]
        stdout, exit_code = run(["search", verb, *args, "--wait", "5"], HttpTransport(), dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "state: running" in stdout
    assert "search_id: synthetic-job" in stdout
    assert clock == [5.0]
    assert [request.method for request in mock.request_history] == (["POST", "POST"] if verb == "start" else ["POST"])


@pytest.mark.parametrize("wait", ["0", "51", "-1", "1.5", "invalid"])
def test_invalid_wait_is_refused_before_authentication(wait: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["search", "start", "--query", QUERY, "--wait", wait], recorded, {})
    assert exit_code == 2
    assert "--wait must be an integer from 1 to 50" in stdout
    assert recorded.requests == []


def test_wait_stops_when_the_job_is_cancelled(clock: list[float]) -> None:
    recorded = RecordedTransport([serve("GetSearchStatusV1", response(200, {"cancelled": True}))])
    stdout, exit_code = run(["search", "status", "synthetic-job", "--wait", "10"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "state: cancelled" in stdout
    assert clock == [0.0]


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
    assert recorded.requests == []


def test_search_status_renders_the_events_and_the_filter_the_api_actually_parsed() -> None:
    recorded = RecordedTransport(DONE)
    stdout, exit_code = run(["search", "status", "synthetic-search-job-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^state: done$", stdout, re.MULTILINE)
    assert re.search(r"^count: 2 of 2 matching events$", stdout, re.MULTILINE)
    assert re.search(r"^events_scanned: 148231$", stdout, re.MULTILINE)
    assert 'parsed_query: "#event_simpleName=ProcessRollup2"' in stdout
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
            "filterQuery": {"queryString": "#event_simpleName=ProcessRollup2"},
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
    recorded = RecordedTransport([serve("StopSearchV1", fixture("ngsiem/job-not-found.json"))])
    stdout, exit_code = run(["search", "stop", "synthetic-missing-job"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: NOT_FOUND" in stdout
    assert "no NG-SIEM search job matched that identifier" in stdout
    assert "FQL" not in stdout


def test_a_rejected_search_is_answered_in_cql_terms_rather_than_fql_terms() -> None:
    rejected = response(400, {"errors": [{"code": 400, "message": "invalid query string"}]})
    recorded = RecordedTransport([serve("StartSearchV1", rejected)])
    stdout, exit_code = run(["search", "start", "--query", "SELECT * FROM events"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "invalid query string" in stdout
    assert "CQL is pipe-based" in stdout
    assert "FQL uses + for AND" not in stdout


def test_rejected_search_preserves_all_server_messages_and_redacts_secrets() -> None:
    secret = CREDENTIAL_ENV["FALCON_CLIENT_SECRET"]
    rejected = response(400, {"errors": [{"message": "Expected ')' at line 2"}, {"message": f"token={secret}"}]})
    recorded = RecordedTransport([serve("StartSearchV1", rejected)])
    stdout, exit_code = run(["search", "start", "--query", QUERY], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "Expected ')' at line 2" in stdout
    assert secret not in stdout
    assert "[redacted]" in stdout
    assert len(recorded.operation_requests("StartSearchV1")) == 1


@pytest.mark.parametrize("status", [400, 404])
def test_search_rejection_without_messages_keeps_cql_guidance(status: int) -> None:
    recorded = RecordedTransport([serve("StartSearchV1", response(status, {}))])
    stdout, exit_code = run(["search", "start", "--query", QUERY], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "NG-SIEM rejected this search" in stdout
    assert "CQL is pipe-based" in stdout


def test_completed_search_surfaces_sanitised_warning_codes_and_messages() -> None:
    secret = CREDENTIAL_ENV["FALCON_CLIENT_SECRET"]
    body = {"done": True, "events": [], "warnings": [{"code": "LIMIT", "message": f"Limit reached token={secret}"}]}
    recorded = RecordedTransport([serve("GetSearchStatusV1", response(200, body))])
    stdout, exit_code = run(["search", "status", "synthetic-job"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "warnings[1]{code,message}" in stdout
    assert "LIMIT" in stdout
    assert "Limit reached" in stdout
    assert secret not in stdout
    assert "[redacted]" in stdout


@pytest.mark.parametrize(
    ("query", "parsed", "differs"),
    [
        (QUERY, "#event_simpleName=ProcessRollup2", False),
        ('message="a|b" | head(2)', 'message="a|b"', False),
        ("misspelled | head(2)", "*", True),
        ("field=value2 | head(2)", "field=value", True),
        ("field=value", "field=value", False),
    ],
)
def test_wait_compares_the_parsed_filter_with_the_submitted_query(
    query: str, parsed: str, differs: bool, clock: list[float]
) -> None:
    body = {"done": True, "events": [], "metaData": {"filterQuery": {"queryString": parsed}}}
    recorded = RecordedTransport([*STARTED, serve("GetSearchStatusV1", response(200, body))])
    stdout, exit_code = run(["search", "start", "--query", query, "--wait", "10"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert ("The normalized filter differs" in stdout) == differs


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
