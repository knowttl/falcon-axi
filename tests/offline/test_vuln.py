"""The Spotlight vulnerabilities domain (docs/design/v1.md §7.1, §7.3, §10.2)."""

import re

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

PAGE = [serve("combinedQueryVulnerabilities", fixture("spotlight/combined-page.json"))]


def test_vuln_list_is_one_request_with_no_hydrate_step() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, exit_code = run(["vuln", "list", "--status", "open", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^count: 2 of 57 total$", stdout, re.MULTILINE)
    assert "vulnerabilities[2]{id,cve,severity,hostname}:" in stdout
    assert len(recorded.requests) == 2  # the token mint and one combined read
    assert recorded.operation_requests("combinedQueryVulnerabilities")[0].query["filter"] == "status:'open'"


def test_a_missing_filter_is_refused_locally_because_spotlight_requires_one() -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["vuln", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "error: vuln list requires a filter" in stdout
    assert "--host <device_id>" in stdout
    assert recorded.operation_requests("combinedQueryVulnerabilities") == []


def test_a_wildcard_is_refused_locally_wherever_it_appears_in_the_filter() -> None:
    recorded = RecordedTransport([])
    for filter in ("cve.id:'CVE-*'", "status:'open'+host_info.hostname:'WIN*'"):
        stdout, exit_code = run(["vuln", "list", "--filter", filter], recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 2
        assert "code: FQL_INVALID" in stdout
        assert "Spotlight filters do not support wildcards" in stdout
    assert recorded.operation_requests("combinedQueryVulnerabilities") == []


def test_the_shorthands_compose_the_documented_spotlight_fields() -> None:
    recorded = RecordedTransport(PAGE)
    run(
        ["vuln", "list", "--host", "synthetic-device-01", "--severity", "critical", "--since", "7d"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert recorded.operation_requests("combinedQueryVulnerabilities")[0].query["filter"] == (
        "aid:'synthetic-device-01'+cve.severity:'CRITICAL'+created_timestamp:>'now-7d'"
    )


def test_the_after_token_travels_opaquely_and_resumes_the_same_query() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, _ = run(["vuln", "list", "--status", "open", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    marker = "continuation_cursor: "
    cursor = next(line for line in stdout.split("\n") if line.startswith(marker))[len(marker) :]
    assert "synthetic-after-token-2" not in cursor

    second = RecordedTransport(PAGE)
    run(["vuln", "list", "--status", "open", "--limit", "2", "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    assert second.operation_requests("combinedQueryVulnerabilities")[0].query["after"] == "synthetic-after-token-2"


def test_a_cursor_whose_filter_changed_is_rejected_before_any_request() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, _ = run(["vuln", "list", "--status", "open", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    marker = "continuation_cursor: "
    cursor = next(line for line in stdout.split("\n") if line.startswith(marker))[len(marker) :]

    second = RecordedTransport([])
    changed, exit_code = run(["vuln", "list", "--status", "closed", "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "this cursor does not continue the current query" in changed
    assert second.operation_requests("combinedQueryVulnerabilities") == []


def test_an_offset_cursor_cannot_stand_in_for_a_token_cursor() -> None:
    context = CursorContext(
        operation="combinedQueryVulnerabilities",
        client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
        origin="https://api.crowdstrike.com",
        query="status:'open'",
        model="offset",
    )
    cursor = encode_cursor(20, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    argv = ["vuln", "list", "--status", "open", "--cursor", cursor]
    stdout, exit_code = run(argv, RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "this cursor does not continue the current query" in stdout


def test_a_missing_total_is_reported_as_unknown_rather_than_invented() -> None:
    page = fixture("spotlight/combined-page.json")
    recorded = RecordedTransport([serve("combinedQueryVulnerabilities", response(200, {"resources": page.body["resources"]}))])
    stdout, exit_code = run(["vuln", "list", "--status", "open"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^count: 2 of unknown total$", stdout, re.MULTILINE)
    assert "continuation_cursor" not in stdout


def test_an_empty_result_states_the_filter_that_produced_it() -> None:
    recorded = RecordedTransport([serve("combinedQueryVulnerabilities", fixture("spotlight/combined-empty.json"))])
    stdout, exit_code = run(["vuln", "list", "--severity", "critical", "--status", "open"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "vulnerabilities: 0 vulnerabilities matching critical severity status open" in stdout


def test_a_scope_failure_on_spotlight_names_the_vulnerabilities_read_scope() -> None:
    recorded = RecordedTransport([serve("combinedQueryVulnerabilities", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["vuln", "list", "--status", "open"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: SCOPE_DENIED" in stdout
    assert "Vulnerabilities:read" in stdout
