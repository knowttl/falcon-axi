"""Intel query/hydrate and Spotlight detail, matched to falconpy and PSFalcon.

falcon-mcp modules/intel.py and modules/spotlight.py have no tool for these two reads.
Endpoint ids and parameters follow falconpy _endpoint/_intel.py and
_endpoint/_spotlight_vulnerabilities.py, and PSFalcon public/intel.ps1 and public/spotlight.ps1.
"""

import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


def page() -> RecordedTransport:
    return RecordedTransport(
        [
            serve("QueryVulnerabilities", fixture("intel/query-page.json")),
            serve("GetVulnerabilities", fixture("intel/entities-page.json")),
        ]
    )


def test_cve_list_preserves_query_order_and_total_from_the_query_step() -> None:
    recorded = page()
    stdout, code = run(["cve", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 2 of 3 total" in stdout
    assert stdout.index("CVE-2099-0002") < stdout.index("CVE-2099-0001")
    assert recorded.operation_requests("GetVulnerabilities")[0].body == {"ids": ["CVE-2099-0002", "CVE-2099-0001"]}


def test_cve_shorthands_and_cursor_resume_the_same_filter() -> None:
    argv = ["cve", "list", "--severity", "critical", "--since", "7d", "--filter", "exploit_status:'unproven'", "--limit", "2"]
    recorded = page()
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests("QueryVulnerabilities")[0].query == {
        "filter": "severity:'CRITICAL'+publish_date:>'now-7d'+(exploit_status:'unproven')",
        "limit": 2,
        "offset": "0",
    }
    cursor = next(
        line.removeprefix("continuation_cursor: ") for line in stdout.splitlines() if line.startswith("continuation_cursor: ")
    )
    second = page()
    _, code = run([*argv, "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    assert code == 0
    assert second.operation_requests("QueryVulnerabilities")[0].query["offset"] == "2"
    changed = page()
    stdout, code = run(["cve", "list", "--cursor", cursor], changed, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "this cursor does not continue the current query" in stdout
    assert changed.operation_requests("QueryVulnerabilities") == []


@pytest.mark.parametrize("flags", [["--severity", "invalid"], ["--since", "yesterday"], ["--filter", " "]])
def test_cve_bad_filter_is_refused_before_the_domain_request(flags: list[str]) -> None:
    recorded = page()
    _, code = run(["cve", "list", *flags], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert recorded.operation_requests("QueryVulnerabilities") == []


def test_cve_empty_query_does_not_hydrate() -> None:
    recorded = RecordedTransport([serve("QueryVulnerabilities", response(200, {"resources": []}))])
    stdout, code = run(["cve", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 CVEs in Falcon Intelligence" in stdout
    assert recorded.operation_requests("GetVulnerabilities") == []


def test_cve_short_hydrate_advances_by_ids_and_retains_total() -> None:
    recorded = RecordedTransport(
        [
            serve("QueryVulnerabilities", fixture("intel/query-page.json")),
            serve("GetVulnerabilities", fixture("intel/vulnerability-one.json")),
        ]
    )
    stdout, code = run(["cve", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 1 of 3 total" in stdout
    assert "continuation_cursor:" in stdout


@pytest.mark.parametrize("operation", ["QueryVulnerabilities", "GetVulnerabilities"])
def test_cve_scope_denial_names_the_intelligence_scope(operation: str) -> None:
    responders = [serve("QueryVulnerabilities", fixture("intel/query-page.json"))] if operation == "GetVulnerabilities" else []
    recorded = RecordedTransport([serve(operation, fixture("errors/403-scope.json")), *responders])
    stdout, code = run(["cve", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Vulnerabilities (Falcon Intelligence):read" in stdout


def test_vuln_show_reads_the_requested_record_without_other_requests() -> None:
    recorded = RecordedTransport([serve("getVulnerabilities", fixture("spotlight/entity-one.json"))])
    stdout, code = run(["vuln", "show", "synthetic-vulnerability-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "description: Synthetic vulnerability description." in stdout
    assert "device_id: synthetic-device-01" in stdout
    assert 'base_score: "9.8"' in stdout
    assert recorded.operation_requests("getVulnerabilities")[0].query == {"ids": ("synthetic-vulnerability-01",)}
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("status", [200, 404])
def test_vuln_show_missing_record_is_not_found(status: int) -> None:
    recorded = RecordedTransport([serve("getVulnerabilities", response(status, {"resources": []}))])
    stdout, code = run(["vuln", "show", "missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: NOT_FOUND" in stdout


def test_vuln_show_rejects_a_response_for_another_record() -> None:
    recorded = RecordedTransport([serve("getVulnerabilities", fixture("spotlight/entity-one.json"))])
    stdout, code = run(["vuln", "show", "another-record"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: UPSTREAM_ERROR" in stdout


def test_vuln_show_scope_denial_names_the_spotlight_scope() -> None:
    recorded = RecordedTransport([serve("getVulnerabilities", fixture("errors/403-scope.json"))])
    stdout, code = run(["vuln", "show", "synthetic-vulnerability-01"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Vulnerabilities:read" in stdout
