"""`cve show`: one GetVulnerabilities read, with no list command and no expanded related lists."""

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


def test_cve_show_posts_the_cve_id_and_does_not_advertise_a_list_command() -> None:
    recorded = RecordedTransport([serve("GetVulnerabilities", fixture("intel/vulnerability-one.json"))])
    stdout, exit_code = run(["cve", "show", "CVE-2099-0001"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "cve: CVE-2099-0001" in stdout
    assert "affected_products: 1" in stdout
    assert "Synthetic Actor" not in stdout
    requests = recorded.operation_requests("GetVulnerabilities")
    assert len(requests) == 1
    assert requests[0].body == {"ids": ["CVE-2099-0001"]}
    help_text, code = run(["cve", "show", "--help"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert code == 0
    assert "there is no cve list command" in help_text
    assert "falcon-axi cve list" not in help_text
    assert "Vulnerabilities (Falcon Intelligence):read" in help_text
    refused = RecordedTransport([])
    bad, bad_code = run(["cve", "show", "not-a-cve"], refused, dict(CREDENTIAL_ENV))
    assert bad_code == 2
    assert "VALIDATION_ERROR" in bad
    assert refused.requests == []
    unicode_bad, unicode_code = run(["cve", "show", "CVE-２０２１-４４２２８"], refused, dict(CREDENTIAL_ENV))
    assert unicode_code == 2
    assert "VALIDATION_ERROR" in unicode_bad
    assert refused.requests == []


def test_cve_show_scope_denial_explains_license_and_spotlight() -> None:
    recorded = RecordedTransport([serve("GetVulnerabilities", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["cve", "show", "CVE-2099-0001"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Vulnerabilities (Falcon Intelligence):read" in stdout
    assert "Falcon Intelligence subscription" in stdout
    assert "Spotlight's Vulnerabilities:read does not satisfy it" in stdout
    assert "API client picker" in stdout


def test_cve_show_does_not_attribute_an_unidentified_or_different_resource_to_the_requested_id() -> None:
    for record in ({"severity": "CRITICAL"}, {"cve": "CVE-2099-0002", "severity": "CRITICAL"}):
        recorded = RecordedTransport([serve("GetVulnerabilities", response(200, {"resources": [record]}))])
        stdout, exit_code = run(["cve", "show", "CVE-2099-0001"], recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 1
        assert "UPSTREAM_ERROR" in stdout
        assert "0 vulnerabilities matching" not in stdout
        assert "severity: CRITICAL" not in stdout
        assert len(recorded.operation_requests("GetVulnerabilities")) == 1


def test_cve_show_selects_the_requested_id_from_a_mixed_response() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "GetVulnerabilities",
                response(200, {"resources": [
                    {"cve": "CVE-2099-0002", "severity": "WRONG"},
                    {"cve": "CVE-2099-0001", "severity": "CRITICAL"},
                ]}),
            )
        ]
    )
    stdout, exit_code = run(["cve", "show", "CVE-2099-0001"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "cve: CVE-2099-0001" in stdout
    assert "severity: CRITICAL" in stdout
    assert "WRONG" not in stdout
