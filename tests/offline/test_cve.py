"""`cve show`: one GetVulnerabilities read, with no list command and no expanded related lists."""

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve


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
