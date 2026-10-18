"""List field selection through the CLI's recorded transport seam."""

import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve


@pytest.mark.parametrize(
    ("noun", "selection", "header", "cell", "responders"),
    [
        (
            "detection",
            "technique,status,created_timestamp,technique",
            "detections[2]{id,severity,tactic,hostname,technique,status,created_timestamp}:",
            'Masquerading,new,"2026-07-28T10:57:44Z"',
            [("GetQueriesAlertsV2", "alerts/query-page.json"), ("PostEntitiesAlertsV2", "alerts/hydrate-page.json")],
        ),
        (
            "host",
            "status,os_version,agent_version,first_seen,machine_domain,status",
            "hosts[2]{device_id,hostname,platform,last_seen,status,os_version,agent_version,first_seen,machine_domain}:",
            'normal,Windows Server 2022,7.11.0000,"2026-01-04T08:12:55Z",synthetic.example',
            [("QueryDevicesByFilter", "hosts/query-page.json"), ("PostDeviceDetailsV2", "hosts/details-page.json")],
        ),
        (
            "vuln",
            "status,base_score,status",
            "vulnerabilities[2]{id,cve,severity,hostname,status,base_score}:",
            'open,"9.8"',
            [("combinedQueryVulnerabilities", "spotlight/combined-page.json")],
        ),
    ],
)
def test_fields_append_in_requested_order_and_ignore_duplicates(noun, selection, header, cell, responders) -> None:
    recorded = RecordedTransport([serve(op, fixture(path)) for op, path in responders])
    stdout, code = run(
        [noun, "list", "--filter", "status:'open'", "--limit", "2", "--fields", selection],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    assert header in stdout
    assert cell in stdout
    assert f"--fields {selection}" in stdout


@pytest.mark.parametrize(
    ("noun", "valid", "defaults"),
    [
        ("detection", "status, technique, created_timestamp", "id, severity, tactic, hostname"),
        ("host", "os_version, agent_version, status, first_seen, machine_domain", "device_id, hostname, platform, last_seen"),
        (
            "vuln",
            "description, base_score, exprt_rating, status, created, updated, product, remediation, platform, os, local_ip",
            "id, cve, severity, hostname",
        ),
    ],
)
def test_unknown_fields_list_valid_names_before_a_domain_request(noun, valid, defaults) -> None:
    recorded = RecordedTransport([])
    stdout, code = run([noun, "list", "--fields", "status,missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert "unknown --fields name missing" in stdout
    assert f"valid --fields names: {valid}" in stdout
    assert f"default columns {defaults} are always included" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize("noun", ["detection", "host", "vuln"])
@pytest.mark.parametrize("selection", ["status,", ",status", "status, ,status"])
def test_empty_field_names_are_rejected(noun: str, selection: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run([noun, "list", "--fields", selection], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "--fields requires one or more field names" in stdout
    assert recorded.requests == []


def test_extra_fields_follow_the_identity_columns() -> None:
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", fixture("alerts/query-identity.json")),
            serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-identity.json")),
        ]
    )
    stdout, code = run(
        ["detection", "list", "--product", "idp", "--fields", "created_timestamp,status"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    assert "detections[2]{id,severity,tactic,hostname,account,account_id,device_id,product,created_timestamp,status}:" in stdout
    assert 'synthetic-agent-07,idp,"2026-10-01T08:15:00Z",new' in stdout
    assert 'n/a,idp,"2026-10-01T08:10:00Z",new' in stdout
