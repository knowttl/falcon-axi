import pytest

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, response, serve


@pytest.mark.parametrize(
    ("noun", "operation", "flag", "value", "term"),
    [
        ("detection", "GetQueriesAlertsV2", "product", "idp", "product:'idp'"),
        ("detection", "GetQueriesAlertsV2", "severity", "high", "severity_name:'High'"),
        ("detection", "GetQueriesAlertsV2", "status", "new", "status:'new'"),
        ("detection", "GetQueriesAlertsV2", "since", "7d", "created_timestamp:>'now-7d'"),
        ("host", "QueryDevicesByFilter", "hostname", "WIN-*", "hostname:'WIN-*'"),
        ("host", "QueryDevicesByFilter", "platform", "windows", "platform_name:'Windows'"),
        ("host", "QueryDevicesByFilter", "status", "normal", "status:'normal'"),
        ("host", "QueryDevicesByFilter", "since", "7d", "last_seen:>'now-7d'"),
        ("vuln", "combinedQueryVulnerabilities", "host", "synthetic-agent", "aid:'synthetic-agent'"),
        ("vuln", "combinedQueryVulnerabilities", "severity", "critical", "cve.severity:'CRITICAL'"),
        ("vuln", "combinedQueryVulnerabilities", "status", "open", "status:'open'"),
        ("vuln", "combinedQueryVulnerabilities", "since", "7d", "created_timestamp:>'now-7d'"),
    ],
)
def test_every_shorthand_constrains_the_entire_raw_disjunction(noun, operation, flag, value, term) -> None:
    raw = "status:'new',status:'in_progress'" if noun == "detection" else "status:'open',status:'closed'"
    recorded = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, exit_code = run(
        [noun, "list", f"--{flag}", value, "--filter", raw], recorded, dict(CREDENTIAL_ENV)
    )
    assert exit_code == 0, stdout
    assert recorded.operation_requests(operation)[0].query["filter"] == f"{term}+({raw})"


@pytest.mark.parametrize(
    ("noun", "operation"),
    [("detection", "GetQueriesAlertsV2"), ("host", "QueryDevicesByFilter"), ("vuln", "combinedQueryVulnerabilities")],
)
def test_a_raw_filter_without_shorthands_is_sent_unchanged(noun, operation) -> None:
    raw = "status:'open',status:'closed'"
    recorded = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, exit_code = run([noun, "list", "--filter", raw], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    assert recorded.operation_requests(operation)[0].query["filter"] == raw
