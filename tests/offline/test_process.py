"""Process detail and investigation pivots through the real CLI with synthetic responses."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

PID = "pid:00000000000000000000000000000001:1234"
# Fixtures retain conspicuous synthetic agent placeholders under the repository hygiene contract.
DETAILS = response(200, [{**fixture("processes/details.json").body[0], "process_id": PID}])


def test_show_renders_the_documented_nine_fields() -> None:
    recorded = RecordedTransport([serve("entities_processes", DETAILS)])
    stdout, code = run(["process", "show", PID], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout) == {"process": DETAILS.body[0]}
    assert recorded.operation_requests("entities_processes")[0].query == {"ids": (PID,)}
    assert len(recorded.requests) == 2


@pytest.mark.parametrize("answer", [response(200, []), response(404, {})])
def test_unknown_process_points_to_ioc_processes(answer) -> None:
    recorded = RecordedTransport([serve("entities_processes", answer)])
    stdout, code = run(["process", "show", PID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: NOT_FOUND" in stdout
    assert "falcon-axi ioc processes <type:value> --host <device_id>" in stdout


def test_denied_process_names_scope_and_subscription_or_permission_limit() -> None:
    recorded = RecordedTransport([serve("entities_processes", response(403, {}))])
    stdout, code = run(["process", "show", PID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    result = decode(stdout)
    assert result["code"] == "SCOPE_DENIED"
    assert result["required_scopes"] == ["IOCs (Indicators of Compromise):read"]
    assert "not permitted to read process details" in result["error"]
    assert "subscription or API client permissions" in stdout


@pytest.mark.parametrize("id", ["1234", "pid:synthetic:1234", "pid:" + "0" * 32 + ":-1", PID + "\n", PID + "," + PID])
def test_invalid_id_is_refused_before_authentication(id: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["process", "show", id], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "code: VALIDATION_ERROR" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "body", [{"resources": []}, [None], [{"process_id": "another-process"}], {"errors": [{"message": "failed"}]}]
)
def test_malformed_or_mismatched_details_never_claim_not_found(body) -> None:
    recorded = RecordedTransport([serve("entities_processes", response(200, body))])
    stdout, code = run(["process", "show", PID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: UPSTREAM_ERROR" in stdout


@pytest.mark.parametrize("full", [False, True])
def test_command_line_redaction_precedes_preview(full: bool) -> None:
    record = {**DETAILS.body[0], "command_line": "x" * 790 + "synthetic-client-secret" + "x" * 30}
    recorded = RecordedTransport([serve("entities_processes", response(200, [record]))])
    stdout, code = run(["process", "show", PID, *(["--full"] if full else [])], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "synthetic-client-secret" not in stdout
    assert "[redacted]" in stdout
    assert ("truncated" in stdout) == (not full)
    assert (f"process show {PID} --full" in stdout) == (not full)


def test_missing_fields_remain_unknown() -> None:
    recorded = RecordedTransport([serve("entities_processes", response(200, [{"process_id": PID}]))])
    stdout, code = run(["process", "show", PID], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["process"]["stop_timestamp"] == "unknown"


def test_ioc_processes_suggests_process_show() -> None:
    recorded = RecordedTransport([serve("ProcessesRanOn", response(200, {"resources": [PID]}))])
    stdout, code = run(
        ["ioc", "processes", "domain:example.invalid", "--host", "synthetic-device"], recorded, dict(CREDENTIAL_ENV)
    )
    assert code == 0
    assert "falcon-axi process show <process_id>" in stdout


@pytest.mark.parametrize("field", ["triggering_process_graph_id", "process_id"])
def test_detection_lineage_suggests_details_for_matching_ids_only(field: str) -> None:
    recorded = RecordedTransport(
        [serve("PostEntitiesAlertsV2", response(200, {"resources": [{"composite_id": "ldt:synthetic:1", field: PID}]}))]
    )
    stdout, code = run(["detection", "process", "ldt:synthetic:1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert f"falcon-axi process show {PID}" in stdout
    assert len(recorded.requests) == 2
