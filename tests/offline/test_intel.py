"""Intel contracts match falcon-mcp modules/intel.py and tests/modules/test_intel.py.

Entity ids/fields additionally follow falconpy _endpoint/_intel.py and PSFalcon public/intel.ps1.
All responses are synthetic; these checks make no tenant-validation claim.
"""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize("noun,operation", [("actor", "QueryIntelActorEntities"), ("report", "QueryIntelReportEntities")])
def test_combined_list_preserves_order_and_total(noun: str, operation: str) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"intel/{noun}s-page.json"))])
    stdout, code = run([noun, "list", "--filter", "name:'Synthetic*'", "--limit", "2"], recorded, CREDENTIAL_ENV)
    assert code == 0
    parsed = decode(stdout)
    assert parsed["count"] == "2 of 3 total"
    assert [str(entry["id"]) for entry in parsed[f"{noun}s"]] == ["123456", "123457"]
    assert recorded.operation_requests(operation)[0].query == {"filter": "name:'Synthetic*'", "limit": 2, "offset": 0}


@pytest.mark.parametrize("noun,operation", [("actor", "QueryIntelActorEntities"), ("report", "QueryIntelReportEntities")])
def test_cursor_advances_and_rejects_a_different_query(noun: str, operation: str) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"intel/{noun}s-page.json"))])
    stdout, _ = run([noun, "list", "--limit", "2"], recorded, CREDENTIAL_ENV)
    cursor = decode(stdout)["continuation_cursor"]
    empty = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, code = run([noun, "list", "--cursor", cursor], empty, CREDENTIAL_ENV)
    assert code == 0
    assert f"no more {noun}s" in stdout
    assert empty.operation_requests(operation)[0].query["offset"] == 2
    different = RecordedTransport([])
    stdout, code = run([noun, "list", "--cursor", cursor, "--filter", "name:'different'"], different, CREDENTIAL_ENV)
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert different.operation_requests(operation) == []


@pytest.mark.parametrize("noun,operation", [("actor", "GetIntelActorEntities"), ("report", "GetIntelReportEntities")])
def test_detail_requests_full_field_collection(noun: str, operation: str) -> None:
    recorded = RecordedTransport([serve(operation, fixture(f"intel/{noun}-one.json"))])
    stdout, code = run([noun, "show", "123456"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "Synthetic" in decode(stdout)[noun]["name"]
    assert recorded.operation_requests(operation)[0].query == {"ids": ("123456",), "fields": ("__full__",)}


@pytest.mark.parametrize(
    "noun,operation",
    [("actor", "GetIntelActorEntities"), ("report", "GetIntelReportEntities"), ("malware", "GetMalwareEntities")],
)
@pytest.mark.parametrize("full", (False, True))
def test_detail_redacts_complete_private_keys_before_preview(noun: str, operation: str, full: bool) -> None:
    pem = "-----BEGIN PRIVATE KEY-----\n" + "SYNTHETIC" * 150 + "\n-----END PRIVATE KEY-----"
    record = {"id": "synthetic-record", "slug": "synthetic-record", "description": pem}
    recorded = RecordedTransport([serve(operation, response(200, {"resources": [record]}))])
    stdout, code = run([noun, "show", "synthetic-record", *(["--full"] if full else [])], recorded, CREDENTIAL_ENV)
    assert code == 0, stdout
    assert decode(stdout) == {
        noun: {"id": "synthetic-record", "slug": "synthetic-record", "description": "[redacted]"}
    }


@pytest.mark.parametrize("noun,operation", [("actor", "GetIntelActorEntities"), ("report", "GetIntelReportEntities")])
def test_detail_truncation_has_a_full_escape_hatch(noun: str, operation: str) -> None:
    answer = response(200, {"resources": [{"id": "123456", "description": "x" * 801}]})
    stdout, code = run([noun, "show", "123456"], RecordedTransport([serve(operation, answer)]), CREDENTIAL_ENV)
    assert code == 0
    parsed = decode(stdout)
    assert "801 chars total" in parsed[noun]["description"]
    assert "--full" in parsed["help"][0]
    stdout, code = run([noun, "show", "123456", "--full"], RecordedTransport([serve(operation, answer)]), CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)[noun]["description"] == "x" * 801


@pytest.mark.parametrize("status", [200, 404])
@pytest.mark.parametrize("noun,operation", [("actor", "GetIntelActorEntities"), ("report", "GetIntelReportEntities")])
def test_unknown_detail_is_not_found(noun: str, operation: str, status: int) -> None:
    stdout, code = run(
        [noun, "show", "missing"],
        RecordedTransport([serve(operation, response(status, {"resources": []}))]),
        CREDENTIAL_ENV,
    )
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"


def test_mitre_uses_json_top_level_array() -> None:
    recorded = RecordedTransport(
        [serve("GetIntelActorEntities", fixture("intel/actor-one.json")), serve("GetMitreReport", fixture("intel/mitre.json"))]
    )
    stdout, code = run(["actor", "show", "123456", "--mitre"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["mitre"][0]["technique_id"] == "T1059"
    assert recorded.operation_requests("GetMitreReport")[0].query == {"actor_id": "123456", "format": "json"}


@pytest.mark.parametrize("body", [None, []])
def test_empty_mitre_mappings_are_definitive(body: object) -> None:
    recorded = RecordedTransport(
        [serve("GetIntelActorEntities", fixture("intel/actor-one.json")), serve("GetMitreReport", response(200, body))]
    )
    stdout, code = run(["actor", "show", "123456", "--mitre"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["mitre"] == "0 ATT&CK mappings for this actor"


@pytest.mark.parametrize("body", [{"unexpected": "shape"}, ["invalid"]])
def test_invalid_mitre_is_an_upstream_error(body: object) -> None:
    recorded = RecordedTransport(
        [serve("GetIntelActorEntities", fixture("intel/actor-one.json")), serve("GetMitreReport", response(200, body))]
    )
    stdout, code = run(["actor", "show", "123456", "--mitre"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


@pytest.mark.parametrize("noun,operation", [("actor", "QueryIntelActorEntities"), ("report", "QueryIntelReportEntities")])
def test_scope_denial_names_the_required_intelligence_scope(noun: str, operation: str) -> None:
    stdout, code = run([noun, "list"], RecordedTransport([serve(operation, fixture("errors/403-scope.json"))]), CREDENTIAL_ENV)
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert f"{noun.title()}s (Falcon Intelligence):read" in stdout


@pytest.mark.parametrize("argv", [["report", "show", "1", "--mitre"], ["actor", "list", "--limit", "5001"]])
def test_invalid_flags_fail_before_authentication(argv: list[str]) -> None:
    recorded = RecordedTransport([])
    _, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert recorded.requests == []
