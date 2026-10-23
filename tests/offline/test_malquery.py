"""MalQuery pure reads through the CLI using documented synthetic responses."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.transport.operations import OPERATIONS
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

SHA256 = "0" * 64


@pytest.mark.parametrize("envelope", [False, True])
def test_metadata_renders_eight_fields(envelope: bool) -> None:
    rows = fixture("malquery/metadata.json").body
    recorded = RecordedTransport([serve("GetMalQueryMetadataV1", response(200, {"resources": rows} if envelope else rows))])
    stdout, code = run(["malquery", "show", SHA256], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout) == {"malquery": rows[0]}
    assert recorded.operation_requests("GetMalQueryMetadataV1")[0].query == {"ids": (SHA256,)}
    assert len(recorded.requests) == 2


def test_quota_uses_meta_and_preserves_zero_counters() -> None:
    answer = fixture("malquery/quota.json")
    recorded = RecordedTransport([serve("GetMalQueryQuotasV1", answer)])
    stdout, code = run(["malquery", "quota"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout) == {"quota": answer.body["meta"]}
    assert recorded.operation_requests("GetMalQueryQuotasV1")[0].query == {}
    assert len(recorded.requests) == 2


def test_unknown_hash_is_a_definitive_successful_empty_state() -> None:
    recorded = RecordedTransport([serve("GetMalQueryMetadataV1", fixture("malquery/empty.json"))])
    stdout, code = run(["malquery", "show", SHA256], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 indexed files for that SHA-256; no MalQuery metadata found" in stdout
    assert "missing Falcon MalQuery licensing" in stdout


@pytest.mark.parametrize("hash", ["", "0" * 63, "0" * 65, "g" * 64, SHA256 + "\n", SHA256 + "," + SHA256])
def test_invalid_hash_is_refused_before_authentication(hash: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["malquery", "show", hash], recorded, {})
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


def test_hash_matching_is_case_insensitive() -> None:
    recorded = RecordedTransport([serve("GetMalQueryMetadataV1", response(200, [{"sha256": "a" * 64}]))])
    stdout, code = run(["malquery", "show", "A" * 64], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["malquery"]["family"] == "unknown"
    assert recorded.operation_requests("GetMalQueryMetadataV1")[0].query == {"ids": ("a" * 64,)}


@pytest.mark.parametrize(
    "command,operation",
    [
        (["show", SHA256], "GetMalQueryMetadataV1"),
        (["quota"], "GetMalQueryQuotasV1"),
    ],
)
def test_scope_denial_explains_malquery_license(command, operation) -> None:
    recorded = RecordedTransport([serve(operation, fixture("errors/403-scope.json"))])
    stdout, code = run(["malquery", *command], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"
    assert decode(stdout)["required_scopes"] == ["MalQuery:read"]
    assert "needs Falcon MalQuery" in stdout
    assert "scope is absent from the picker" in stdout


@pytest.mark.parametrize("body", [{}, [None], [{"sha256": "1" * 64}], {"resources": [], "errors": [{"code": 500}]}])
def test_invalid_metadata_does_not_claim_no_data(body) -> None:
    recorded = RecordedTransport([serve("GetMalQueryMetadataV1", response(200, body))])
    stdout, code = run(["malquery", "show", SHA256], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


@pytest.mark.parametrize("body", [{}, {"meta": {}}, {"meta": {"hunt_limit": 5}, "errors": [{"code": 500}]}])
def test_invalid_quota_does_not_invent_zero_counters(body) -> None:
    recorded = RecordedTransport([serve("GetMalQueryQuotasV1", response(200, body))])
    stdout, code = run(["malquery", "quota"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


def test_malquery_registry_admits_only_metadata_and_quota_reads() -> None:
    assert {id for id in OPERATIONS if "MalQuery" in id} == {"GetMalQueryMetadataV1", "GetMalQueryQuotasV1"}
    assert not any(id.startswith("PostMalQuery") for id in OPERATIONS)
    assert "GetMalQueryDownloadV1" not in OPERATIONS
    assert "GetMalQueryEntitiesSamplesFetchV1" not in OPERATIONS
