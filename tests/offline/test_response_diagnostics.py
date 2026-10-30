"""Shared byte contract and response-invalid output, using synthetic responses only."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import requests_mock
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.response_diagnostics import ResponseDiagnostics
from falcon_axi.transport import HttpTransport
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, response, serve

VECTORS = Path(__file__).resolve().parents[1] / "diagnostics" / "response-diagnostics-vectors.json"


def test_canonical_vector_bytes() -> None:
    # beyondtrust-axi 8a8626a9e1b15d2e23ef484a69176f216d757e7c, test/fixtures/response-diagnostics-sha256.json.
    expected = "30810792443114d526bae43d2aca31d73512386ec362d368109b56ebd7e6a9d0"
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("vector", json.loads(VECTORS.read_text()), ids=lambda vector: vector["name"])
def test_shared_diagnostics_vector(vector: dict[str, Any]) -> None:
    def redact(text: str) -> str:
        for secret in vector.get("secrets", []):
            text = text.replace(secret, "***redacted***")
        return text

    diagnostics = ResponseDiagnostics(redact)
    diagnostics.record(vector["status"], {"content-type": vector.get("contentType", "")}, vector["data"])
    if "issues" in vector:
        diagnostics.validation_failed(vector["issues"])
    assert diagnostics.details == vector["expected"]


@pytest.mark.parametrize(
    "body,content_type,shape",
    [
        ("<html>synthetic login secret</html>", "text/html; charset=utf-8", [{"path": "$", "type": "string"}]),
        (
            {"resources": "synthetic private value"},
            "application/json",
            [
                {"path": "$", "type": "object"},
                {"path": '$["resources"]', "type": "string"},
            ],
        ),
    ],
)
def test_invalid_success_reports_metadata_without_values(body: Any, content_type: str, shape: list[Any]) -> None:
    with requests_mock.Mocker() as mock:
        mock.post("https://api.crowdstrike.com/oauth2/token", json={"access_token": "synthetic-token"})
        options = {"text": body} if isinstance(body, str) else {"json": body}
        mock.get("https://api.crowdstrike.com/devices/queries/devices/v1", headers={"Content-Type": content_type}, **options)
        stdout, code = run(["host", "list"], HttpTransport(), CREDENTIAL_ENV)
    assert code == 1
    document = decode(stdout)
    assert document["code"] == "UPSTREAM_ERROR"
    assert document["status"] == 200
    assert document["contentType"] == content_type.split(";")[0]
    assert document["shape"] == shape
    assert "synthetic" not in stdout


def test_healthy_response_omits_diagnostics() -> None:
    transport = RecordedTransport([serve("QueryDevicesByFilter", response(200, {"resources": []}))])
    stdout, code = run(["host", "list"], transport, CREDENTIAL_ENV)
    assert code == 0
    document = decode(stdout)
    assert document["hosts"] == "0 hosts in this tenant"
    assert "shape" not in document
    assert "status" not in document


def test_non_response_error_omits_diagnostics() -> None:
    transport = RecordedTransport([serve("QueryDevicesByFilter", response(403, {"errors": []}))])
    stdout, code = run(["host", "list"], transport, CREDENTIAL_ENV)
    assert code == 1
    document = decode(stdout)
    assert document["code"] == "SCOPE_DENIED"
    assert "shape" not in document
    assert "status" not in document


def test_invalid_token_reports_its_own_response() -> None:
    transport = RecordedTransport([], oauth=[response(200, {"access_token": False}, {"Content-Type": "application/json"})])
    stdout, code = run(["host", "list"], transport, CREDENTIAL_ENV)
    assert code == 1
    document = decode(stdout)
    assert document["status"] == 200
    assert document["shape"] == [
        {"path": "$", "type": "object"},
        {"path": '$["access_token"]', "type": "boolean"},
    ]


def test_recording_another_response_resets_issue_annotations() -> None:
    diagnostics = ResponseDiagnostics()
    diagnostics.record(200, {}, {"field": 123})
    diagnostics.validation_failed([{"path": ["field"], "expected": "string"}])
    diagnostics.record(202, {}, {"field": False})
    assert diagnostics.details == {
        "status": 202,
        "contentType": None,
        "shape": [{"path": "$", "type": "object"}, {"path": '$["field"]', "type": "boolean"}],
        "shapeTruncated": False,
    }


@pytest.mark.parametrize("path,count", [(["field"], 64), (["a" * 40, "b" * 40], 46)])
def test_issue_annotations_are_bounded(path: list[str], count: int) -> None:
    diagnostics = ResponseDiagnostics()
    diagnostics.record(200, {}, {})
    diagnostics.validation_failed([{"path": path, "expected": "string"}] * 65)
    assert len(diagnostics.details["issues"]) == count
    assert diagnostics.details["issuePathsTruncated"] is True


def test_shape_entries_are_bounded() -> None:
    diagnostics = ResponseDiagnostics()
    diagnostics.record(200, {}, {f"field{index}": "synthetic private value" for index in range(65)})
    assert len(diagnostics.details["shape"]) == 64
    assert diagnostics.details["shapeTruncated"] is True
