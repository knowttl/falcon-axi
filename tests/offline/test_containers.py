"""Container read contracts follow falcon-mcp ece8575 cloud/cloud_containers.py.

Image inventory has no falcon-mcp tool; falconpy _container_images and PSFalcon
Get-FalconContainerAssessment corroborate its parameters.
Row fields match CrowdStrike/gofalcon 29988d8 falcon/models/models_container.go,
models_ext_api_image_combined.go and models_api_vulnerability_combined.go.
"""

import shlex
from typing import Any

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.commands import COMMAND_SPECS
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

CASES = [
    (
        "container list",
        "ReadContainerCombined",
        "containers/containers-page.json",
        "containers",
        "container_id",
        "container_name.asc",
        200,
    ),
    ("image list", "GetCombinedImages", "containers/images-page.json", "images", "image_id", "image_id.asc", 100),
    (
        "image vulnerabilities",
        "ReadCombinedVulnerabilities",
        "containers/vulnerabilities-page.json",
        "vulnerabilities",
        "cve_id",
        "cve_id.asc",
        100,
    ),
]
FILTER = "repository:'example/service'"


def cursor_at(command: str, sort: str, offset: int, filter: str | None = None) -> str:
    return encode_cursor(
        offset,
        CursorContext(
            operation=COMMAND_SPECS[command].operations[0],
            client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
            origin="https://api.crowdstrike.com",
            query=filter,
            sort=sort,
        ),
        CREDENTIAL_ENV["FALCON_CLIENT_SECRET"],
    )


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_list_reads_combined_rows_and_continues_with_the_same_filter(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([serve(operation, fixture(path))])
    stdout, code = run([*command.split(), "--filter", FILTER, "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 0
    assert document["count"] == "2 of 3 total"
    assert len(document[key]) == 2
    assert len(document[key][0]) == 4
    assert id_field in document[key][0]
    assert recorded.operation_requests(operation)[0].query == {"filter": FILTER, "limit": 2, "offset": 0, "sort": sort}
    next_command = shlex.split(document["help"][-1].split("`", 2)[1])[1:]
    resumed = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    next_stdout, next_code = run(next_command, resumed, dict(CREDENTIAL_ENV))
    assert next_code == 0
    assert f"no more {key}" in next_stdout
    assert resumed.operation_requests(operation)[0].query == {"filter": FILTER, "limit": 2, "offset": 2, "sort": sort}


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_last_window_page_shrinks_the_request_and_has_no_unreachable_cursor(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport(
        [
            serve(
                operation,
                response(
                    200,
                    {
                        "resources": [{id_field: "synthetic-last"}],
                        "meta": {"pagination": {"total": 10001}},
                    },
                ),
            )
        ]
    )
    stdout, code = run([*command.split(), "--cursor", cursor_at(command, sort, 9999)], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests(operation)[0].query["limit"] == 1
    document = decode(stdout)
    assert document["partial"] is True
    assert document["stop_reason"] == "pagination_limit"
    assert "continuation_cursor" not in document
    assert document[key][0][id_field] == "synthetic-last"


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_exhausted_window_fails_before_an_inventory_request(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([])
    stdout, code = run([*command.split(), "--cursor", cursor_at(command, sort, 10000)], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "PAGINATION_LIMIT"
    assert not recorded.operation_requests(operation)


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_changed_filter_rejects_the_cursor_before_an_inventory_request(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(
        [*command.split(), "--filter", FILTER, "--cursor", cursor_at(command, sort, 2)], recorded, dict(CREDENTIAL_ENV)
    )
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert not recorded.operation_requests(operation)


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_documented_page_ceiling_is_enforced_before_authentication(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([])
    stdout, code = run([*command.split(), "--limit", str(ceiling + 1)], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert not recorded.requests


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"resources": []}, "0 containers"),
        ({"resources": [{"container_id": "synthetic-only"}], "meta": {"pagination": {"total": 1}}}, "1 of 1 total"),
    ],
)
def test_complete_page_has_no_continuation(body: dict, expected: str) -> None:
    recorded = RecordedTransport([serve("ReadContainerCombined", response(200, body))])
    stdout, code = run(["container", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert expected in stdout
    assert "continuation_cursor" not in stdout


def test_full_page_without_a_total_keeps_the_total_unknown_and_offers_continuation() -> None:
    recorded = RecordedTransport(
        [serve("ReadContainerCombined", response(200, {"resources": [{"container_id": "synthetic-only"}]}))]
    )
    stdout, code = run(["container", "list", "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "1 of unknown total" in stdout
    assert "continuation_cursor" in stdout


@pytest.mark.parametrize("body", [{}, {"resources": {}}, {"resources": ["synthetic-id"]}, {"resources": [{}]}])
def test_malformed_inventory_never_masquerades_as_an_empty_success(body: dict) -> None:
    recorded = RecordedTransport([serve("ReadContainerCombined", response(200, body))])
    stdout, code = run(["container", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_scope_denial_names_the_container_image_read_scope(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([serve(operation, response(403, {}))])
    stdout, code = run(command.split(), recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"
    assert "Falcon Container Image:read" in stdout


@pytest.mark.parametrize("command,operation,path,key,id_field,sort,ceiling", CASES)
def test_invalid_filter_teaches_the_right_command(
    command: str,
    operation: str,
    path: str,
    key: str,
    id_field: str,
    sort: str,
    ceiling: int,
) -> None:
    recorded = RecordedTransport([serve(operation, response(400, {"errors": [{"message": "Invalid FQL filter"}]}))])
    stdout, code = run([*command.split(), "--filter", "invalid"], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    document: dict[str, Any] = decode(stdout)
    assert document["code"] == "FQL_INVALID"
    assert document["help"][-1] == f"Run `falcon-axi {command} --help` for the filterable fields"
