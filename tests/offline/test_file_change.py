"""FileVantage public reads, exercised exclusively through the offline CLI seam."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport.operations import operation
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

FIRST = "synthetic-change-01"
SECOND = "synthetic-change-02"


def test_two_pages_preserve_order_and_after_token():
    recorded = RecordedTransport(
        [
            serve("highVolumeQueryChanges", fixture("filevantage/query.json")),
            serve("getChanges", fixture("filevantage/changes.json")),
        ]
    )
    argv = ["file-change", "list", "--limit", "2", "--filter", "host.name:'SYNTHETIC-HOST'"]
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 0
    value = decode(stdout)
    assert value["change_ids"] == [FIRST, SECOND]
    assert [row["entity_path"] for row in value["file_changes"]] == ["/synthetic/first.conf", "/synthetic/second.conf"]
    assert list(value["file_changes"][0]) == [
        "action_timestamp",
        "action_type",
        "entity_type",
        "entity_path",
        "host",
        "severity",
    ]
    assert "synthetic-hidden" not in stdout
    assert recorded.operation_requests("highVolumeQueryChanges")[0].query == {
        "limit": 2,
        "sort": "action_timestamp|desc",
        "filter": "host.name:'SYNTHETIC-HOST'",
    }
    next_page = RecordedTransport(
        [
            serve("highVolumeQueryChanges", response(200, {"resources": ["synthetic-third"]})),
            serve("getChanges", response(200, {"resources": [{"id": "synthetic-third"}]})),
        ]
    )
    stdout, code = run(argv + ["--cursor", value["continuation_cursor"]], next_page, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["change_ids"] == ["synthetic-third"]
    assert "continuation_cursor" not in stdout
    assert next_page.operation_requests("highVolumeQueryChanges")[0].query["after"] == "synthetic-filevantage-next"


@pytest.mark.parametrize(
    ("extra", "env"),
    [
        ([], {"FALCON_CLIENT_ID": "synthetic-other-client"}),
        ([], {"FALCON_CLIENT_SECRET": "synthetic-other-secret"}),
        (["--filter", "host.name:'OTHER'"], {}),
        (["--region", "eu-1"], {}),
        (["--member-cid", "a" * 32], {}),
    ],
)
def test_cursor_rejects_changed_query_or_credential_before_data_request(extra, env):
    first = RecordedTransport(
        [
            serve("highVolumeQueryChanges", fixture("filevantage/query.json")),
            serve("getChanges", fixture("filevantage/changes.json")),
        ]
    )
    stdout, code = run(["file-change", "list"], first, CREDENTIAL_ENV)
    assert code == 0
    cursor = decode(stdout)["continuation_cursor"]
    recorded = RecordedTransport([], oauth=[response(201, {"access_token": "synthetic-access-token"})])
    stdout, code = run(["file-change", "list", "--cursor", cursor, *extra], recorded, {**CREDENTIAL_ENV, **env})
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not recorded.operation_requests("highVolumeQueryChanges")


def test_hydration_caps_batches_at_500_and_restores_order():
    ids = [f"synthetic-change-{index}" for index in range(1001)]

    def hydrate(args: RequestArgs):
        return response(200, {"resources": [{"id": id} for id in reversed(args.query["ids"])]})

    recorded = RecordedTransport(
        [serve("highVolumeQueryChanges", response(200, {"resources": ids})), serve("getChanges", hydrate)]
    )
    stdout, code = run(["file-change", "list", "--limit", "1001"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert decode(stdout)["change_ids"] == ids
    assert [len(args.query["ids"]) for args in recorded.operation_requests("getChanges")] == [500, 500, 1]


@pytest.mark.parametrize("resources", [[{"id": SECOND}], []])
@pytest.mark.parametrize("envelope", [True, False])
def test_incomplete_list_hydration_fails_without_results_or_continuation(resources, envelope):
    recorded = RecordedTransport(
        [
            serve("highVolumeQueryChanges", fixture("filevantage/query.json")),
            serve("getChanges", response(200, {"resources": resources} if envelope else resources)),
        ]
    )
    stdout, code = run(["file-change", "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    value = decode(stdout)
    assert value["code"] == "UPSTREAM_ERROR"
    assert "count" not in value
    assert "file_changes" not in value
    assert "change_ids" not in value
    assert "continuation_cursor" not in value


@pytest.mark.parametrize("envelope", [True, False])
def test_mismatched_detail_hydration_is_upstream_error(envelope):
    resources = [{"id": SECOND}]
    recorded = RecordedTransport([serve("getChanges", response(200, {"resources": resources} if envelope else resources))])
    stdout, code = run(["file-change", "show", FIRST], recorded, CREDENTIAL_ENV)
    assert code == 1
    value = decode(stdout)
    assert value["code"] == "UPSTREAM_ERROR"
    assert "file_change" not in value


def test_show_includes_process_fields_and_diff_without_content_request():
    recorded = RecordedTransport([serve("getChanges", fixture("filevantage/changes.json"))])
    stdout, code = run(["file-change", "show", FIRST], recorded, CREDENTIAL_ENV)
    assert code == 0
    value = decode(stdout)["file_change"]
    assert value["id"] == FIRST
    assert value["process_id"] == "1234"
    assert value["command_line"] == "synthetic-editor --example"
    assert value["parent_process_image_file_name"] == "/synthetic/shell"
    assert value["grandparent_process_image_file_name"] == "/synthetic/launcher"
    assert value["diff"] == {}
    assert "synthetic-hidden" not in stdout
    assert recorded.operation_requests("getChanges")[0].query == {"ids": (FIRST,)}
    with pytest.raises(CliError):
        operation("getContents")


def test_empty_list_explains_data_and_licensing_without_hydration():
    recorded = RecordedTransport([serve("highVolumeQueryChanges", fixture("filevantage/empty.json"))])
    stdout, code = run(["file-change", "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "no file changes" in stdout
    assert "no matching data" in stdout
    assert "without Falcon FileVantage licensing" in stdout
    assert not recorded.operation_requests("getChanges")
    assert "continuation_cursor" not in stdout


@pytest.mark.parametrize("argv,op", [(["list"], "highVolumeQueryChanges"), (["show", FIRST], "getChanges")])
def test_scope_denied_explains_filevantage_license(argv, op):
    recorded = RecordedTransport([serve(op, fixture("errors/403-scope.json"))])
    stdout, code = run(["file-change", *argv], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Falcon FileVantage:read" in stdout
    assert "tenant lacks that subscription" in stdout


def test_rejected_fql_names_filevantage_host_filter():
    recorded = RecordedTransport(
        [serve("highVolumeQueryChanges", response(400, {"errors": [{"message": "invalid FQL filter"}]}))]
    )
    stdout, code = run(["file-change", "list", "--filter", "bad"], recorded, CREDENTIAL_ENV)
    assert code == 2
    assert "FQL_INVALID" in stdout
    assert "host.name:'SYNTHETIC-HOST'" in stdout
    assert "falcon-axi file-change list --help" in stdout


@pytest.mark.parametrize("answer", [response(404, {}), response(200, {"resources": []}), response(200, [])])
def test_missing_change_suggests_list(answer):
    recorded = RecordedTransport([serve("getChanges", answer)])
    stdout, code = run(["file-change", "show", FIRST], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "NOT_FOUND" in stdout
    assert "falcon-axi file-change list" in stdout


@pytest.mark.parametrize("body", [{}, {"resources": [None]}, {"resources": [], "errors": [{"message": "failed"}]}])
def test_malformed_query_is_not_reported_as_no_data(body):
    recorded = RecordedTransport([serve("highVolumeQueryChanges", response(200, body))])
    stdout, code = run(["file-change", "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout
