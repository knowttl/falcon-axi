import re

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from falcon_axi.detection import ALERTS_WALL, HYDRATE_CHUNK
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

QUERY_PAGE = fixture("alerts/query-page.json")
HYDRATE_PAGE = fixture("alerts/hydrate-page.json")
LINEAGE_ID = "ldt:synthetic-agent:1001"


def test_process_view_renders_recorded_lineage_without_another_operation() -> None:
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-lineage.json"))])
    stdout, code = run(["detection", "process", LINEAGE_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    result = decode(stdout)
    assert result["triggering_process_graph_id"] == "pid:synthetic-agent:1003"
    assert result["processes"] == [
        {
            "relation": "triggering",
            "filename": "synthetic-child.exe",
            "filepath": "C:\\Synthetic\\synthetic-child.exe",
            "cmdline": "synthetic-child.exe --example",
            "sha256": "a" * 64,
            "process_id": "1003",
        },
        {
            "relation": "parent",
            "filename": "synthetic-parent.exe",
            "filepath": "C:\\Synthetic\\synthetic-parent.exe",
            "cmdline": "synthetic-parent.exe --example",
            "sha256": "b" * 64,
            "process_id": "1002",
        },
        {
            "relation": "grandparent",
            "filename": "synthetic-grandparent.exe",
            "filepath": "C:\\Synthetic\\synthetic-grandparent.exe",
            "cmdline": "synthetic-grandparent.exe --example",
            "sha256": "c" * 64,
            "process_id": "1001",
        },
    ]
    assert recorded.operation_requests("PostEntitiesAlertsV2")[0].body == {"composite_ids": [LINEAGE_ID]}
    assert "sandbox" not in stdout


@pytest.mark.parametrize(
    "alert, expected",
    [
        ({"filename": "synthetic.exe"}, "parent: no parent recorded"),
        ({"product": "idp", "source_account_name": "synthetic-user"}, "processes: no process recorded for this detection"),
    ],
)
def test_process_view_states_missing_process_context(alert: dict, expected: str) -> None:
    recorded = RecordedTransport(
        [serve("PostEntitiesAlertsV2", response(200, {"resources": [{"composite_id": LINEAGE_ID, **alert}]}))]
    )
    stdout, code = run(["detection", "process", LINEAGE_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert expected in stdout


@pytest.mark.parametrize("relation", ["parent", "grandparent"])
@pytest.mark.parametrize("full", [False, True])
def test_process_view_preserves_ancestors_without_triggering_fields(relation: str, full: bool) -> None:
    alert = {"composite_id": LINEAGE_ID, f"{relation}_details": {"filename": "synthetic-ancestor.exe"}}
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", response(200, {"resources": [alert]}))])
    stdout, code = run(["detection", "process", LINEAGE_ID, *(["--full"] if full else [])], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["processes"][1:] == [
        {
            "relation": relation,
            "filename": "synthetic-ancestor.exe",
            "filepath": "unknown",
            "cmdline": "unknown",
            "sha256": "unknown",
            "process_id": "unknown",
        }
    ]


@pytest.mark.parametrize("relation", [None, "parent_details", "grandparent_details"])
@pytest.mark.parametrize("full", [False, True])
def test_process_command_lines_preview_or_expand_each_generation(relation: str | None, full: bool) -> None:
    alert = {"composite_id": LINEAGE_ID, "filename": "synthetic.exe"}
    command = "x" * 801
    payload = {"cmdline": command}
    alert.update(payload if relation is None else {relation: payload})
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", response(200, {"resources": [alert]}))])
    stdout, code = run(["detection", "process", LINEAGE_ID, *(["--full"] if full else [])], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert (command in stdout) == full
    assert ("truncated, 801 chars total" in stdout) == (not full)
    assert (f"detection process {LINEAGE_ID} --full" in stdout) == (not full)


def test_process_view_missing_detection_is_not_an_empty_lineage() -> None:
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", response(200, {"resources": []}))])
    stdout, code = run(["detection", "process", LINEAGE_ID], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "code: NOT_FOUND" in stdout


def _rows(stdout: str) -> list[str]:
    return [line for line in stdout.split("\n") if re.match(r'^ {2}"?ldt:', line)]


def test_shorthand_flags_compose_one_fql_filter_and_reach_the_query_step() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)])
    run(
        ["detection", "list", "--severity", "high", "--status", "new", "--since", "24h", "--limit", "2"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    args = recorded.operation_requests("GetQueriesAlertsV2")[0]
    assert args.query["filter"] == "severity_name:'High'+status:'new'+created_timestamp:>'now-24h'"
    assert args.query["limit"] == 2
    assert args.query["offset"] == 0


def test_the_hydrate_step_is_chunked_at_the_documented_cap_and_the_query_order_survives() -> None:
    ids = [f"ldt:synthetic-agent-{index}:{index}" for index in range(2500)]

    def hydrate(args: RequestArgs):
        chunk = args.body["composite_ids"]
        assert len(chunk) <= HYDRATE_CHUNK
        return response(
            200,
            {
                "resources": [
                    {"composite_id": id, "severity_name": "Medium", "tactic": "Discovery", "device": {"hostname": "WIN-WS-11"}}
                    for id in reversed(chunk)
                ]
            },
        )

    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", response(200, {"meta": {"pagination": {"total": 2500}}, "resources": ids})),
            serve("PostEntitiesAlertsV2", hydrate),
        ]
    )
    stdout, exit_code = run(["detection", "list", "--limit", "2500"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert len(recorded.operation_requests("PostEntitiesAlertsV2")) == 3
    rows = _rows(stdout)
    assert len(rows) == 2500
    assert re.match(r'^ {2}"?ldt:synthetic-agent-0:0"?,', rows[0])
    assert re.match(r'^ {2}"?ldt:synthetic-agent-2499:2499"?,', rows[2499])


def test_a_cursor_continues_the_same_query_and_the_wall_withholds_an_unreachable_cursor() -> None:
    position = ALERTS_WALL - 10
    cursor = encode_cursor(
        position,
        CursorContext(
            operation="GetQueriesAlertsV2",
            client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
            origin="https://api.crowdstrike.com",
        ),
        CREDENTIAL_ENV["FALCON_CLIENT_SECRET"],
    )
    ids = [f"ldt:synthetic-agent-{index}:{index}" for index in range(10)]
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", response(200, {"meta": {"pagination": {"total": 41892}}, "resources": ids})),
            serve(
                "PostEntitiesAlertsV2",
                lambda args: response(
                    200,
                    {
                        "resources": [
                            {
                                "composite_id": id,
                                "severity_name": "Low",
                                "tactic": "Discovery",
                                "device": {"hostname": "WIN-WS-07"},
                            }
                            for id in args.body["composite_ids"]
                        ]
                    },
                ),
            ),
        ]
    )
    stdout, exit_code = run(["detection", "list", "--limit", "20", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    args = recorded.operation_requests("GetQueriesAlertsV2")[0]
    assert args.query["offset"] == position
    # The requested page lands on the wall rather than overshooting it.
    assert args.query["limit"] == 10
    assert "continuation_cursor" not in stdout
    assert "PostCombinedAlertsV1" in stdout
