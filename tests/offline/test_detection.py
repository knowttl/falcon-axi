import re

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from falcon_axi.detection import ALERTS_WALL, HYDRATE_CHUNK
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

QUERY_PAGE = fixture("alerts/query-page.json")
HYDRATE_PAGE = fixture("alerts/hydrate-page.json")


def _rows(stdout: str) -> list[str]:
    return [line for line in stdout.split("\n") if re.match(r'^ {2}"?ldt:', line)]


def test_detection_list_renders_the_four_field_schema_in_query_step_order() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)])
    stdout, exit_code = run(["detection", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^count: 2 of 384 total$", stdout, re.MULTILINE)
    assert re.search(r"^detections\[2\]\{id,severity,tactic,hostname\}:$", stdout, re.MULTILINE)
    rows = _rows(stdout)
    assert len(rows) == 2
    # The query step returned agent-01 first; the hydrate fixture returns agent-02 first.
    assert "ldt:synthetic-agent-01:1001" in rows[0]
    assert "High" in rows[0]
    assert "ldt:synthetic-agent-02:1002" in rows[1]
    assert re.search(r'help\[\d+\]: "Run `falcon-axi detection show <id>` for the full detection"', stdout)
    assert re.search(r"^continuation_cursor: ", stdout, re.MULTILINE)


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


def test_an_empty_result_states_the_filter_and_makes_no_hydrate_request() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("alerts/query-empty.json"))])
    stdout, exit_code = run(["detection", "list", "--severity", "critical", "--since", "24h"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^detections: 0 detections matching critical severity in the last 24h$", stdout, re.MULTILINE)
    assert recorded.operation_requests("PostEntitiesAlertsV2") == []
    assert "--since 7d" in stdout


def test_a_response_without_a_total_says_unknown_rather_than_inventing_a_count() -> None:
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", fixture("alerts/query-no-total.json")),
            serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-detail.json")),
        ]
    )
    stdout, _ = run(["detection", "list", "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert re.search(r"^count: 1 of unknown total$", stdout, re.MULTILINE)


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


def test_a_wall_reached_with_no_rows_retained_is_pagination_limit_at_exit_1() -> None:
    cursor = encode_cursor(
        ALERTS_WALL,
        CursorContext(
            operation="GetQueriesAlertsV2",
            client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
            origin="https://api.crowdstrike.com",
        ),
        CREDENTIAL_ENV["FALCON_CLIENT_SECRET"],
    )
    recorded = RecordedTransport([])
    stdout, exit_code = run(["detection", "list", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: PAGINATION_LIMIT$", stdout, re.MULTILINE)
    assert recorded.operation_requests("GetQueriesAlertsV2") == []


def test_detection_show_truncates_a_long_command_line_and_offers_full() -> None:
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-detail.json"))])
    truncated, exit_code = run(["detection", "show", "ldt:synthetic-agent-01:1001"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"truncated, \d+ chars total", truncated)
    assert "--full" in truncated
    assert "severity: High (70)" in truncated

    full, _ = run(["detection", "show", "ldt:synthetic-agent-01:1001", "--full"], recorded, dict(CREDENTIAL_ENV))
    assert "truncated" not in full
    assert "--full" not in full


def test_detection_show_reports_a_missing_detection_as_not_found() -> None:
    recorded = RecordedTransport([serve("PostEntitiesAlertsV2", response(200, {"resources": []}))])
    stdout, exit_code = run(["detection", "show", "ldt:absent:0"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: NOT_FOUND$", stdout, re.MULTILINE)


def test_the_home_view_caps_at_five_rows_and_names_the_read_only_posture() -> None:
    ids = [f"ldt:synthetic-agent-{index}:{index}" for index in range(5)]
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", response(200, {"meta": {"pagination": {"total": 384}}, "resources": ids})),
            serve(
                "PostEntitiesAlertsV2",
                lambda args: response(
                    200,
                    {
                        "resources": [
                            {
                                "composite_id": id,
                                "severity_name": "High",
                                "tactic": "Execution",
                                "device": {"hostname": "WIN-WS-42"},
                            }
                            for id in args.body["composite_ids"]
                        ]
                    },
                ),
            ),
        ]
    )
    stdout, exit_code = run([], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^description: Read CrowdStrike Falcon detections from the shell \(read-only\)$", stdout, re.MULTILINE)
    assert re.search(r"^tenant: us-1 \(own CID unavailable\)$", stdout, re.MULTILINE)
    assert re.search(r"^count: 5 of 384 total$", stdout, re.MULTILINE)
    assert len(_rows(stdout)) == 5


def test_the_home_view_without_a_credential_is_the_setup_instruction() -> None:
    stdout, exit_code = run([], RecordedTransport([]), {"FALCON_AXI_CREDENTIALS_FILE": "/nonexistent/credentials"})
    assert exit_code == 1
    assert re.search(r"^code: AUTH_REQUIRED$", stdout, re.MULTILINE)
    assert re.search(r"^bin: ", stdout, re.MULTILINE)
    assert "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET" in stdout
