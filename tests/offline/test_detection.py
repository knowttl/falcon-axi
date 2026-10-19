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
