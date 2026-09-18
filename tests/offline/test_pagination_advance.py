"""Regression for the pagination advance fix (02aba94).

PostEntitiesAlertsV2 can return fewer records than the query step consumed when an alert ages out
between the query and hydrate calls. The continuation position must advance by the number of
query-step ids consumed, not by the hydrated row count, or detections at positions past the page
are silently dropped (total unknown) or re-shown (total known).
"""

import re

from falcon_axi.cli import run
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, response, serve


def _short_hydrate(severity: str, hostname: str):
    def hydrate(args: RequestArgs):
        return response(
            200,
            {
                "resources": [
                    {"composite_id": id, "severity_name": severity, "tactic": "Discovery", "device": {"hostname": hostname}}
                    for id in args.body["composite_ids"][:18]
                ]
            },
        )

    return hydrate


IDS = [f"ldt:synthetic-agent-{index}:{index}" for index in range(20)]


def test_total_unknown_a_short_hydrate_still_advances_the_cursor_by_the_ids_consumed() -> None:
    recorded = RecordedTransport(
        [
            # 20 ids returned for a limit-20 page, no total in meta.
            serve("GetQueriesAlertsV2", response(200, {"resources": IDS})),
            # Two ids aged out: only 18 records hydrate.
            serve("PostEntitiesAlertsV2", _short_hydrate("Medium", "WIN-WS-11")),
        ]
    )
    stdout, exit_code = run(["detection", "list", "--limit", "20"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^count: 18 of unknown total$", stdout, re.MULTILINE)
    # The bug stopped pagination here (18 >= 20 is false), dropping rows at positions 20+.
    assert re.search(r"^continuation_cursor: ", stdout, re.MULTILINE)


def test_total_known_a_short_hydrate_advances_the_cursor_past_the_whole_page() -> None:
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", response(200, {"meta": {"pagination": {"total": 100}}, "resources": IDS})),
            serve("PostEntitiesAlertsV2", _short_hydrate("Low", "WIN-WS-07")),
        ]
    )
    first, _ = run(["detection", "list", "--limit", "20"], recorded, dict(CREDENTIAL_ENV))
    cursor_line = next(line for line in first.split("\n") if line.startswith("continuation_cursor: "))
    cursor = cursor_line[len("continuation_cursor: ") :].strip()

    # Continuing with that cursor must query at offset 20, not 18 (which would re-show rows 18 and 19).
    next_transport = RecordedTransport(
        [serve("GetQueriesAlertsV2", response(200, {"meta": {"pagination": {"total": 100}}, "resources": []}))]
    )
    second, exit_code = run(["detection", "list", "--limit", "20", "--cursor", cursor], next_transport, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert next_transport.operation_requests("GetQueriesAlertsV2")[0].query["offset"] == 20
