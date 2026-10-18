import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


def test_summary_counts_alerts_without_the_list_result_window() -> None:
    recorded = RecordedTransport([serve("PostAggregatesAlertsV2", fixture("alerts/aggregate-severity.json"))])
    stdout, code = run(["detection", "summary"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout) == {"severities": [{"severity": "High", "count": 24000}, {"severity": "Critical", "count": 12}]}
    assert [args[0] for kind, args in recorded.requests if kind == "operation"] == ["PostAggregatesAlertsV2"]
    assert recorded.operation_requests("PostAggregatesAlertsV2")[0].body == [
        {"name": "severity", "type": "terms", "field": "severity_name", "size": 100, "missing": "unknown"}
    ]


def test_summary_uses_the_list_shorthand_and_raw_filter_contract() -> None:
    recorded = RecordedTransport([serve("PostAggregatesAlertsV2", fixture("alerts/aggregate-empty.json"))])
    stdout, code = run(
        [
            "detection",
            "summary",
            "--severity",
            "high",
            "--status",
            "new",
            "--product",
            "idp",
            "--since",
            "24h",
            "--filter",
            "tactic:'Discovery',tactic:'Execution'",
        ],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    assert "0 detections matching" in stdout
    assert recorded.operation_requests("PostAggregatesAlertsV2")[0].body[0]["filter"] == (
        "severity_name:'High'+status:'new'+product:'idp'+created_timestamp:>'now-24h'+(tactic:'Discovery',tactic:'Execution')"
    )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"errors": [{"message": "aggregation failed"}], "resources": []},
        {"resources": [{"name": "different", "buckets": []}]},
        {"resources": [{"name": "severity"}]},
        {"resources": [{"name": "severity", "buckets": [{"key": "High", "count": 2}]}]},
        {"resources": [{"name": "severity", "buckets": [{"label": "High", "count": -1}]}]},
    ],
)
def test_invalid_aggregate_results_do_not_claim_zero_detections(body: dict) -> None:
    recorded = RecordedTransport([serve("PostAggregatesAlertsV2", response(200, body))])
    stdout, code = run(["detection", "summary"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "UPSTREAM_ERROR"


def test_omitted_buckets_are_disclosed() -> None:
    recorded = RecordedTransport(
        [
            serve(
                "PostAggregatesAlertsV2",
                response(
                    200,
                    {
                        "resources": [
                            {"name": "severity", "buckets": [{"label": "High", "count": 10}], "sum_other_doc_count": 3}
                        ]
                    },
                ),
            )
        ]
    )
    stdout, code = run(["detection", "summary"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["other_count"] == 3


@pytest.mark.parametrize(
    ("args", "code"), [(["--severity", "urgent"], "VALIDATION_ERROR"), (["--limit", "10"], "VALIDATION_ERROR")]
)
def test_invalid_summary_flags_make_no_aggregate_request(args: list[str], code: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["detection", "summary", *args], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert decode(stdout)["code"] == code
    assert recorded.operation_requests("PostAggregatesAlertsV2") == []


@pytest.mark.parametrize(("status", "code"), [(403, "SCOPE_DENIED"), (429, "RATE_LIMITED"), (503, "UPSTREAM_UNAVAILABLE")])
def test_summary_translates_upstream_failures(status: int, code: str) -> None:
    recorded = RecordedTransport([serve("PostAggregatesAlertsV2", response(status, {}))])
    stdout, exit_code = run(["detection", "summary"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert decode(stdout)["code"] == code
