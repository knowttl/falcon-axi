"""Read-only T1 journeys, matched to falcon-mcp/modules/recon.py and sensor_usage.py."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

DOMAINS = [
    ("recon-rule", "rules", "QueryRulesV1", "GetRulesV1", "synthetic-rule-01"),
    ("recon-notification", "notifications", "QueryNotificationsV1", "GetNotificationsDetailedV1", "synthetic-notification-01"),
    (
        "recon-record",
        "records",
        "QueryNotificationsExposedDataRecordsV1",
        "GetNotificationsExposedDataRecordsV1",
        "synthetic-record-01",
    ),
]


@pytest.mark.parametrize("noun,fixture_name,query_op,get_op,id", DOMAINS)
def test_recon_list_preserves_query_order_and_total(noun, fixture_name, query_op, get_op, id):
    recorded = RecordedTransport(
        [
            serve(query_op, fixture(f"recon/{fixture_name}-query.json")),
            serve(get_op, fixture(f"recon/{fixture_name}.json")),
        ]
    )
    stdout, code = run([noun, "list", "--limit", "2", "--filter", "status:'new'"], recorded, dict(CREDENTIAL_ENV))
    parsed = decode(stdout)
    assert code == 0
    assert parsed["count"] == "2 of 4 total"
    assert parsed["records"][0]["id"] == id
    assert len(parsed["records"][0]) == 4
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests(query_op)[0].query == {"limit": 2, "offset": 0, "filter": "status:'new'"}
    assert recorded.operation_requests(get_op)[0].query == {"ids": (id, id[:-1] + "2")}
    continuation = parsed["continuation_cursor"]
    stdout, code = run(
        [noun, "list", "--limit", "2", "--filter", "status:'new'", "--cursor", continuation],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert code == 0
    assert recorded.operation_requests(query_op)[-1].query["offset"] == 2
    assert "continuation_cursor" not in stdout
    refused = RecordedTransport([])
    stdout, code = run([noun, "list", "--cursor", continuation], refused, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert refused.operation_requests(query_op) == []


def test_notifications_read_status_from_nested_notification():
    recorded = RecordedTransport(
        [
            serve("QueryNotificationsV1", fixture("recon/notifications-query.json")),
            serve("GetNotificationsDetailedV1", fixture("recon/notifications.json")),
        ]
    )
    stdout, code = run(["recon-notification", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["records"][0] == {
        "id": "synthetic-notification-01",
        "status": "new",
        "rule_name": "Synthetic breach monitor",
        "created_date": "2026-10-11T00:00:00Z",
    }


@pytest.mark.parametrize("noun,fixture_name,query_op,get_op,id", DOMAINS)
def test_recon_show_reads_only_selected_id_and_redacts_cid(noun, fixture_name, query_op, get_op, id):
    recorded = RecordedTransport([serve(get_op, fixture(f"recon/{fixture_name}.json"))])
    stdout, code = run([noun, "show", id], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["record"]["id"] == id
    assert "synthetic-cid" not in stdout
    assert recorded.operation_requests(query_op) == []
    assert recorded.operation_requests(get_op)[0].query == {"ids": (id,)}


@pytest.mark.parametrize("status,body", [(200, {"resources": []}), (404, {"errors": []})])
def test_recon_show_reports_missing_record(status, body):
    recorded = RecordedTransport([serve("GetRulesV1", response(status, body))])
    stdout, code = run(["recon-rule", "show", "missing"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "NOT_FOUND"


def test_recon_detail_truncates_nested_content_and_full_restores_it():
    recorded = RecordedTransport(
        [
            serve(
                "GetNotificationsDetailedV1",
                response(
                    200,
                    {
                        "resources": [{"id": "synthetic", "details": {"content": "x" * 900}}],
                    },
                ),
            )
        ]
    )
    stdout, code = run(["recon-notification", "show", "synthetic"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "truncated, 900 chars total" in stdout
    assert "falcon-axi recon-notification show synthetic --full" in stdout
    stdout, code = run(["recon-notification", "show", "synthetic", "--full"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["record"]["details"]["content"] == "x" * 900
    assert "help" not in decode(stdout)


@pytest.mark.parametrize("noun,fixture_name,query_op,get_op,id", DOMAINS)
@pytest.mark.parametrize("flags", [[], ["--full"]])
def test_recon_detail_redacts_complete_private_keys_before_preview(noun, fixture_name, query_op, get_op, id, flags):
    private_key = "-----BEGIN PRIVATE KEY-----\n" + "synthetic-key-material" * 60 + "\n-----END PRIVATE KEY-----"
    recorded = RecordedTransport(
        [
            serve(
                get_op,
                response(
                    200,
                    {
                        "resources": [
                            {
                                "id": id,
                                "content": private_key,
                                "details": {"content": private_key},
                                "matches": [private_key, {"content": private_key}],
                            }
                        ]
                    },
                ),
            )
        ]
    )
    stdout, code = run([noun, "show", id, *flags], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    parsed = decode(stdout)
    assert parsed["record"] == {
        "id": id,
        "content": "[redacted]",
        "details": {"content": "[redacted]"},
        "matches": ["[redacted]", {"content": "[redacted]"}],
    }
    assert "help" not in parsed


@pytest.mark.parametrize("status", [200, 404])
def test_missing_hydration_advances_cursor_by_queried_ids(status):
    recorded = RecordedTransport(
        [
            serve("QueryRulesV1", fixture("recon/rules-query.json")),
            serve("GetRulesV1", response(status, {"resources": []})),
        ]
    )
    stdout, code = run(["recon-rule", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    parsed = decode(stdout)
    assert code == 0
    assert parsed["count"] == "0 of 4 total"
    run(["recon-rule", "list", "--limit", "2", "--cursor", parsed["continuation_cursor"]], recorded, dict(CREDENTIAL_ENV))
    assert recorded.operation_requests("QueryRulesV1")[-1].query["offset"] == 2


def test_recon_clips_page_at_offset_wall_and_explains_remaining_results():
    context = CursorContext(
        operation="QueryRulesV1", client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"], origin="https://api.crowdstrike.com"
    )
    cursor = encode_cursor(9999, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    recorded = RecordedTransport(
        [
            serve(
                "QueryRulesV1", response(200, {"meta": {"pagination": {"total": 10001}}, "resources": ["synthetic-rule-01"]})
            ),
            serve("GetRulesV1", fixture("recon/rules.json")),
        ]
    )
    stdout, code = run(["recon-rule", "list", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests("QueryRulesV1")[0].query == {"limit": 1, "offset": 9999}
    assert "continuation_cursor" not in stdout
    assert "stop_reason: pagination_limit" in stdout


@pytest.mark.parametrize("count", [None, 0])
def test_empty_recon_list_is_definitive_and_does_not_hydrate(count):
    recorded = RecordedTransport(
        [
            serve("QueryRulesV1", response(200, {"resources": [], "meta": {"pagination": {"total": count}}})),
        ]
    )
    stdout, code = run(["recon-rule", "list", "--filter", "status:'inactive'"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 records matching the supplied filter" in stdout
    assert recorded.operation_requests("GetRulesV1") == []


def test_unknown_total_is_not_invented_and_full_page_offers_continuation():
    recorded = RecordedTransport(
        [
            serve("QueryRulesV1", response(200, {"resources": ["synthetic-rule-01"]})),
            serve("GetRulesV1", fixture("recon/rules.json")),
        ]
    )
    stdout, code = run(["recon-rule", "list", "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "1 of unknown total" in stdout
    assert "continuation_cursor" in stdout


@pytest.mark.parametrize(
    "argv,op,scope",
    [
        (["recon-rule", "list"], "QueryRulesV1", "Monitoring rules (Falcon Intelligence Recon):read"),
        (
            ["recon-notification", "show", "synthetic"],
            "GetNotificationsDetailedV1",
            "Monitoring rules (Falcon Intelligence Recon):read",
        ),
        (["sensor-usage", "list"], "GetSensorUsageWeekly", "Sensor Usage:read"),
    ],
)
def test_scope_errors_name_required_read_scope(argv, op, scope):
    recorded = RecordedTransport([serve(op, fixture("errors/403-scope.json"))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert decode(stdout)["code"] == "SCOPE_DENIED"
    assert decode(stdout)["required_scopes"] == [scope]


@pytest.mark.parametrize(
    "noun,operation,example",
    [
        ("recon-rule", "QueryRulesV1", "status:'active'"),
        ("recon-notification", "QueryNotificationsV1", "status:'new'"),
        ("recon-record", "QueryNotificationsExposedDataRecordsV1", "domain:'example.com'"),
        ("sensor-usage", "GetSensorUsageWeekly", "period:'30'"),
    ],
)
def test_rejected_filter_guidance_uses_the_originating_domain(noun, operation, example):
    recorded = RecordedTransport(
        [serve(operation, response(400, {"errors": [{"message": "invalid FQL filter"}]}))]
    )
    stdout, code = run([noun, "list", "--filter", "bad"], recorded, dict(CREDENTIAL_ENV))
    parsed = decode(stdout)
    assert code == 2
    assert parsed["code"] == "FQL_INVALID"
    assert parsed["help"] == [
        "FQL uses + for AND, `,` for OR, and values must be quoted",
        f'Example: `--filter "{example}"`',
        f"Run `falcon-axi {noun} list --help` for the filterable fields",
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["recon-rule", "list", "--limit", "501"],
        ["recon-rule", "show"],
        ["recon-record", "delete", "synthetic"],
        ["recon-notification", "update", "synthetic"],
        ["sensor-usage", "list", "--cursor", "x"],
        ["sensor-usage", "show", "x"],
    ],
)
def test_invalid_t1_commands_fail_before_authentication(argv):
    recorded = RecordedTransport([])
    _, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert recorded.requests == []


@pytest.mark.parametrize("array_body", [False, True])
def test_sensor_usage_preserves_zero_metrics_and_passes_only_filter(array_body):
    answer = fixture("recon/usage.json")
    if array_body:
        answer = response(200, answer.body["resources"])
    recorded = RecordedTransport([serve("GetSensorUsageWeekly", answer)])
    stdout, code = run(["sensor-usage", "list", "--filter", "period:'30'"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert decode(stdout)["usage"][0]["chrome_os"] == 0
    assert decode(stdout)["usage"][0]["workstations"] == 42
    assert recorded.operation_requests("GetSensorUsageWeekly")[0].query == {"filter": "period:'30'"}


def test_sensor_usage_empty_response_is_definitive():
    recorded = RecordedTransport([serve("GetSensorUsageWeekly", response(200, {"resources": []}))])
    stdout, code = run(["sensor-usage", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 weekly sensor usage reports" in stdout
