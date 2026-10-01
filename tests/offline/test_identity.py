"""The Identity Protection domain over GraphQL (docs/design/v1.md §4.4, §10.2)."""

import re
import shlex
from typing import Any

import pytest
from graphql import GraphQLResolveInfo, build_schema, graphql_sync
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.transport.graphql import GRAPHQL_DOCUMENTS, request_body
from falcon_axi.transport.operations import operation
from falcon_axi.transport.types import FalconResponse, RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, FIXTURES, NO_CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

GRAPHQL = "api_preempt_proxy_post_graphql"
ENTITY_ID = "00000000-0000-4000-8000-000000000001"
LISTED = [serve(GRAPHQL, fixture("identity/entities-page.json"))]
DETAIL = [serve(GRAPHQL, fixture("identity/entity-detail.json"))]
TIMELINE = [serve(GRAPHQL, fixture("identity/timeline-page.json"))]
SCHEMA = build_schema((FIXTURES / "identity/schema.graphql").read_text(encoding="utf-8"))


def _execute_query(args: RequestArgs, root: dict[str, Any]) -> FalconResponse:
    body = request_body(operation(GRAPHQL), args.document, args.variables, args.body)
    result = graphql_sync(SCHEMA, body["query"], variable_values=body["variables"], root_value=root)
    assert not result.errors, result.errors
    return response(200, {"data": result.data})


def _sent(recorded: RecordedTransport) -> RequestArgs:
    requests = recorded.operation_requests(GRAPHQL)
    assert len(requests) == 1
    return requests[0]


def _cursor_of(stdout: str) -> str:
    match = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert match
    return match.group(1)


def test_identity_list_sends_one_registered_document_with_its_filters_as_variables() -> None:
    recorded = RecordedTransport(LISTED)
    stdout, exit_code = run(
        ["identity", "list", "--name", "Admin*", "--email", "*@example.test", "--domain", "EXAMPLE.TEST", "--limit", "2"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 0
    sent = _sent(recorded)
    assert sent.document == "identity_list"
    assert sent.body is None
    assert sent.variables == {"first": 2, "name": "Admin*", "email": "*@example.test", "domains": ["EXAMPLE.TEST"]}
    parsed = decode(stdout)
    assert parsed["count"] == "2 shown"
    assert parsed["identities"][0] == {
        "id": ENTITY_ID,
        "name": "Synthetic Admin",
        "secondary": "synthetic.admin@example.test",
        "type": "USER",
        "risk": "HIGH (0.82)",
    }
    assert parsed["identities"][1]["type"] == "ENDPOINT"


def test_identity_list_omits_the_variables_it_was_not_given() -> None:
    recorded = RecordedTransport(LISTED)
    run(["identity", "list"], recorded, dict(CREDENTIAL_ENV))
    assert _sent(recorded).variables == {"first": 20}


def test_the_type_flag_selects_a_registered_document_rather_than_building_one() -> None:
    for kind, document in (("user", "identity_list_users"), ("ENDPOINT", "identity_list_endpoints")):
        recorded = RecordedTransport(LISTED)
        _, exit_code = run(["identity", "list", "--type", kind], recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 0
        assert _sent(recorded).document == document
        assert document in GRAPHQL_DOCUMENTS


def test_an_unknown_type_a_bare_wildcard_and_an_oversized_limit_are_refused_before_any_request() -> None:
    for argv, needle in (
        (["identity", "list", "--type", "group"], "unknown type group"),
        (["identity", "list", "--name", "*"], "bare wildcard"),
        (["identity", "list", "--email", " * "], "bare wildcard"),
        (["identity", "list", "--limit", "201"], "--limit must be an integer from 1 to 200"),
    ):
        recorded = RecordedTransport(LISTED)
        stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
        assert exit_code == 2
        assert needle in stdout
        assert recorded.requests == []


@pytest.mark.parametrize("authentication", ["missing", "valid", "failed"])
@pytest.mark.parametrize(
    "argv, message",
    [
        (["identity", "list", "--type", "group"], "unknown type group"),
        (["identity", "list", "--name", "*"], "bare wildcard"),
        (["identity", "list", "--email", " * "], "bare wildcard"),
        (["identity", "list", "--domain", " \t "], "--domain requires a value"),
        (["identity", "list", "--limit", "201"], "--limit must be an integer"),
        (["identity", "show", "not-a-guid"], "an identity id must be an entity GUID"),
        (["identity", "timeline", "not-a-guid"], "an identity id must be an entity GUID"),
        (["identity", "timeline", ENTITY_ID, "--category", "gossip"], "unknown --category"),
        (["identity", "timeline", ENTITY_ID, "--category", "activity,"], "unknown --category"),
        (["identity", "timeline", ENTITY_ID, "--since", "yesterday"], "--since must be a relative window"),
    ],
)
def test_identity_usage_errors_precede_credentials_and_all_requests(authentication: str, argv: list[str], message: str) -> None:
    env = NO_CREDENTIAL_ENV if authentication == "missing" else CREDENTIAL_ENV
    oauth = response(401, {}) if authentication == "failed" else fixture("oauth2/token-success.json")
    recorded = RecordedTransport([], oauth=[oauth])
    stdout, exit_code = run(argv, recorded, dict(env))
    assert exit_code == 2
    parsed = decode(stdout)
    assert parsed["code"] == "VALIDATION_ERROR"
    assert message in parsed["error"]
    assert recorded.requests == []


def test_identity_help_skips_input_validation_and_authentication() -> None:
    for argv in (
        ["identity", "list", "--type", "group", "--help"],
        ["identity", "show", "not-a-guid", "--help"],
        ["identity", "timeline", "--since", "yesterday", "--help"],
    ):
        recorded = RecordedTransport([])
        stdout, exit_code = run(argv, recorded, dict(NO_CREDENTIAL_ENV))
        assert exit_code == 0
        assert stdout.startswith("falcon-axi identity")
        assert recorded.requests == []


def test_identity_list_continues_with_an_opaque_cursor_bound_to_its_filters() -> None:
    first = RecordedTransport(LISTED)
    stdout, _ = run(["identity", "list", "--name", "Admin*"], first, dict(CREDENTIAL_ENV))
    cursor = _cursor_of(stdout)
    assert "synthetic-end-cursor-01" not in stdout
    assert "identity list --name 'Admin*' --cursor" in stdout

    second = RecordedTransport(LISTED)
    run(["identity", "list", "--name", "Admin*", "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    assert _sent(second).variables == {"first": 20, "name": "Admin*", "after": "synthetic-end-cursor-01"}

    other = RecordedTransport(LISTED)
    stdout, exit_code = run(["identity", "list", "--name", "Other*", "--cursor", cursor], other, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "does not continue the current query" in stdout
    assert other.operation_requests(GRAPHQL) == []


@pytest.mark.parametrize(
    "first_flags, second_flags",
    [
        (
            ["--name", "Ops|Admin", "--email", "user@example.test"],
            ["--name", "Ops", "--email", "Admin|user@example.test"],
        ),
        (
            ["--email", "user|team", "--domain", "example.test"],
            ["--email", "user", "--domain", "team|example.test"],
        ),
    ],
)
@pytest.mark.parametrize("entity_type", [None, "user", "endpoint"])
def test_directory_cursor_rejects_ambiguous_filter_boundaries(
    first_flags: list[str], second_flags: list[str], entity_type: str | None
) -> None:
    argv = ["identity", "list", *(["--type", entity_type] if entity_type else [])]
    for original, changed in ((first_flags, second_flags), (second_flags, first_flags)):
        stdout, exit_code = run([*argv, *original], RecordedTransport(LISTED), dict(CREDENTIAL_ENV))
        assert exit_code == 0
        cursor = _cursor_of(stdout)
        continued = RecordedTransport(LISTED)
        _, exit_code = run([*argv, *original, "--cursor", cursor], continued, dict(CREDENTIAL_ENV))
        assert exit_code == 0
        variables = _sent(continued).variables
        assert variables is not None
        assert variables["after"] == "synthetic-end-cursor-01"
        other = RecordedTransport(LISTED)
        stdout, exit_code = run([*argv, *changed, "--cursor", cursor], other, dict(CREDENTIAL_ENV))
        assert exit_code == 2
        assert "does not continue the current query" in stdout
        assert other.operation_requests(GRAPHQL) == []


@pytest.mark.parametrize("pattern", ["O'Brien", '*$HOME"test"*', "a;b", "a\\b", "two words", "Admin*"])
@pytest.mark.parametrize("flag", ["name", "email", "domain"])
def test_identity_continuation_replays_shell_sensitive_filters(flag: str, pattern: str) -> None:
    argv = ["identity", "list", f"--{flag}", pattern]
    first = RecordedTransport(LISTED)
    stdout, exit_code = run(argv, first, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    hint = next(item for item in decode(stdout)["help"] if item.endswith("` for the next page"))
    replay = shlex.split(hint.removeprefix("Run `").removesuffix("` for the next page"))
    assert replay[:-2] == ["falcon-axi", *argv]
    second = RecordedTransport(LISTED)
    _, exit_code = run(replay[1:], second, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert _sent(second).variables == {**_sent(first).variables, "after": "synthetic-end-cursor-01"}


def test_the_last_page_carries_no_cursor_and_an_empty_result_is_a_definitive_statement() -> None:
    stdout, _ = run(
        ["identity", "list", "--name", "Nobody*"],
        RecordedTransport([serve(GRAPHQL, fixture("identity/entities-empty.json"))]),
        dict(CREDENTIAL_ENV),
    )
    assert "continuation_cursor" not in stdout
    assert re.search(r"^identities: 0 identities matching name Nobody\*$", stdout, re.MULTILINE)


@pytest.mark.parametrize("flag", ["name", "email", "domain"])
def test_empty_directory_filters_are_encoded_as_one_toon_value(flag: str) -> None:
    pattern = 'Ann\nMarie\r\t"\\, : test'
    recorded = RecordedTransport([serve(GRAPHQL, fixture("identity/entities-empty.json"))])
    stdout, exit_code = run(["identity", "list", f"--{flag}", pattern], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    parsed = decode(stdout)
    assert parsed["identities"] == f"0 identities matching {flag} {pattern}"
    assert set(parsed) == {"identities", "help"}
    assert len(stdout.splitlines()) == 2


@pytest.mark.parametrize("empty", [False, True])
def test_timeline_window_text_is_encoded_as_one_toon_value(empty: bool) -> None:
    recorded = RecordedTransport(
        [serve(GRAPHQL, fixture("identity/timeline-empty.json" if empty else "identity/timeline-page.json"))]
    )
    stdout, exit_code = run(["identity", "timeline", ENTITY_ID, "--since", "7d\n"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    parsed = decode(stdout)
    if empty:
        assert parsed["events"] == "0 events for this identity in the last 7d\n"
    else:
        assert parsed["window"] == "the last 7d\n"


def test_identity_show_prints_risk_accounts_associations_and_open_incidents() -> None:
    recorded = RecordedTransport(DETAIL)
    stdout, exit_code = run(["identity", "show", ENTITY_ID], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    sent = _sent(recorded)
    assert (sent.document, sent.variables) == ("identity_show", {"entityIds": [ENTITY_ID]})
    detail = decode(stdout)["identity"]
    assert detail["risk"] == "HIGH (0.82)"
    assert detail["risk_factors"] == [
        {"type": "WEAK_PASSWORD", "severity": "MEDIUM"},
        {"type": "STALE_ACCOUNT", "severity": "LOW"},
    ]
    assert detail["accounts"][0]["domain"] == "EXAMPLE.TEST"
    assert detail["accounts"][0]["account"] == "synthetic.admin"
    assert detail["accounts"][1] == {"source": "SYNTHETIC_SSO", "title": "Synthetic Engineer"}
    assert [row["name"] for row in detail["associations"]] == [
        "SYNTH-DC-01",
        "synthetic-local-admin",
        "Sampletown, Exampleland",
    ]
    assert detail["open_incidents"] == [
        {
            "type": "POTENTIAL_RISKY_ACTIVITY",
            "start": "2026-09-30T08:00:00Z",
            "end": "unknown",
            "compromised": "Synthetic Admin",
        }
    ]
    assert f"identity timeline {ENTITY_ID}" in stdout


def test_identity_show_caps_a_long_association_list_until_full_is_given() -> None:
    template = fixture("identity/entity-detail.json")
    node = template.body["data"]["entities"]["nodes"][0]
    many = [{"bindingType": "LOCAL_ADMIN", "accountName": f"synthetic-account-{index}"} for index in range(30)]
    long_body = {"data": {"entities": {"nodes": [{**node, "associations": many}]}}}
    capped, _ = run(
        ["identity", "show", ENTITY_ID], RecordedTransport([serve(GRAPHQL, response(200, long_body))]), dict(CREDENTIAL_ENV)
    )
    assert decode(capped)["identity"]["associations_total"] == 30
    assert len(decode(capped)["identity"]["associations"]) == 25
    assert f"identity show {ENTITY_ID} --full" in capped
    full, _ = run(
        ["identity", "show", ENTITY_ID, "--full"],
        RecordedTransport([serve(GRAPHQL, response(200, long_body))]),
        dict(CREDENTIAL_ENV),
    )
    assert len(decode(full)["identity"]["associations"]) == 30
    assert "associations_total" not in full


@pytest.mark.parametrize("incident_count", [0, 9, 10, 11])
@pytest.mark.parametrize("full", [False, True])
def test_identity_show_discloses_the_server_incident_cap_even_with_full(incident_count: int, full: bool) -> None:
    incident = fixture("identity/entity-detail.json").body["data"]["entities"]["nodes"][0]["openIncidents"]["nodes"][0]
    incidents = [incident] * incident_count

    def open_incidents(info: GraphQLResolveInfo, first: int) -> dict[str, Any]:
        return {"nodes": incidents[:first], "pageInfo": {"hasNextPage": len(incidents) > first}}

    node = {"entityId": ENTITY_ID, "openIncidents": open_incidents}
    recorded = RecordedTransport([serve(GRAPHQL, lambda args: _execute_query(args, {"entities": {"nodes": [node]}}))])
    stdout, exit_code = run(["identity", "show", ENTITY_ID, *(["--full"] if full else [])], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    detail = decode(stdout)["identity"]
    assert len(detail["open_incidents"]) == min(incident_count, 10)
    if incident_count > 10:
        assert detail["open_incidents_partial"] is True
        assert "Open incidents are limited to the first 10; more exist in Falcon" in stdout
        assert "--full expands associations only" in stdout
    else:
        assert "open_incidents_partial" not in detail
        assert "more exist in Falcon" not in stdout
    _sent(recorded)


def test_identity_show_refuses_a_value_that_is_not_a_guid_and_reports_a_missing_identity() -> None:
    recorded = RecordedTransport(DETAIL)
    stdout, exit_code = run(["identity", "show", "synthetic-admin"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "an identity id must be an entity GUID" in stdout
    assert recorded.requests == []

    stdout, exit_code = run(
        ["identity", "show", ENTITY_ID],
        RecordedTransport([serve(GRAPHQL, fixture("identity/entities-empty.json"))]),
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 1
    assert "code: NOT_FOUND" in stdout


def test_identity_timeline_sends_its_window_categories_and_page_size_as_variables() -> None:
    recorded = RecordedTransport(TIMELINE)
    stdout, exit_code = run(
        ["identity", "timeline", ENTITY_ID, "--since", "24h", "--category", "threat,audit", "--limit", "2"],
        recorded,
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 0
    sent = _sent(recorded)
    assert sent.document == "identity_timeline"
    assert sent.variables is not None
    assert sent.variables["entityIds"] == [ENTITY_ID]
    assert sent.variables["categories"] == ["THREAT", "AUDIT"]
    assert sent.variables["first"] == 2
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", sent.variables["startTime"])
    assert "after" not in sent.variables
    parsed = decode(stdout)
    assert parsed["window"] == "the last 24h"
    assert parsed["events"][0] == {
        "time": "2026-09-30T10:15:00Z",
        "type": "SUCCESSFUL_AUTHENTICATION",
        "severity": "INFORMATIONAL",
        "user": "Synthetic Admin",
        "endpoint": "SYNTH-WS-07",
        "ip": "192.0.2.10",
    }
    # An alert event has no endpoint or address, and the row says so rather than dropping the column.
    assert parsed["events"][1]["endpoint"] == "unknown"
    assert parsed["events"][1]["user"] == "Synthetic Admin"


@pytest.mark.parametrize(
    "event_type",
    [
        "TimelineUserOnEndpointActivityEvent",
        "TimelineAuthenticationEvent",
        "TimelineSuccessfulAuthenticationEvent",
        "TimelineFailedAuthenticationEvent",
        "TimelineServiceAccessEvent",
        "TimelineLdapSearchEvent",
        "TimelineDceRpcEvent",
        "TimelineRemoteCodeExecutionEvent",
        "TimelineFileOperationEvent",
        "TimelineAlertEvent",
    ],
)
@pytest.mark.parametrize("endpoint_name", ["SYNTH-WS-07", None])
def test_timeline_fetches_event_specific_fields_on_initial_and_continued_pages(
    event_type: str, endpoint_name: str | None
) -> None:
    event = {
        "__typename": event_type,
        "eventId": "synthetic-event",
        "eventType": "SYNTHETIC_ACTIVITY",
        "eventSeverity": "INFORMATIONAL",
        "timestamp": "2026-09-30T10:15:00Z",
        "sourceEntity": {"entityId": ENTITY_ID, "primaryDisplayName": "Synthetic Admin"},
        "targetEntity": {"entityId": ENTITY_ID, "primaryDisplayName": "SYNTH-TARGET"},
        "userDisplayName": "Synthetic User",
        "endpointDisplayName": endpoint_name,
        "ipAddress": "192.0.2.10",
    }
    root = {"timeline": {"nodes": [event], "pageInfo": {"hasNextPage": True, "endCursor": "synthetic-next-page"}}}
    cursor: list[str] = []
    for _ in range(2):
        recorded = RecordedTransport([serve(GRAPHQL, lambda args: _execute_query(args, root))])
        stdout, exit_code = run(
            ["identity", "timeline", ENTITY_ID, "--category", "activity", *cursor], recorded, dict(CREDENTIAL_ENV)
        )
        assert exit_code == 0
        row = decode(stdout)["events"][0]
        if event_type == "TimelineAlertEvent":
            assert (row["user"], row["endpoint"], row["ip"]) == ("Synthetic Admin", "unknown", "unknown")
        else:
            assert (row["user"], row["endpoint"], row["ip"]) == (
                "Synthetic User",
                endpoint_name or "SYNTH-TARGET",
                "192.0.2.10",
            )
        if cursor:
            variables = _sent(recorded).variables
            assert variables is not None
            assert variables["after"] == "synthetic-next-page"
        cursor = ["--cursor", _cursor_of(stdout)]


def test_identity_timeline_defaults_to_seven_days_and_sends_no_categories() -> None:
    recorded = RecordedTransport(TIMELINE)
    run(["identity", "timeline", ENTITY_ID], recorded, dict(CREDENTIAL_ENV))
    variables = _sent(recorded).variables
    assert variables is not None
    assert "categories" not in variables


def test_a_timeline_cursor_continues_the_same_window_and_replays_the_identity_id() -> None:
    first = RecordedTransport(TIMELINE)
    stdout, _ = run(["identity", "timeline", ENTITY_ID, "--since", "3d"], first, dict(CREDENTIAL_ENV))
    start = _sent(first).variables["startTime"]  # type: ignore[index]
    cursor = _cursor_of(stdout)
    assert f"falcon-axi identity timeline {ENTITY_ID} --since 3d --cursor {cursor}" in stdout

    second = RecordedTransport(TIMELINE)
    run(["identity", "timeline", ENTITY_ID, "--since", "3d", "--cursor", cursor], second, dict(CREDENTIAL_ENV))
    variables = _sent(second).variables
    assert variables is not None
    assert (variables["startTime"], variables["after"]) == (start, "synthetic-timeline-cursor-01")


@pytest.mark.parametrize(
    "changed",
    [
        ["identity", "timeline", "00000000-0000-4000-8000-000000000002", "--since", "3d", "--category", "activity"],
        ["identity", "timeline", ENTITY_ID, "--since", "4d", "--category", "activity"],
        ["identity", "timeline", ENTITY_ID, "--since", "3d", "--category", "threat"],
    ],
)
def test_timeline_cursor_remains_bound_to_identity_window_and_categories(changed: list[str]) -> None:
    stdout, exit_code = run(
        ["identity", "timeline", ENTITY_ID, "--since", "3d", "--category", "activity"],
        RecordedTransport(TIMELINE),
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 0
    other = RecordedTransport(TIMELINE)
    stdout, exit_code = run([*changed, "--cursor", _cursor_of(stdout)], other, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "does not continue the current query" in stdout
    assert other.operation_requests(GRAPHQL) == []


def test_a_timeline_with_no_events_says_so_and_an_unknown_category_is_refused() -> None:
    stdout, _ = run(
        ["identity", "timeline", ENTITY_ID],
        RecordedTransport([serve(GRAPHQL, fixture("identity/timeline-empty.json"))]),
        dict(CREDENTIAL_ENV),
    )
    assert "events: 0 events for this identity in the last 7d" in stdout
    recorded = RecordedTransport(TIMELINE)
    stdout, exit_code = run(["identity", "timeline", ENTITY_ID, "--category", "gossip"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "valid values for --category: activity, notification, threat, entity, audit, policy, system" in stdout
    assert recorded.requests == []


def test_a_missing_graphql_scope_names_the_write_labelled_scope_and_the_read_scope_honestly() -> None:
    for argv, read_scope in (
        (["identity", "list"], "Identity Protection Entities:read"),
        (["identity", "timeline", ENTITY_ID], "Identity Protection Timeline:read"),
    ):
        stdout, exit_code = run(
            argv, RecordedTransport([serve(GRAPHQL, fixture("identity/graphql-403-scope.json"))]), dict(CREDENTIAL_ENV)
        )
        assert exit_code == 1
        assert "code: SCOPE_DENIED" in stdout
        assert f"Identity Protection GraphQL:write and {read_scope}" in stdout
        assert "labelled write because Falcon requires it even for read-only queries" in stdout
        assert "captain exception N2" in stdout
        assert "(read only)" not in stdout


def test_a_graphql_validation_rejection_is_not_mistaken_for_a_bad_fql_filter() -> None:
    stdout, exit_code = run(
        ["identity", "list"], RecordedTransport([serve(GRAPHQL, fixture("identity/graphql-400.json"))]), dict(CREDENTIAL_ENV)
    )
    assert exit_code == 1
    assert "code: UPSTREAM_ERROR" in stdout
    assert "FQL" not in stdout
    assert "trace_id: synthetic-trace-graphql-400" in stdout
    assert "Cannot query field" not in stdout


def test_a_graphql_error_on_http_200_is_an_error_and_never_an_empty_result() -> None:
    for argv in (["identity", "list"], ["identity", "show", ENTITY_ID], ["identity", "timeline", ENTITY_ID]):
        stdout, exit_code = run(
            argv, RecordedTransport([serve(GRAPHQL, fixture("identity/graphql-errors-on-200.json"))]), dict(CREDENTIAL_ENV)
        )
        assert exit_code == 1
        assert "code: UPSTREAM_ERROR" in stdout
        assert "trace_id: synthetic-trace-graphql" in stdout
        assert "synthetic execution failure" not in stdout
        assert "0 identities" not in stdout


def test_an_error_alongside_partial_data_is_still_an_error() -> None:
    body = {**fixture("identity/entities-page.json").body, "errors": [{"message": "partial"}]}
    stdout, exit_code = run(
        ["identity", "list"], RecordedTransport([serve(GRAPHQL, response(200, body))]), dict(CREDENTIAL_ENV)
    )
    assert exit_code == 1
    assert "code: UPSTREAM_ERROR" in stdout


def test_no_identity_command_can_reach_a_document_outside_the_registry() -> None:
    """Every document an identity command names resolves from the closed registry."""
    sent: set[str] = set()
    for argv in (
        ["identity", "list"],
        ["identity", "list", "--type", "user"],
        ["identity", "list", "--type", "endpoint"],
        ["identity", "show", ENTITY_ID],
        ["identity", "timeline", ENTITY_ID],
    ):
        recorded = RecordedTransport([serve(GRAPHQL, fixture("identity/graphql-400.json"))])
        run(argv, recorded, dict(CREDENTIAL_ENV))
        sent.update(args.document for args in recorded.operation_requests(GRAPHQL) if args.document)
    assert sent == set(GRAPHQL_DOCUMENTS)
