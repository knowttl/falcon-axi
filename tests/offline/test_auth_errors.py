import re
from dataclasses import replace

from falcon_axi.cli import run
from falcon_axi.render import render
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

SECRET = CREDENTIAL_ENV["FALCON_CLIENT_SECRET"]
TOKEN_SUCCESS = fixture("oauth2/token-success.json")
QUERY_PAGE = fixture("alerts/query-page.json")
HYDRATE_PAGE = fixture("alerts/hydrate-page.json")


def test_auth_status_reports_the_channel_and_region_without_printing_any_value() -> None:
    stdout, exit_code = run(["auth", "status"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert re.search(r"^credential_resolved: true$", stdout, re.MULTILINE)
    assert re.search(r"^credential_channel: environment$", stdout, re.MULTILINE)
    assert re.search(r"^tenant: us-1 \(own CID unavailable\)$", stdout, re.MULTILINE)
    assert re.search(r"^scopes: read-only client recommended; falcon-axi requests no write scope$", stdout, re.MULTILINE)
    assert re.search(r"^rate_limit: 5999 of 6000 requests remaining$", stdout, re.MULTILINE)
    assert SECRET not in stdout
    assert "synthetic-access-token" not in stdout


def test_auth_status_without_a_credential_reports_the_setup_paths_and_exits_0() -> None:
    stdout, exit_code = run(
        ["auth", "status"], RecordedTransport([]), {"FALCON_AXI_CREDENTIALS_FILE": "/nonexistent/credentials"}
    )
    assert exit_code == 0
    assert re.search(r"^credential_resolved: false$", stdout, re.MULTILINE)
    assert "FALCON_CLIENT_ID" in stdout


def test_a_member_cid_is_selected_at_token_mint_and_only_its_masked_suffix_is_printed() -> None:
    recorded = RecordedTransport([], [TOKEN_SUCCESS])
    stdout, exit_code = run(["auth", "status", "--member-cid", "synthetic-child-cid-a3b4"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    mint = recorded.oauth_requests()[0]
    assert mint.member_cid == "synthetic-child-cid-a3b4"
    assert "member CID …a3b4" in stdout
    assert "synthetic-child-cid-a3b4" not in stdout


def test_no_member_cid_clears_an_inherited_environment_selection() -> None:
    recorded = RecordedTransport([], [TOKEN_SUCCESS])
    run(["auth", "status", "--no-member-cid"], recorded, {**CREDENTIAL_ENV, "FALCON_MEMBER_CID": "synthetic-child-cid"})
    assert recorded.oauth_requests()[0].member_cid is None


def test_a_403_at_token_mint_with_a_member_cid_is_tenant_denied() -> None:
    recorded = RecordedTransport([], [fixture("oauth2/token-403-member-cid.json")])
    stdout, exit_code = run(["auth", "status", "--member-cid", "synthetic-child-cid"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: TENANT_DENIED$", stdout, re.MULTILINE)
    assert "--no-member-cid" in stdout


def test_a_401_at_token_mint_is_auth_failed_and_a_403_without_a_member_cid_is_too() -> None:
    unauthorized, exit_code = run(
        ["auth", "status"], RecordedTransport([], [fixture("oauth2/token-401.json")]), dict(CREDENTIAL_ENV)
    )
    assert exit_code == 1
    assert re.search(r"^code: AUTH_FAILED$", unauthorized, re.MULTILINE)

    forbidden, _ = run(
        ["auth", "status"], RecordedTransport([], [fixture("oauth2/token-403-member-cid.json")]), dict(CREDENTIAL_ENV)
    )
    assert re.search(r"^code: AUTH_FAILED$", forbidden, re.MULTILINE)
    assert "no scopes granted" in forbidden


def test_region_autodiscovery_retargets_exactly_once_on_x_cs_region() -> None:
    recorded = RecordedTransport([], [fixture("oauth2/token-region-us-2.json"), TOKEN_SUCCESS])
    stdout, exit_code = run(["auth", "status"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert len(recorded.oauth_requests()) == 2
    assert re.search(r"^tenant: us-2 \(re-targeted from us-1\) \(own CID unavailable\)$", stdout, re.MULTILINE)


def test_an_unknown_observed_region_is_region_mismatch_and_preserves_the_observed_value() -> None:
    observed = replace(TOKEN_SUCCESS, headers={"x-cs-region": "us-gov-2"})
    stdout, exit_code = run(["auth", "status"], RecordedTransport([], [observed]), dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: REGION_MISMATCH$", stdout, re.MULTILINE)
    assert "us-gov-2" in stdout
    assert "--allow-unknown-origin" in stdout


def test_a_403_on_an_operation_names_the_read_scopes_to_grant() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["detection", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: SCOPE_DENIED$", stdout, re.MULTILINE)
    assert re.search(r'required_scopes\[1\]: "?Alerts:read"?', stdout)
    assert "Falcon console" in stdout


def test_a_400_filter_rejection_teaches_the_fql_rules_and_exits_2() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/400-fql.json"))])
    stdout, exit_code = run(["detection", "list", "--filter", "severity_name:High"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert re.search(r"^code: FQL_INVALID$", stdout, re.MULTILINE)
    assert "+ for AND" in stdout


def test_an_upstream_failure_prints_the_trace_id_and_never_the_raw_falcon_body() -> None:
    recorded = RecordedTransport(
        [serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", fixture("errors/500-internal.json"))]
    )
    stdout, exit_code = run(["detection", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: UPSTREAM_ERROR$", stdout, re.MULTILINE)
    assert "synthetic-trace-500" in stdout
    assert "internal server error" not in stdout
    assert "500 " not in stdout
    assert "/alerts/entities" not in stdout


def test_a_429_after_retries_is_rate_limited() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/429-rate-limited.json"))])
    stdout, exit_code = run(["detection", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: RATE_LIMITED$", stdout, re.MULTILINE)


def test_no_credential_token_or_cid_value_reaches_stdout_on_a_successful_read() -> None:
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)])
    stdout, exit_code = run(
        ["detection", "list", "--limit", "2", "--member-cid", "synthetic-child-cid"], recorded, dict(CREDENTIAL_ENV)
    )
    assert exit_code == 0
    for secret in (SECRET, CREDENTIAL_ENV["FALCON_CLIENT_ID"], "synthetic-access-token", "synthetic-child-cid"):
        assert secret not in stdout, f"stdout leaked {secret}"


def test_redaction_covers_every_sensitive_key_that_reaches_the_renderer() -> None:
    rendered = render(
        {
            "access_token": "synthetic-access-token",
            "client_id": "synthetic-client-id",
            "client_secret": SECRET,
            "member_cid": "synthetic-child-cid",
            "token": "synthetic-token",
            "Authorization": "Bearer synthetic-access-token",
            "nested": {"client_secret": SECRET},
        }
    )
    for secret in ("synthetic-access-token", "synthetic-client-id", SECRET, "synthetic-child-cid", "synthetic-token"):
        assert secret not in rendered, f"render leaked {secret}"
    assert len(re.findall(r"\[redacted\]", rendered)) == 7


def test_a_rate_limit_headroom_note_appears_when_the_window_is_nearly_spent() -> None:
    low_headroom = replace(
        TOKEN_SUCCESS, headers={"x-cs-region": "us-1", "x-ratelimit-limit": "6000", "x-ratelimit-remaining": "100"}
    )
    recorded = RecordedTransport(
        [serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)], [low_headroom]
    )
    stdout, _ = run(["detection", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert re.search(r"^rate_limit: 100 of 6000 requests remaining in this rate limit window$", stdout, re.MULTILINE)
    assert response(200, {}).status == 200
