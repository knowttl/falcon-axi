"""The Discover accounts domain (docs/design/v1.md §2.3, §5.7, §10.2)."""

import re

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve

PAGE = [
    serve("query_accounts", fixture("discover/accounts-query-page.json")),
    serve("get_accounts", fixture("discover/accounts-details-page.json")),
]


def test_account_list_queries_then_hydrates_and_renders_the_six_field_schema() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, exit_code = run(
        ["account", "list", "--limit", "2", "--filter", "admin_privileges:'Yes'"], recorded, dict(CREDENTIAL_ENV)
    )
    assert exit_code == 0
    assert re.search(r"^count: 2 of 41 total$", stdout, re.MULTILINE)
    assert "accounts[2]{id,username,account_type,login_domain,admin_privileges,last_login}:" in stdout
    assert "synthetic-account-01,synthetic-admin,Domain,SYNTHETIC,Yes," in stdout
    assert "synthetic-account-02,synthetic-user,Local,WIN-WS-42,No," in stdout
    (query,) = recorded.operation_requests("query_accounts")
    assert query.query == {"limit": 2, "offset": 0, "filter": "admin_privileges:'Yes'"}
    (hydrate,) = recorded.operation_requests("get_accounts")
    assert hydrate.query == {"ids": ("synthetic-account-01", "synthetic-account-02")}
    assert "synthetic-cid" not in stdout
    assert "Run `falcon-axi account show <id>` for the full account record" in stdout


def test_account_list_continues_with_a_cursor_bound_to_its_filter() -> None:
    recorded = RecordedTransport(PAGE)
    stdout, _ = run(["account", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE)
    assert cursor
    followed = RecordedTransport(PAGE)
    run(["account", "list", "--limit", "2", "--cursor", cursor.group(1)], followed, dict(CREDENTIAL_ENV))
    assert followed.operation_requests("query_accounts")[0].query["offset"] == 2
    refused, exit_code = run(
        ["account", "list", "--limit", "2", "--filter", "username:'x'", "--cursor", cursor.group(1)],
        RecordedTransport(PAGE),
        dict(CREDENTIAL_ENV),
    )
    assert exit_code == 2
    assert "VALIDATION_ERROR" in refused


def test_account_list_stops_offering_a_cursor_at_the_last_page() -> None:
    context = CursorContext(
        operation="query_accounts",
        client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
        origin="https://api.crowdstrike.com",
        model="offset",
    )
    cursor = encode_cursor(39, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    stdout, _ = run(["account", "list", "--limit", "2", "--cursor", cursor], RecordedTransport(PAGE), dict(CREDENTIAL_ENV))
    assert "continuation_cursor" not in stdout


def test_an_empty_result_states_whether_a_filter_produced_it() -> None:
    recorded = RecordedTransport([serve("query_accounts", fixture("discover/accounts-query-empty.json"))])
    stdout, _ = run(["account", "list", "--filter", "username:'nobody'"], recorded, dict(CREDENTIAL_ENV))
    assert "accounts: 0 accounts matching the supplied filter" in stdout
    assert recorded.operation_requests("get_accounts") == []
    stdout, _ = run(["account", "list"], recorded, dict(CREDENTIAL_ENV))
    assert "accounts: 0 accounts in this tenant" in stdout


def test_account_show_renders_the_detail_and_pivots_to_the_last_login_host() -> None:
    recorded = RecordedTransport([serve("get_accounts", fixture("discover/accounts-details-one.json"))])
    stdout, exit_code = run(["account", "show", "synthetic-account-01"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert "user_sid: S-1-5-21-0-0-0-1001" in stdout
    assert "last_login_hostname: WIN-DC-01" in stdout
    assert "Run `falcon-axi host logins synthetic-device-01`" in stdout
    assert "synthetic-cid" not in stdout


def test_an_unknown_account_is_not_found() -> None:
    recorded = RecordedTransport([serve("get_accounts", fixture("discover/accounts-details-empty.json"))])
    stdout, exit_code = run(["account", "show", "synthetic-account-99"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: NOT_FOUND" in stdout


def test_scope_denied_names_assets_read_and_the_license_it_needs() -> None:
    recorded = RecordedTransport([serve("query_accounts", fixture("errors/403-scope.json"))])
    stdout, exit_code = run(["account", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert "code: SCOPE_DENIED" in stdout
    assert 'required_scopes[1]: "Assets:read"' in stdout
    assert "Falcon Discover or Exposure Management" in stdout
    assert "tenant lacks that subscription" in stdout


def test_account_commands_are_refused_before_any_request_when_malformed() -> None:
    recorded = RecordedTransport([])
    _, no_id = run(["account", "show"], recorded, dict(CREDENTIAL_ENV))
    _, ceiling = run(["account", "list", "--limit", "101"], recorded, dict(CREDENTIAL_ENV))
    _, unknown = run(["account", "delete", "x"], recorded, dict(CREDENTIAL_ENV))
    assert (no_id, ceiling, unknown) == (2, 2, 2)
    assert recorded.requests == []
