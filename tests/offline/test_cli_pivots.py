import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import replace

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve

TARGET_FIXTURES = [
    ("query_accounts", "discover/accounts-query-page.json"),
    ("get_accounts", "discover/accounts-details-page.json"),
    ("QueryDeviceLoginHistoryV2", "hosts/login-history.json"),
    ("QueryDevicesByFilter", "hosts/query-page.json"),
    ("PostDeviceDetailsV2", "hosts/details-page.json"),
    ("GetQueriesAlertsV2", "alerts/query-page.json"),
    ("PostEntitiesAlertsV2", "alerts/hydrate-page.json"),
    ("combinedQueryVulnerabilities", "spotlight/combined-page.json"),
    ("StartSearchV1", "ngsiem/start-search.json"),
    ("GetSearchStatusV1", "ngsiem/search-status-running.json"),
    ("StopSearchV1", "ngsiem/stop-search.json"),
]
SOURCE_FILTER = "username:'synthetic-source-only'"


@pytest.mark.parametrize(
    ("argv", "overrides", "source_code"),
    [
        (["account", "list", "--filter", SOURCE_FILTER], [], 0),
        (["account", "list", "--filter", SOURCE_FILTER], [("query_accounts", "discover/accounts-query-empty.json")], 0),
        (["account", "show", "synthetic-account-01"], [("get_accounts", "discover/accounts-details-one.json")], 0),
        (["account", "show", "synthetic-account-99"], [("get_accounts", "discover/accounts-details-empty.json")], 1),
        (["host", "logins", "synthetic-device-01", "--since", "24h", "--limit", "2"], [], 0),
        (["host", "logins", "synthetic-device-01"], [("QueryDeviceLoginHistoryV2", "hosts/login-history-empty.json")], 0),
        (
            ["host", "logins", "synthetic-device-99"],
            [("QueryDeviceLoginHistoryV2", "hosts/login-history-invalid-id.json")],
            1,
        ),
        (["host", "list"], [], 0),
        (["host", "show", "synthetic-device-01"], [], 0),
        (["detection", "list"], [], 0),
        (["vuln", "list", "--status", "open"], [], 0),
        (["search", "start", "--query", "#synthetic_event | head(2)"], [], 0),
        (["search", "status", "synthetic-job"], [], 0),
        (["auth", "status"], [], 0),
        ([], [], 0),
    ],
)
@pytest.mark.parametrize("explicit_member", [False, True])
def test_emitted_pivots_preserve_global_context_without_copying_source_filters(
    argv: list[str],
    overrides: list[tuple[str, str]],
    source_code: int,
    explicit_member: bool,
) -> None:
    env = {**CREDENTIAL_ENV, "FALCON_MEMBER_CID": "synthetic-inherited-child"}
    selected = "synthetic-selected-child" if explicit_member else None
    global_flags = (
        ["--region", "eu-1", "--member-cid", str(selected)]
        if explicit_member
        else ["--region", "https://synthetic.invalid", "--allow-unknown-origin", "--no-member-cid"]
    )
    recorded = RecordedTransport(
        [serve(op, fixture(path)) for op, path in [*overrides, *TARGET_FIXTURES]],
        [replace(fixture("oauth2/token-success.json"), headers={})],
    )
    stdout, code = run([*argv, *global_flags], recorded, env)
    assert code == source_code
    document = decode(stdout)
    assert "synthetic-inherited-child" not in stdout
    assert "synthetic-selected-child" not in stdout
    if explicit_member:
        assert "Supply the same tenant selection used for this invocation when continuing" in document["help"]
    suggestions = [
        item for item in document["help"]
        if item.startswith("Run `falcon-axi ") and not item.endswith("for the next page")
    ]
    assert suggestions
    target_env = {**env, **({"FALCON_MEMBER_CID": str(selected)} if explicit_member else {})}
    program = (
        "import json, sys; from dataclasses import replace; from falcon_axi.cli import run; "
        "from tests.support.recorded import RecordedTransport, fixture, serve; "
        f"recorded = RecordedTransport([serve(op, fixture(path)) for op, path in {TARGET_FIXTURES!r}], "
        "[replace(fixture('oauth2/token-success.json'), headers={})]); "
        f"stdout, code = run(sys.argv[1:], recorded, {target_env!r}); "
        "print(json.dumps([stdout, code, "
        "[[r.base_url, r.member_cid, r.allow_unknown_origin] for r in recorded.oauth_requests()]]))"
    )
    shell = shutil.which("bash")
    assert shell
    for suggestion in suggestions:
        command = suggestion.partition("`")[2].rpartition("`")[0]
        command = command.replace("<device_id>", "synthetic-device-01").replace("<user_name>", "synthetic-admin")
        command = command.replace("<name>", "WIN-DC-01")
        id = "synthetic-account-01" if "account show" in command else "ldt:synthetic-agent-01:1001"
        command = command.replace("<id>", id)
        tokens = shlex.split(command)
        assert SOURCE_FILTER not in tokens
        assert tokens.count("--region") == 1
        assert "--member-cid" not in tokens
        result = subprocess.run(  # noqa: S603
            [shell, "-c", f"falcon-axi() {{ {shlex.quote(sys.executable)} -c {shlex.quote(program)} \"$@\"; }}; {command}"],
            env={**os.environ, **target_env},
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        followed, exit_code, authentication = json.loads(result.stdout)
        assert exit_code == 0, followed
        expected = recorded.oauth_requests()[0]
        expected_authentication = [] if tokens[1] == "scopes" else [[expected.base_url, selected, expected.allow_unknown_origin]]
        assert authentication == expected_authentication
