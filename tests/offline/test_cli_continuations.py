import json
import os
import shlex
import shutil
import subprocess
import sys

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve


@pytest.mark.parametrize(
    ("noun", "operation", "fixtures", "filter", "extra_flags", "position"),
    [
        (
            "account",
            "query_accounts",
            [
                ("query_accounts", "discover/accounts-query-page.json"),
                ("get_accounts", "discover/accounts-details-page.json"),
            ],
            "admin_privileges:'Yes'",
            [],
            2,
        ),
        (
            "detection",
            "GetQueriesAlertsV2",
            [
                ("GetQueriesAlertsV2", "alerts/query-page.json"),
                ("PostEntitiesAlertsV2", "alerts/hydrate-page.json"),
            ],
            "device.hostname:'synthetic $USER \"host\" \\ name'",
            [],
            2,
        ),
        (
            "host",
            "QueryDevicesByFilter",
            [
                ("QueryDevicesByFilter", "hosts/query-page.json"),
                ("PostDeviceDetailsV2", "hosts/details-page.json"),
            ],
            "hostname:'WIN-*'",
            ["--hostname", "WIN-*"],
            2,
        ),
        (
            "vuln",
            "combinedQueryVulnerabilities",
            [("combinedQueryVulnerabilities", "spotlight/combined-page.json")],
            "status:'open'",
            ["--fields", "status"],
            "synthetic-after-token-2",
        ),
    ],
)
def test_emitted_continuations_execute_with_the_same_filter_and_tenant_context(
    noun: str,
    operation: str,
    fixtures: list[tuple[str, str]],
    filter: str,
    extra_flags: list[str],
    position: int | str,
) -> None:
    env = {**CREDENTIAL_ENV, "FALCON_MEMBER_CID": "synthetic-child"}
    recorded = RecordedTransport([serve(op, fixture(path)) for op, path in fixtures])
    stdout, exit_code = run(
        [noun, "list", "--filter", filter, "--limit", "2", "--no-member-cid", *extra_flags], recorded, env
    )
    assert exit_code == 0
    suggestion = next(item for item in decode(stdout)["help"] if item.endswith("for the next page"))
    command = suggestion.removeprefix("Run `").removesuffix("` for the next page")
    program = (
        "import json, sys; from falcon_axi.cli import run; "
        "from tests.support.recorded import RecordedTransport, fixture, serve; "
        f"recorded = RecordedTransport([serve(op, fixture(path)) for op, path in {fixtures!r}]); "
        f"stdout, code = run(sys.argv[1:], recorded, {env!r}); "
        f"print(json.dumps([stdout, code, [dict(r.query) for r in recorded.operation_requests({operation!r})], "
        "[r.member_cid for r in recorded.oauth_requests()]]))"
    )
    shell = shutil.which("bash")
    assert shell
    result = subprocess.run(  # noqa: S603
        [shell, "-c", f"falcon-axi() {{ {shlex.quote(sys.executable)} -c {shlex.quote(program)} \"$@\"; }}; {command}"],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    followed, code, queries, tenants = json.loads(result.stdout)
    assert code == 0, followed
    expected = json.loads(json.dumps(dict(recorded.operation_requests(operation)[0].query)))
    expected["offset" if isinstance(position, int) else "after"] = position
    assert queries == [expected]
    assert tenants == [None]
    assert "synthetic-child" not in stdout
