import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize(
    ("argv", "empty"),
    [
        ([], False),
        ([], True),
        (["detection", "list", "--product", "idp", "--since", "24h", "--limit", "2"], False),
        (["detection", "list", "--product", "idp", "--since", "24h"], True),
        (["detection", "list"], True),
        (["host", "list", "--platform", "windows", "--since", "24h", "--limit", "2"], False),
        (["host", "list", "--platform", "windows", "--since", "24h"], True),
        (["vuln", "list", "--status", "open", "--limit", "2"], False),
        (["vuln", "list", "--status", "open"], True),
        (["auth", "status"], False),
    ],
)
@pytest.mark.parametrize("selection", [[], ["--no-member-cid"], ["--member-cid", "synthetic-selected-child"]])
@pytest.mark.parametrize(
    "context",
    [["--region", "us-2"], ["--region", "https://synthetic-cloud.example", "--allow-unknown-origin"]],
)
def test_discovery_empty_states_and_continuations_preserve_context_once(argv, empty, selection, context) -> None:
    alerts = fixture("alerts/query-identity.json")
    details = fixture("alerts/hydrate-identity.json")
    alert_page = response(200, {**alerts.body, "meta": {"pagination": {"total": 20}}})
    empty_page = response(200, {"resources": []})
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", empty_page if empty else alert_page),
            serve("PostEntitiesAlertsV2", details),
            serve("QueryDevicesByFilter", empty_page if empty else fixture("hosts/query-page.json")),
            serve("PostDeviceDetailsV2", fixture("hosts/details-page.json")),
            serve("combinedQueryVulnerabilities", empty_page if empty else fixture("spotlight/combined-page.json")),
            serve("GetVulnerabilities", fixture("intel/vulnerability-one.json")),
        ],
        oauth=[response(201, fixture("oauth2/token-success.json").body)],
    )
    env = {**CREDENTIAL_ENV, "FALCON_MEMBER_CID": "synthetic-inherited-child"}
    stdout, exit_code = run([*argv, *context, *selection], recorded, env)
    assert exit_code == 0, stdout
    original = recorded.oauth_requests()[0]
    selected = selection != ["--no-member-cid"]
    document = decode(stdout)
    assert sum("Supply the same tenant selection" in item for item in document["help"]) == int(selected)
    assert "synthetic-selected-child" not in stdout
    assert "synthetic-inherited-child" not in stdout
    followed = 0
    for item in document["help"]:
        if not item.startswith("Run `falcon-axi "):
            continue
        tokens = shlex.split(item.split("`", 2)[1])
        assert tokens.count("--region") == 1
        assert tokens[tokens.index("--region") + 1] == context[1]
        assert tokens.count("--allow-unknown-origin") == int("--allow-unknown-origin" in context)
        assert tokens.count("--no-member-cid") == int(not selected)
        assert "--member-cid" not in tokens
        if selection and selection[0] == "--member-cid":
            tokens += selection
        subjects = {
            "<id>": details.body["resources"][0]["composite_id"],
            "<device_id>": "synthetic-device-01",
            "<CVE-ID>": "CVE-2099-0001",
        }
        tokens = [subjects.get(token, token) for token in tokens]
        result, exit_code = run(tokens[1:], recorded, env)
        assert exit_code == 0, result
        latest = recorded.oauth_requests()[-1]
        assert latest.member_cid == original.member_cid
        assert latest.base_url == original.base_url
        assert latest.allow_unknown_origin == original.allow_unknown_origin
        if "--cursor" in tokens:
            operation = {
                "detection": "GetQueriesAlertsV2",
                "host": "QueryDevicesByFilter",
                "vuln": "combinedQueryVulnerabilities",
            }[tokens[1]]
            requests = recorded.operation_requests(operation)
            assert requests[0].query.get("filter") == requests[-1].query.get("filter")
        followed += 1
    assert followed > 0


@pytest.mark.parametrize(
    ("noun", "flag", "value", "empty"),
    [
        ("detection", "filter", "status:'new',status:'in_progress'", False),
        ("detection", "filter", "status:'new',status:'in_progress'", True),
        ("detection", "filter", "device.hostname:'WIN-$backup'", False),
        ("detection", "filter", 'device.hostname:\'WIN "LAB"\'', False),
        ("host", "filter", "status:'normal',status:'contained'", False),
        ("host", "filter", "status:'normal',status:'contained'", True),
        ("host", "hostname", "WIN-*", False),
        ("host", "hostname", "WIN-$backup", False),
        ("host", "hostname", "WIN-$backup", True),
        ("vuln", "filter", "status:'open',status:'closed'", False),
    ],
)
def test_replayed_query_values_survive_shell_parsing_and_reach_the_next_request(noun, flag, value, empty) -> None:
    operation = {
        "detection": "GetQueriesAlertsV2",
        "host": "QueryDevicesByFilter",
        "vuln": "combinedQueryVulnerabilities",
    }[noun]
    page = {
        "detection": fixture("alerts/query-page.json"),
        "host": fixture("hosts/query-page.json"),
        "vuln": fixture("spotlight/combined-page.json"),
    }[noun]
    recorded = RecordedTransport(
        [
            serve(operation, response(200, {"resources": []}) if empty else page),
            serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-page.json")),
            serve("PostDeviceDetailsV2", fixture("hosts/details-page.json")),
        ]
    )
    argv = [noun, "list", f"--{flag}", value, "--since", "24h", "--limit", "2"]
    if noun == "detection":
        argv += ["--product", "idp"]
    stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    help = decode(stdout)["help"]
    suggestion = next(item for item in help if ("widen the window" if empty else "--cursor") in item)
    tokens = shlex.split(suggestion.split("`", 2)[1])
    assert tokens[tokens.index(f"--{flag}") + 1] == value
    stdout, exit_code = run(tokens[1:], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    first, second = recorded.operation_requests(operation)
    expected = first.query["filter"]
    if empty:
        expected = expected.replace("now-24h", "now-7d" if noun == "detection" else "now-30d")
    assert second.query["filter"] == expected
    if not empty:
        if noun == "vuln":
            assert second.query["after"] == "synthetic-after-token-2"
        else:
            assert second.query["offset"] == 2
