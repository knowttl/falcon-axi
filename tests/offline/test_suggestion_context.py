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
        (["identity", "list", "--name", "Admin*", "--limit", "2"], False),
        (["identity", "list", "--name", "Admin*"], True),
        (["identity", "show", "00000000-0000-4000-8000-000000000001"], False),
        (["identity", "timeline", "00000000-0000-4000-8000-000000000001", "--since", "24h"], False),
        (["identity", "timeline", "00000000-0000-4000-8000-000000000001", "--since", "24h"], True),
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
            serve(
                "api_preempt_proxy_post_graphql",
                lambda args: fixture(
                    {
                        "identity_show": "identity/entity-detail.json",
                        "identity_timeline": "identity/timeline-empty.json" if empty else "identity/timeline-page.json",
                        "identity_list": "identity/entities-empty.json" if empty else "identity/entities-page.json",
                    }[args.document]
                ),
            ),
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
        tokens = shlex.split(item.partition("`")[2].rpartition("`")[0])
        assert tokens.count("--region") == 1
        assert tokens[tokens.index("--region") + 1] == context[1]
        assert tokens.count("--allow-unknown-origin") == int("--allow-unknown-origin" in context)
        assert tokens.count("--no-member-cid") == int(not selected)
        assert "--member-cid" not in tokens
        if selection and selection[0] == "--member-cid":
            tokens += selection
        subjects = {
            "<id>": (
                "00000000-0000-4000-8000-000000000001"
                if tokens[1] == "identity"
                else details.body["resources"][0]["composite_id"]
            ),
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
                "identity": "api_preempt_proxy_post_graphql",
            }[tokens[1]]
            requests = recorded.operation_requests(operation)
            if tokens[1] == "identity":
                first = requests[0].variables
                latest = requests[-1].variables
                assert {key: value for key, value in latest.items() if key != "after"} == first
            else:
                assert requests[0].query.get("filter") == requests[-1].query.get("filter")
        followed += 1
    assert followed > 0


@pytest.mark.parametrize(
    ("noun", "flag", "value", "empty"),
    [
        ("detection", "filter", "status:'new',status:'in_progress'", False),
        ("detection", "filter", "status:'new',status:'in_progress'", True),
        ("detection", "filter", "device.hostname:'WIN-$backup'", False),
        ("detection", "filter", "device.hostname:'WIN \"LAB\"'", False),
        ("host", "filter", "status:'normal',status:'contained'", False),
        ("host", "filter", "status:'normal',status:'contained'", True),
        ("host", "hostname", "WIN-*", False),
        ("host", "hostname", "WIN-$backup", False),
        ("host", "hostname", "WIN-$backup", True),
        ("vuln", "filter", "status:'open',status:'closed'", False),
        ("detection", "filter", "device.hostname:'lab`x'", False),
        ("detection", "filter", "device.hostname:'lab`x'", True),
        ("detection", "filter", "device.hostname:'lab`x'\n", False),
        ("host", "filter", "hostname:'lab`x'", False),
        ("host", "filter", "hostname:'lab`x'", True),
        ("host", "hostname", "lab`*", False),
        ("host", "hostname", "lab`*", True),
        ("host", "hostname", "lab`x`*", False),
        ("vuln", "filter", "host_info.hostname:'lab`x'", False),
    ],
)
@pytest.mark.parametrize(
    "context",
    [
        [],
        ["--region", "us-2", "--no-member-cid"],
        ["--region", "https://synthetic-cloud.example", "--allow-unknown-origin", "--no-member-cid"],
    ],
)
def test_replayed_query_values_survive_shell_parsing_and_reach_the_next_request(noun, flag, value, empty, context) -> None:
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
        ],
        oauth=[response(201, fixture("oauth2/token-success.json").body)],
    )
    argv = [noun, "list", f"--{flag}", value, "--since", "24h", "--limit", "2", *context]
    if noun == "detection":
        argv += ["--product", "idp"]
    stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    help = decode(stdout)["help"]
    suggestion = next(item for item in help if ("widen the window" if empty else "--cursor") in item)
    tokens = shlex.split(suggestion.partition("`")[2].rpartition("`")[0])
    assert tokens[tokens.index(f"--{flag}") + 1] == value
    if context:
        assert tokens[-len(context) :] == context
        assert tokens.count("--region") == 1
        assert tokens.count("--no-member-cid") == 1
    stdout, exit_code = run(tokens[1:], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    first, second = recorded.operation_requests(operation)
    expected = first.query["filter"]
    if empty:
        expected = expected.replace("now-24h", "now-7d" if noun == "detection" else "now-30d")
    assert second.query["filter"] == expected
    original, latest = recorded.oauth_requests()
    assert latest.base_url == original.base_url
    assert latest.member_cid == original.member_cid
    assert latest.allow_unknown_origin == original.allow_unknown_origin
    if not empty:
        if noun == "vuln":
            assert second.query["after"] == "synthetic-after-token-2"
        else:
            assert second.query["offset"] == 2
