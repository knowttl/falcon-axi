import re
from dataclasses import replace

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.render import render
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve

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
    assert re.search(
        r"^scopes: read scopes, plus NGSIEM:write for `search start`, `search stop`, and `identity activity`, "
        r"Identity Protection GraphQL:write for the fixed Identity Protection query commands, "
        r"and MalQuery:write for bounded exact/fuzzy searches \(N4\)$",
        stdout,
        re.MULTILINE,
    )
    assert re.search(r"^rate_limit: 5999 of 6000 requests remaining$", stdout, re.MULTILINE)
    assert SECRET not in stdout
    assert "synthetic-access-token" not in stdout


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


def test_region_autodiscovery_retargets_exactly_once_on_a_308_x_cs_region() -> None:
    """Falcon announces a non-us-1 cloud with 308, X-Cs-Region, and an empty body, not a 201."""
    redirect = fixture("oauth2/token-region-us-2.json")
    recorded = RecordedTransport([], [redirect, TOKEN_SUCCESS])
    stdout, exit_code = run(["auth", "status"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert redirect.status == 308
    assert redirect.body is None
    minted = recorded.oauth_requests()
    assert len(minted) == 2
    assert minted[0].base_url == "https://api.crowdstrike.com"
    assert minted[1].base_url == "https://api.us-2.crowdstrike.com"
    assert "attacker" not in minted[1].base_url
    assert ":443" not in minted[1].base_url
    assert re.search(r"^tenant: us-2 \(re-targeted from us-1\) \(own CID unavailable\)$", stdout, re.MULTILINE)


def test_a_201_with_a_different_known_region_still_retargets_once() -> None:
    observed = replace(TOKEN_SUCCESS, headers={"x-cs-region": "eu-1"})
    recorded = RecordedTransport([], [observed, TOKEN_SUCCESS])
    stdout, exit_code = run(["auth", "status"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert [request.base_url for request in recorded.oauth_requests()] == [
        "https://api.crowdstrike.com",
        "https://api.eu-1.crowdstrike.com",
    ]
    assert "re-targeted from us-1" in stdout


def test_a_308_whose_region_is_unknown_is_region_mismatch_and_is_not_followed() -> None:
    observed = replace(
        fixture("oauth2/token-region-us-2.json"),
        headers={"x-cs-region": "us-gov-2", "location": "https://attacker.example/oauth2/token"},
    )
    recorded = RecordedTransport([], [observed])
    stdout, exit_code = run(["auth", "status"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: REGION_MISMATCH$", stdout, re.MULTILINE)
    assert "us-gov-2" in stdout
    assert len(recorded.oauth_requests()) == 1


def test_a_308_without_a_region_and_a_second_redirect_are_refused() -> None:
    missing = replace(fixture("oauth2/token-region-us-2.json"), headers={"location": "https://attacker.example/oauth2/token"})
    refused, exit_code = run(["auth", "status"], RecordedTransport([], [missing]), dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: ORIGIN_NOT_ALLOWED$", refused, re.MULTILINE)

    second = replace(fixture("oauth2/token-region-us-2.json"), headers={"x-cs-region": "eu-1"})
    recorded = RecordedTransport([], [fixture("oauth2/token-region-us-2.json"), second])
    again, exit_code = run(["auth", "status"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 1
    assert re.search(r"^code: ORIGIN_NOT_ALLOWED$", again, re.MULTILINE)
    assert [request.base_url for request in recorded.oauth_requests()] == [
        "https://api.crowdstrike.com",
        "https://api.us-2.crowdstrike.com",
    ]


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
            "nested": {"client_secret": SECRET, "Customer_ID": "synthetic-customer-cid"},
            "records": [{"customer_id": "synthetic-customer-cid"}],
        }
    )
    for secret in ("synthetic-access-token", "synthetic-client-id", SECRET, "synthetic-child-cid", "synthetic-token"):
        assert secret not in rendered, f"render leaked {secret}"
    assert "synthetic-customer-cid" not in rendered
    assert len(re.findall(r"\[redacted\]", rendered)) == 9


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("#repo.cid=synthetic-tenant | head(5)", "#repo.cid=[redacted] | head(5)"),
        ('cid="synthetic tenant" | head(5)', "cid=[redacted] | head(5)"),
        ('"member_cid": "synthetic tenant"', '"member_cid": [redacted]'),
        ("client_id=synthetic-id", "client_id=[redacted]"),
        ("client_secret=synthetic-secret", "client_secret=[redacted]"),
        ("access_token=synthetic-access", "access_token=[redacted]"),
        ('Authorization="Bearer synthetic-token"', "Authorization=[redacted]"),
        ("Authorization: Bearer synthetic-token", "Authorization: [redacted]"),
        ("token=eyJzeW50aGV0aWM.payload.signature", "token=[redacted]"),
        ("Bearer eyJzeW50aGV0aWM.payload.signature", "Bearer [redacted]"),
        ("repo=services/OR/logs | head(5)", "repo=services/OR/logs | head(5)"),
    ],
)
def test_sensitive_text_is_redacted_in_data_and_help(text: str, expected: str) -> None:
    assert decode(render({"message": text}, [text])) == {"message": expected, "help": [expected]}
