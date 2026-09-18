"""The one module allowed to reach the network, exercised against a `requests` mock.

These assertions pin decision D2 (docs/design/v1-python.md §3.3): falcon-axi mints the OAuth token
itself with redirects refused, and falconpy only ever executes an already-permitted read operation.
"""

import pytest
import requests
import requests_mock

from falcon_axi.core import CliError
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.harness import mint_permit, send_permitted_request
from falcon_axi.transport.types import OAuthTokenArgs, PreparedOperation, PreparedToken, RequestArgs

TOKEN_URL = "https://api.crowdstrike.com/oauth2/token"
QUERY_URL = "https://api.crowdstrike.com/alerts/queries/alerts/v2"
HYDRATE_URL = "https://api.crowdstrike.com/alerts/entities/alerts/v2"
QUERYJOBS_URL = "https://api.crowdstrike.com/humio/api/v1/repositories/search-all/queryjobs"
JSON = {"Content-Type": "application/json"}


def test_the_query_step_issues_the_registered_get_with_its_parameters() -> None:
    with requests_mock.Mocker() as mock:
        mock.get(QUERY_URL, json={"resources": ["ldt:a:1"]}, headers={**JSON, "X-RateLimit-Limit": "6000"})
        response = HttpTransport().request(
            "GetQueriesAlertsV2",
            RequestArgs(base_url="https://api.crowdstrike.com", token="synthetic-token", query={"limit": 2, "offset": 0}),
        )
    request = mock.request_history[0]
    assert request.method == "GET"
    assert request.path == "/alerts/queries/alerts/v2"
    assert request.qs == {"limit": ["2"], "offset": ["0"]}
    assert request.headers["Authorization"] == "Bearer synthetic-token"
    assert request.headers["User-Agent"].startswith("falcon-axi/")
    assert response.status == 200
    assert response.headers["x-ratelimit-limit"] == "6000"
    assert response.body["resources"] == ["ldt:a:1"]


def test_the_hydrate_step_issues_the_registered_post_with_its_body() -> None:
    with requests_mock.Mocker() as mock:
        mock.post(HYDRATE_URL, json={"resources": []}, headers=JSON)
        HttpTransport().request(
            "PostEntitiesAlertsV2",
            RequestArgs(base_url="https://api.crowdstrike.com", token="synthetic-token", body={"composite_ids": ["ldt:a:1"]}),
        )
    request = mock.request_history[0]
    assert request.method == "POST"
    assert request.path == "/alerts/entities/alerts/v2"
    assert request.json() == {"composite_ids": ["ldt:a:1"]}


def test_the_search_lifecycle_routes_interpolate_their_path_variables() -> None:
    """The three NG-SIEM routes are the only ones with `{name}` variables (§3.3 property 7).

    `GetSearchStatusV1` also pins the falconpy quirk the sink works around: its uber path-variable
    map lists `search_id` beside `id` and reads every name it lists while interpolating.
    """
    with requests_mock.Mocker() as mock:
        mock.post(QUERYJOBS_URL, json={"id": "synthetic-job"}, headers=JSON)
        mock.get(f"{QUERYJOBS_URL}/synthetic-job", json={"done": True, "events": []}, headers=JSON)
        mock.delete(f"{QUERYJOBS_URL}/synthetic-job", status_code=200, headers=JSON)
        transport = HttpTransport()
        transport.request(
            "StartSearchV1",
            RequestArgs(
                base_url="https://api.crowdstrike.com",
                token="synthetic-token",
                path_params={"repository": "search-all"},
                body={"queryString": "#event_simpleName=ProcessRollup2", "start": 1, "end": 2},
            ),
        )
        for id in ("GetSearchStatusV1", "StopSearchV1"):
            transport.request(
                id,  # type: ignore[arg-type]
                RequestArgs(
                    base_url="https://api.crowdstrike.com",
                    token="synthetic-token",
                    path_params={"repository": "search-all", "id": "synthetic-job"},
                ),
            )
    started, polled, stopped = mock.request_history
    assert (started.method, started.path) == ("POST", "/humio/api/v1/repositories/search-all/queryjobs")
    assert started.json()["queryString"] == "#event_simpleName=ProcessRollup2"
    assert (polled.method, polled.path) == ("GET", "/humio/api/v1/repositories/search-all/queryjobs/synthetic-job")
    assert (stopped.method, stopped.path) == ("DELETE", "/humio/api/v1/repositories/search-all/queryjobs/synthetic-job")
    # The path variables are interpolated, never left behind as query string parameters.
    assert all(not request.qs for request in mock.request_history)


def test_the_token_mint_is_falcon_axis_own_and_refuses_to_follow_a_redirect() -> None:
    with requests_mock.Mocker() as mock:
        mock.post(TOKEN_URL, json={"access_token": "synthetic-access-token"}, headers={**JSON, "X-Cs-Region": "us-1"})
        response = HttpTransport().request_oauth_token(
            OAuthTokenArgs(
                base_url="https://api.crowdstrike.com",
                client_id="synthetic-client-id",
                client_secret="synthetic-client-secret",
                member_cid="synthetic-child-cid",
            )
        )
    request = mock.request_history[0]
    assert request.method == "POST"
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert "client_secret=synthetic-client-secret" in request.text
    assert "member_cid=synthetic-child-cid" in request.text
    assert response.status == 200
    assert response.headers["x-cs-region"] == "us-1"


@pytest.mark.parametrize("status", [301, 307, 308])
def test_a_redirect_on_the_token_path_is_refused_without_replaying_the_credential(status: int) -> None:
    with requests_mock.Mocker() as mock:
        mock.post(TOKEN_URL, status_code=status, headers={"Location": "https://attacker.example/oauth2/token"})
        with pytest.raises(CliError) as error:
            HttpTransport().request_oauth_token(
                OAuthTokenArgs(
                    base_url="https://api.crowdstrike.com",
                    client_id="synthetic-client-id",
                    client_secret="synthetic-client-secret",
                )
            )
    assert error.value.code == "ORIGIN_NOT_ALLOWED"
    assert error.value.details["invalid_component"] == "redirect"
    assert len(mock.request_history) == 1


def test_an_unreachable_endpoint_and_an_untrusted_certificate_are_named_apart() -> None:
    with requests_mock.Mocker() as mock:
        mock.post(TOKEN_URL, exc=requests.exceptions.ConnectionError("refused"))
        with pytest.raises(CliError) as unreachable:
            send_permitted_request(
                PreparedToken(origin="https://api.crowdstrike.com", form={"client_id": "x", "client_secret": "y"}),
                mint_permit(),
            )
    assert unreachable.value.code == "NETWORK_UNREACHABLE"

    with requests_mock.Mocker() as mock:
        mock.get(QUERY_URL, exc=requests.exceptions.SSLError("bad certificate"))
        with pytest.raises(CliError) as untrusted:
            send_permitted_request(
                PreparedOperation(
                    operation_id="GetQueriesAlertsV2",
                    origin="https://api.crowdstrike.com",
                    token="synthetic-token",
                    query={},
                ),
                mint_permit(),
            )
    assert untrusted.value.code == "TLS_UNTRUSTED"


def test_an_unregistered_operation_never_reaches_falconpy() -> None:
    with requests_mock.Mocker() as mock:
        with pytest.raises(CliError) as error:
            HttpTransport().request(
                "PostEntitiesAlertsActionV1",  # type: ignore[arg-type]
                RequestArgs(base_url="https://api.crowdstrike.com", token="synthetic-token"),
            )
    assert error.value.code == "READ_ONLY_VIOLATION"
    assert mock.request_history == []


def test_a_redirect_on_an_operation_is_refused_rather_than_followed() -> None:
    with requests_mock.Mocker() as mock:
        mock.get(QUERY_URL, status_code=302, headers={"Location": "https://attacker.example/alerts"})
        with pytest.raises(CliError) as error:
            HttpTransport().request(
                "GetQueriesAlertsV2",
                RequestArgs(base_url="https://api.crowdstrike.com", token="synthetic-token", query={"limit": 1}),
            )
    assert error.value.code == "ORIGIN_NOT_ALLOWED"
    assert error.value.details["invalid_component"] == "redirect"
    assert len(mock.request_history) == 1
