"""Token mint and session (docs/design/v1.md §5.1, §5.4, §6.4)."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.origin import REGIONS, region_of
from falcon_axi.transport.types import FalconResponse, OAuthTokenArgs, Transport


@dataclass(frozen=True)
class RateLimit:
    limit: int | None = None
    remaining: int | None = None


@dataclass(frozen=True)
class Session:
    token: str
    base_url: str
    rate_limit: RateLimit
    allow_unknown_origin: bool = False
    region: str | None = None
    retargeted_from: str | None = None
    member_cid: str | None = None


def _number(headers: Mapping[str, str], name: str) -> int | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):
        return None
    return int(parsed)


def rate_limit_of(response: FalconResponse) -> RateLimit:
    return RateLimit(
        limit=_number(response.headers, "x-ratelimit-limit"),
        remaining=_number(response.headers, "x-ratelimit-remaining"),
    )


def _token_of(response: FalconResponse) -> str:
    body: Any = response.body
    token = body.get("access_token") if isinstance(body, Mapping) else None
    if not isinstance(token, str) or not token:
        raise CliError(
            "UPSTREAM_ERROR",
            "the Falcon token response carried no access token",
            ["Retry shortly", "Run `falcon-axi auth status` to re-check the credential"],
        )
    return token


def _token_failure(response: FalconResponse, member_cid: str | None) -> CliError:
    if response.status == 401:
        return CliError(
            "AUTH_FAILED",
            "the Falcon credential was rejected",
            ["The client ID or secret is wrong, or the API client was revoked"],
        )
    if response.status == 403:
        if member_cid:
            return CliError(
                "TENANT_DENIED",
                "the selected member CID was refused for this credential",
                [
                    "Verify this is a valid child CID in the Falcon console and not the parent CID itself",
                    "Or retry with `--no-member-cid` to authenticate as the credential's own CID",
                ],
            )
        return CliError(
            "AUTH_FAILED",
            "the Falcon credential was refused",
            [
                "The API client has no scopes granted, or is disabled",
                "Grant `Alerts:read` (read only) in the Falcon console under Support and resources > API clients and keys",
            ],
        )
    return translate_falcon_error(response, "GetQueriesAlertsV2", "the Falcon token endpoint")


def _redirect_refused() -> CliError:
    """A token redirect is never followed, and Location is never read (§6.3, §6.4)."""
    return CliError(
        "ORIGIN_NOT_ALLOWED",
        "the Falcon endpoint answered with a redirect and no credential was replayed",
        ["Supply a verified Falcon base URL with `--region <url>`"],
        {"invalid_component": "redirect"},
    )


def _region_mismatch(observed: str) -> CliError:
    return CliError(
        "REGION_MISMATCH",
        f"this credential belongs to Falcon region {observed}",
        [
            f"falcon-axi has no verified base URL for {observed}",
            "Supply a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
        ],
        {"observed_region": observed},
    )


def _verified_host(observed: str) -> str:
    target = REGIONS.get(observed)
    if not target:
        raise _region_mismatch(observed)
    return target


def authenticate(
    transport: Transport,
    credential: Credential,
    base_url: str,
    member_cid: str | None = None,
    allow_unknown_origin: bool = False,
) -> Session:
    """Mints a bearer token for this invocation (§5.1, §5.4).

    The token is never persisted. Region autodiscovery re-targets at most once: a 3xx from the
    token endpoint is not followed, and a known `X-Cs-Region` selects that region's verified host
    for one re-mint. Location is never read (§6.4).
    """

    def mint(target: str) -> FalconResponse:
        return transport.request_oauth_token(
            OAuthTokenArgs(
                base_url=target,
                client_id=credential.client_id,
                client_secret=credential.client_secret,
                member_cid=member_cid,
                allow_unknown_origin=allow_unknown_origin,
            )
        )

    response = mint(base_url)
    retargeted_from: str | None = None
    current = region_of(base_url)
    if 300 <= response.status < 400:
        observed = response.headers.get("x-cs-region")
        if not observed:
            raise _redirect_refused()
        target = _verified_host(observed)
        if target == base_url:
            raise _redirect_refused()
        retargeted_from = current
        base_url = target
        response = mint(base_url)
        if 300 <= response.status < 400:
            raise _redirect_refused()
    elif response.status in (200, 201):
        observed = response.headers.get("x-cs-region")
        if observed and current and observed != current:
            target = _verified_host(observed)
            retargeted_from = current
            base_url = target
            response = mint(base_url)
            if 300 <= response.status < 400:
                raise _redirect_refused()
    if response.status not in (200, 201):
        raise _token_failure(response, member_cid)

    return Session(
        token=_token_of(response),
        base_url=base_url,
        region=region_of(base_url),
        retargeted_from=retargeted_from,
        member_cid=member_cid,
        allow_unknown_origin=allow_unknown_origin,
        rate_limit=rate_limit_of(response),
    )
