"""Regions and trusted origins (docs/design/v1.md §6)."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal
from urllib.parse import urlsplit

from falcon_axi.core import CliError

#: The verified Falcon clouds (§6.1). Not necessarily the complete set (§17.3).
REGIONS: Mapping[str, str] = MappingProxyType(
    {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    }
)

DEFAULT_REGION = "us-1"

TRUSTED_HOSTS = frozenset(urlsplit(url).netloc for url in REGIONS.values())
TRUSTED_PARENTS = ("crowdstrike.com", "gcw.crowdstrike.com")

InvalidComponent = Literal["scheme", "userinfo", "port", "path", "query", "fragment", "host", "redirect"]


def _refuse(component: InvalidComponent) -> CliError:
    """Refuses an untrusted destination before any credential or token is sent (§6.3).

    The rejected URL and every component value stay out of the message, because an arbitrary query
    key can carry a secret that key-based redaction would not recognize (§5.5).
    """
    return CliError(
        "ORIGIN_NOT_ALLOWED",
        "the resolved Falcon base URL is not a trusted destination",
        [
            f"Use a documented region with `--region` ({' '.join(REGIONS)})",
            "Allowed hosts are the documented Falcon clouds and subdomains of crowdstrike.com or gcw.crowdstrike.com",
            "Pass `--allow-unknown-origin` in the same invocation to reach a deliberately selected unknown Falcon cloud",
        ],
        {"invalid_component": component},
    )


def _host_allowed(host: str) -> bool:
    if host in TRUSTED_HOSTS:
        return True
    return any(host == parent or host.endswith(f".{parent}") for parent in TRUSTED_PARENTS)


def assert_trusted_origin(base_url: str, allow_unknown_origin: bool = False) -> str:
    """Validates a base URL and returns its canonical origin.

    `allow_unknown_origin` relaxes only the host allowlist; every other rule still applies (§6.3).
    """
    try:
        url = urlsplit(base_url)
        port = url.port
    except ValueError as error:
        raise _refuse("scheme") from error
    if url.scheme != "https" or not url.netloc:
        raise _refuse("scheme")
    if url.username or url.password:
        raise _refuse("userinfo")
    if port is not None:
        raise _refuse("port")
    if url.path not in ("", "/"):
        raise _refuse("path")
    if url.query:
        raise _refuse("query")
    if url.fragment:
        raise _refuse("fragment")
    host = (url.hostname or "").lower()
    if not host:
        raise _refuse("host")
    if not allow_unknown_origin and not _host_allowed(host):
        raise _refuse("host")
    return f"https://{host}"


def region_of(base_url: str) -> str | None:
    """The short name of a base URL, when it is one of the verified clouds."""
    for name, url in REGIONS.items():
        if url == base_url:
            return name
    return None


def resolve_base_url(region: str | None = None, env_base_url: str | None = None) -> str:
    """Region precedence: `--region`, then FALCON_BASE_URL, then the default cloud (§6.2).

    Profile configuration is not implemented in stage 1; see README.
    """
    if region is not None:
        known = REGIONS.get(region)
        if known:
            return known
        if "://" in region:
            return region
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown region {region}",
            [
                f"valid regions: {', '.join(REGIONS)}",
                "Or pass a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
            ],
        )
    if env_base_url:
        return env_base_url
    return REGIONS[DEFAULT_REGION]
