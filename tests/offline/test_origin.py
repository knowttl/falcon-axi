import pytest

from falcon_axi.core import CliError
from falcon_axi.origin import REGIONS, assert_trusted_origin, region_of, resolve_base_url

SECRET = "synthetic-client-secret"


def _rejection(url: str, allow_unknown: bool = False) -> CliError:
    with pytest.raises(CliError) as error:
        assert_trusted_origin(url, allow_unknown)
    return error.value


def test_every_documented_region_is_a_trusted_origin() -> None:
    for name, url in REGIONS.items():
        assert assert_trusted_origin(url) == url
        assert region_of(url) == name


def test_a_crowdstrike_subdomain_is_trusted_and_a_lookalike_host_is_not() -> None:
    assert assert_trusted_origin("https://api.us-3.crowdstrike.com") == "https://api.us-3.crowdstrike.com"
    assert _rejection("https://api.crowdstrike.com.example").details["invalid_component"] == "host"


def test_each_violated_component_is_reported_by_name_and_never_with_the_url() -> None:
    cases = [
        ("http://api.crowdstrike.com", "scheme"),
        (f"https://user:{SECRET}@api.crowdstrike.com", "userinfo"),
        ("https://api.crowdstrike.com:8443", "port"),
        ("https://api.crowdstrike.com/internal", "path"),
        (f"https://api.crowdstrike.com/?probe={SECRET}", "query"),
        ("https://api.crowdstrike.com/#fragment", "fragment"),
        ("not-a-url", "scheme"),
    ]
    for url, component in cases:
        error = _rejection(url)
        assert error.code == "ORIGIN_NOT_ALLOWED"
        assert error.details["invalid_component"] == component
        rendered = "\n".join([error.message, *error.help])
        assert SECRET not in rendered, f"{component} rendering leaked a value"
        assert "8443" not in rendered and "internal" not in rendered


def test_allow_unknown_origin_relaxes_only_the_host_allowlist() -> None:
    assert assert_trusted_origin("https://api.unknown-cloud.example", True) == "https://api.unknown-cloud.example"
    assert _rejection("http://api.unknown-cloud.example", True).details["invalid_component"] == "scheme"
    assert _rejection("https://api.unknown-cloud.example/path", True).details["invalid_component"] == "path"


def test_region_precedence_is_flag_then_environment_then_the_default_cloud() -> None:
    assert resolve_base_url(region="eu-1", env_base_url="https://api.us-2.crowdstrike.com") == REGIONS["eu-1"]
    assert resolve_base_url(env_base_url="https://api.us-2.crowdstrike.com") == "https://api.us-2.crowdstrike.com"
    assert resolve_base_url() == REGIONS["us-1"]
    assert resolve_base_url(region="https://api.laggar.gcw.crowdstrike.com") == "https://api.laggar.gcw.crowdstrike.com"
    with pytest.raises(CliError) as error:
        resolve_base_url(region="us-9")
    assert error.value.code == "VALIDATION_ERROR"
