"""AXI profiles and SecretRefs, resolved independently for every invocation."""

import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

from falcon_axi.core import CliError
from falcon_axi.private_file import read_private_file
from falcon_axi.redaction import register_secret

CredentialChannel = Literal["environment", "file"]
PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
PROFILE_FIELDS = frozenset({"region", "memberCid", "clientId", "clientSecret"})
ALIASES = {
    "FALCON_CLIENT_ID": "FALCON_AXI_CLIENT_ID",
    "FALCON_CLIENT_SECRET": "FALCON_AXI_CLIENT_SECRET",
    "FALCON_MEMBER_CID": "FALCON_AXI_MEMBER_CID",
    "FALCON_BASE_URL": "FALCON_AXI_BASE_URL",
    "FALCON_PROXY_URL": "FALCON_AXI_PROXY_URL",
}


@dataclass(frozen=True)
class Credential:
    client_id: str
    client_secret: str
    channel: CredentialChannel
    path: str | None = None
    profile: str = "env"
    region: str | None = None
    member_cid: str | None = None
    secret_source: str = "env:FALCON_AXI_CLIENT_SECRET"  # noqa: S105


def normalized_environment(env: Mapping[str, str]) -> dict[str, str]:
    values = dict(env)
    for old, new in ALIASES.items():
        if old in values:
            sys.stderr.write(f"{old} is deprecated; use {new}\n")
            values.setdefault(new, values[old])
    return values


def _source_name(name: str, env: Mapping[str, str]) -> str:
    if name not in env:
        for old, new in ALIASES.items():
            if name == new and old in env:
                return old
    return name


def tool_directory(kind: Literal["config", "state"], env: Mapping[str, str], platform: str | None = None) -> Path:
    windows = (os.name if platform is None else platform) == "nt"
    if windows:
        variable = "APPDATA" if kind == "config" else "LOCALAPPDATA"
        fallback = Path.home() / "AppData" / ("Roaming" if kind == "config" else "Local")
        root = Path(env[variable]) if env.get(variable) else fallback
    else:
        configured = env.get(f"XDG_{kind.upper()}_HOME", "")
        root = (
            Path(configured)
            if Path(configured).is_absolute()
            else Path.home() / (".config" if kind == "config" else ".local/state")
        )
    return root / "falcon-axi"


def config_path(env: Mapping[str, str] | None = None, flag: str | None = None) -> str:
    values = os.environ if env is None else env
    return flag or values.get("FALCON_AXI_CONFIG") or str(tool_directory("config", values) / "config.json")


def write_log_path(env: Mapping[str, str]) -> str:
    return env.get("FALCON_AXI_WRITE_LOG") or str(tool_directory("state", env) / "writes.log")


def read_only(env: Mapping[str, str]) -> bool:
    value = env.get("FALCON_AXI_READ_ONLY", "false").lower()
    if value not in ("true", "false", "1", "0"):
        raise CliError("CONFIG_INVALID", "FALCON_AXI_READ_ONLY must be 1, true, 0 or false")
    return value in ("true", "1")


def setup_help(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    return (
        "Set FALCON_AXI_CLIENT_ID and FALCON_AXI_CLIENT_SECRET in the environment",
        f"Or configure a profile with a clientSecret SecretRef in {config_path(env)}",
        "Provision an API client with read scopes; only `search start`, `search stop`, and `identity activity` "
        "need NGSIEM:write",
    )


def _invalid(message: str) -> CliError:
    return CliError("CONFIG_INVALID", message)


def _validate_ref(ref: Any, platform: str | None = None) -> None:
    if not isinstance(ref, dict) or len(ref) != 1:
        raise _invalid("clientSecret must be a SecretRef, never an inline secret")
    if "env" in ref and isinstance(ref["env"], str) and ENV_NAME.fullmatch(ref["env"]):
        return
    if "file" in ref and isinstance(ref["file"], str):
        path = ref["file"]
        if (os.name if platform is None else platform) == "nt":
            parsed = PureWindowsPath(path)
            if parsed.is_absolute() and re.fullmatch(r"[A-Za-z]:", parsed.drive):
                return
        elif Path(path).is_absolute():
            return
    raise _invalid("clientSecret must reference a valid env name or an absolute local file; stored secrets are unsupported")


def _check_legacy_config(path: str) -> None:
    legacy = str(Path.home() / ".config/falcon-axi/credentials")
    if not os.path.lexists(path) and os.path.lexists(legacy):
        raise CliError(
            "CONFIG_MOVED",
            f"legacy credentials at {legacy} must be converted to {path}",
            [
                "Use version 1 config.json profiles with clientId and clientSecret: {env: NAME} or {file: /absolute/path}",
                "See https://github.com/knowttl/artium-axi/blob/main/docs/credential-standard.md",
            ],
        )


def load_profiles(
    env: Mapping[str, str],
    flag: str | None = None,
    *,
    diagnostic: bool = False,
    platform: str | None = None,
) -> dict[str, Any]:
    path = config_path(env, flag)
    _check_legacy_config(path)
    text = read_private_file(path, diagnostic=diagnostic, platform=platform)
    if text is None:
        return {"version": 1, "profiles": {}}
    try:
        document = json.loads(text)
    except ValueError as error:
        raise _invalid(f"invalid JSON in {path}") from error
    if (
        not isinstance(document, dict)
        or set(document) - {"version", "defaultProfile", "profiles"}
        or type(document.get("version")) is not int
        or document["version"] != 1
        or not isinstance(document.get("profiles"), dict)
    ):
        raise _invalid("config.json requires version 1 and a profiles object")
    profiles = document["profiles"]
    for name, profile in profiles.items():
        if not PROFILE_NAME.fullmatch(name):
            raise _invalid("invalid profile name")
        if not isinstance(profile, dict) or set(profile) - PROFILE_FIELDS:
            raise _invalid(f"profile {name} has unknown fields")
        for field in ("region", "memberCid", "clientId"):
            if field in profile and (not isinstance(profile[field], str) or not profile[field].strip()):
                raise _invalid(f"profile {name} requires a nonempty string for {field}")
        if "clientId" not in profile:
            raise _invalid(f"profile {name} requires clientId")
        _validate_ref(profile.get("clientSecret", {"env": "FALCON_AXI_CLIENT_SECRET"}), platform)
    default = document.get("defaultProfile")
    if default is not None and (not isinstance(default, str) or default not in profiles):
        raise _invalid("defaultProfile must name an existing profile")
    return document


def resolve_credential(
    env: Mapping[str, str] | None = None,
    *,
    config: str | None = None,
    profile: str | None = None,
    diagnostic: bool = False,
) -> Credential:
    original = os.environ if env is None else env
    values = normalized_environment(original)
    read_only(values)
    _check_legacy_config(config_path(values, config))
    selected = profile or values.get("FALCON_AXI_PROFILE")
    if selected is None:
        client_id, secret = values.get("FALCON_AXI_CLIENT_ID"), values.get("FALCON_AXI_CLIENT_SECRET")
        if client_id and secret:
            register_secret(client_id)
            register_secret(secret)
            return Credential(
                client_id,
                secret,
                "environment",
                region=values.get("FALCON_AXI_REGION") or values.get("FALCON_AXI_BASE_URL"),
                member_cid=values.get("FALCON_AXI_MEMBER_CID"),
                secret_source=f"env:{_source_name('FALCON_AXI_CLIENT_SECRET', original)}",
            )
        if client_id or secret:
            missing = "FALCON_AXI_CLIENT_SECRET" if client_id else "FALCON_AXI_CLIENT_ID"
            raise _invalid(f"env profile is incomplete; set {missing}")
    document = load_profiles(values, config, diagnostic=diagnostic)
    profiles = document["profiles"]
    if selected is None:
        selected = document.get("defaultProfile")
        if selected is None:
            if len(profiles) == 1:
                selected = next(iter(profiles))
            elif profiles:
                raise CliError("PROFILE_AMBIGUOUS", "select a profile with --profile or FALCON_AXI_PROFILE")
            else:
                raise CliError("PROFILE_REQUIRED", "no Falcon profile configured", setup_help(values))
    if selected not in profiles:
        raise CliError("PROFILE_NOT_FOUND", "selected profile does not exist", ["Run `falcon-axi profile list`"])
    settings = profiles[selected]
    ref = settings.get("clientSecret", {"env": "FALCON_AXI_CLIENT_SECRET"})
    if "env" in ref:
        secret = values.get(ref["env"])
        source = f"env:{_source_name(ref['env'], original)}"
        path = None
    else:
        path = ref["file"]
        contents = read_private_file(path, secret=True, diagnostic=diagnostic)
        secret = contents.rstrip() if contents is not None else None
        source = f"file:{path}"
    if not secret:
        raise CliError("AUTH_REQUIRED", "clientSecret SecretRef resolved to no value")
    register_secret(settings["clientId"])
    register_secret(secret)
    return Credential(
        settings["clientId"], secret, "file", path, selected, settings.get("region"), settings.get("memberCid"), source
    )
