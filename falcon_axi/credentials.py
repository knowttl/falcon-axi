"""Credential resolution (docs/design/v1.md §5.2).

Secrets reach falcon-axi through the environment or a 0600 file, never through argv.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from falcon_axi.core import CliError

CredentialChannel = Literal["environment", "file"]


@dataclass(frozen=True)
class Credential:
    client_id: str
    client_secret: str
    channel: CredentialChannel
    path: str | None = None


DEFAULT_CREDENTIALS_PATH = str(Path.home() / ".config" / "falcon-axi" / "credentials")


def credentials_path(env: Mapping[str, str] | None = None) -> str:
    values = os.environ if env is None else env
    return values.get("FALCON_AXI_CREDENTIALS_FILE") or DEFAULT_CREDENTIALS_PATH


def setup_help(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    return (
        "Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in the environment",
        f"Or write them to {credentials_path(env)} with mode 0600",
        "Provision an API client with read scopes; only `search start` and `search stop` need NGSIEM:write",
    )


def _incomplete(missing: str, present: str) -> CliError:
    return CliError(
        "CREDENTIAL_INCOMPLETE",
        f"{present} is set but {missing} is missing",
        [f"Set {missing} as well", f"Or unset {present} to fall back to {credentials_path()}"],
    )


def _assert_protected_file(path: str) -> bool:
    """Rejects a credentials file that any other account could have written or read (§5.2).

    The file is not read when this fails, and no value from it is ever echoed.
    """
    try:
        stats = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise CliError(
            "VALIDATION_ERROR",
            f"the credentials file at {path} could not be read",
            [f"Ensure {path} is a regular file owned by the current user with mode 0600"],
        ) from error
    import stat as stat_module

    owned = stats.st_uid == os.getuid() if hasattr(os, "getuid") else True
    if stat_module.S_ISLNK(stats.st_mode) or not stat_module.S_ISREG(stats.st_mode) or not owned or (stats.st_mode & 0o077):
        raise CliError(
            "VALIDATION_ERROR",
            f"the credentials file at {path} is not protected",
            [
                f"{path} must be a regular file owned by the current user with mode 0600",
                "Run `chmod 0600` on it and replace any symlink with the file itself",
            ],
        )
    return True


def _parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.split("\n"):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        separator = trimmed.find("=")
        if separator <= 0:
            continue
        key = trimmed[:separator].strip()
        value = trimmed[separator + 1 :].strip()
        if len(value) >= 2 and value[0] in "\"'" and value[-1] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def resolve_credential(env: Mapping[str, str] | None = None) -> Credential | None:
    """Resolves a credential through the accepted input channels, in precedence order (§5.2).

    A half-configured environment stops resolution rather than falling through to a file, because a
    silent fallback could select the wrong identity.
    """
    values = os.environ if env is None else env
    id = values.get("FALCON_CLIENT_ID")
    secret = values.get("FALCON_CLIENT_SECRET")
    if id and secret:
        return Credential(client_id=id, client_secret=secret, channel="environment")
    if id:
        raise _incomplete("FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID")
    if secret:
        raise _incomplete("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")

    path = credentials_path(env)
    if not _assert_protected_file(path):
        return None
    parsed = _parse_key_values(Path(path).read_text(encoding="utf-8"))
    file_id = parsed.get("FALCON_CLIENT_ID")
    file_secret = parsed.get("FALCON_CLIENT_SECRET")
    if file_id and file_secret:
        return Credential(client_id=file_id, client_secret=file_secret, channel="file", path=path)
    if not file_id and not file_secret:
        return None
    raise CliError(
        "CREDENTIAL_INCOMPLETE",
        f"the credentials file at {path} sets only one half of the credential",
        [f"Set both FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in {path}"],
    )
