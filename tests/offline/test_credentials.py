import json
import os
from pathlib import Path

import pytest

from falcon_axi.core import CliError
from falcon_axi.credentials import resolve_credential


def test_both_environment_variables_resolve_as_one_atomic_pair() -> None:
    credential = resolve_credential({"FALCON_CLIENT_ID": "id", "FALCON_CLIENT_SECRET": "secret"})
    assert credential is not None
    assert credential.channel == "environment"
    assert credential.client_id == "id"


def test_half_an_environment_credential_stops_resolution_and_names_the_missing_half() -> None:
    for present, missing in (("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"), ("FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID")):
        with pytest.raises(CliError) as error:
            resolve_credential({present: "value"})
        assert error.value.code == "CONFIG_INVALID"
        assert error.value.exit_code == 2
        assert missing.replace("FALCON_", "FALCON_AXI_") in error.value.message


def test_no_credential_anywhere_requires_a_profile() -> None:
    with pytest.raises(CliError) as error:
        resolve_credential({})
    assert error.value.code == "PROFILE_REQUIRED"


def test_a_protected_credentials_file_is_read_and_a_loose_one_is_refused_unread(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    path.write_text("\ufefffile-secret\r\n", encoding="utf-8")
    path.chmod(0o600)
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "test": {
                        "clientId": "file-id",
                        "clientSecret": {"file": str(path)},
                    }
                },
            }
        )
    )
    values = {"FALCON_AXI_CONFIG": str(config)}
    config.chmod(0o600)
    credential = resolve_credential(values)
    assert credential is not None
    assert credential.channel == "file"
    assert credential.client_id == "file-id"
    assert credential.client_secret == "file-secret"

    path.chmod(0o640)
    with pytest.raises(CliError) as loose:
        resolve_credential(values)
    assert loose.value.code == "CONFIG_INSECURE"
    assert "file-secret" not in loose.value.message

    path.chmod(0o600)
    link = tmp_path / "linked-credentials"
    os.symlink(path, link)
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "test": {
                        "clientId": "file-id",
                        "clientSecret": {"file": str(link)},
                    }
                },
            }
        )
    )
    with pytest.raises(CliError) as linked:
        resolve_credential(values)
    assert linked.value.code == "CONFIG_INSECURE"


def test_legacy_credentials_are_never_read() -> None:
    path = Path.home() / ".config/falcon-axi/credentials"
    path.parent.mkdir(parents=True)
    path.write_text("FALCON_CLIENT_ID=file-id\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(CliError) as error:
        resolve_credential({})
    assert error.value.code == "CONFIG_MOVED"
