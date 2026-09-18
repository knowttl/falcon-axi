import os
import tempfile
from pathlib import Path

import pytest

from falcon_axi.core import CliError
from falcon_axi.credentials import resolve_credential

MISSING = str(Path(tempfile.gettempdir()) / "falcon-axi-absent" / "credentials")


def env(**values: str) -> dict[str, str]:
    return {"FALCON_AXI_CREDENTIALS_FILE": MISSING, **values}


def test_both_environment_variables_resolve_as_one_atomic_pair() -> None:
    credential = resolve_credential(env(FALCON_CLIENT_ID="id", FALCON_CLIENT_SECRET="secret"))
    assert credential is not None
    assert credential.channel == "environment"
    assert credential.client_id == "id"


def test_half_an_environment_credential_stops_resolution_and_names_the_missing_half() -> None:
    for present, missing in (("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"), ("FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID")):
        with pytest.raises(CliError) as error:
            resolve_credential(env(**{present: "value"}))
        assert error.value.code == "CREDENTIAL_INCOMPLETE"
        assert error.value.exit_code == 2
        assert missing in error.value.message


def test_no_credential_anywhere_resolves_to_nothing() -> None:
    assert resolve_credential(env()) is None


def test_a_protected_credentials_file_is_read_and_a_loose_one_is_refused_unread(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    path.write_text("FALCON_CLIENT_ID=file-id\nFALCON_CLIENT_SECRET=file-secret\n", encoding="utf-8")
    path.chmod(0o600)
    credential = resolve_credential(env(FALCON_AXI_CREDENTIALS_FILE=str(path)))
    assert credential is not None
    assert credential.channel == "file"
    assert credential.client_id == "file-id"

    path.chmod(0o640)
    with pytest.raises(CliError) as loose:
        resolve_credential(env(FALCON_AXI_CREDENTIALS_FILE=str(path)))
    assert loose.value.code == "VALIDATION_ERROR"
    assert "file-secret" not in loose.value.message

    path.chmod(0o600)
    link = tmp_path / "linked-credentials"
    os.symlink(path, link)
    with pytest.raises(CliError) as linked:
        resolve_credential(env(FALCON_AXI_CREDENTIALS_FILE=str(link)))
    assert linked.value.code == "VALIDATION_ERROR"


def test_a_credentials_file_holding_one_half_of_the_pair_is_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "credentials"
    path.write_text("FALCON_CLIENT_ID=file-id\n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(CliError) as error:
        resolve_credential(env(FALCON_AXI_CREDENTIALS_FILE=str(path)))
    assert error.value.code == "CREDENTIAL_INCOMPLETE"
