import json
import os
import stat
import subprocess
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.credentials import config_path, load_profiles, resolve_credential, tool_directory
from falcon_axi.private_file import read_private_file, verify_windows_acl
from tests.support.recorded import RecordedTransport, fixture, serve


@pytest.fixture
def profiles(tmp_path: Path) -> dict[str, str]:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "one": {
                        "region": "us-2",
                        "clientId": "synthetic-one",
                        "memberCid": "synthetic-child",
                        "clientSecret": {"env": "TEST_SECRET"},
                    },
                    "two": {"clientId": "synthetic-two", "clientSecret": {"env": "TEST_SECRET"}},
                },
            }
        )
    )
    path.chmod(0o600)
    return {"FALCON_AXI_CONFIG": str(path), "TEST_SECRET": "synthetic-secret"}


def test_paths_follow_each_call_and_ignore_relative_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    assert config_path({"XDG_CONFIG_HOME": str(tmp_path / "first")}) == str(tmp_path / "first/falcon-axi/config.json")
    assert config_path({"XDG_CONFIG_HOME": str(tmp_path / "second")}) == str(tmp_path / "second/falcon-axi/config.json")
    assert config_path({"XDG_CONFIG_HOME": "relative"}) == str(tmp_path / "home/.config/falcon-axi/config.json")
    assert config_path({"FALCON_AXI_CONFIG": "env.json"}, "flag.json") == "flag.json"


def test_windows_paths_use_appdata_and_ignore_xdg(tmp_path: Path) -> None:
    env = {
        "APPDATA": str(tmp_path / "roaming"),
        "LOCALAPPDATA": str(tmp_path / "local"),
        "XDG_CONFIG_HOME": str(tmp_path / "ignored"),
        "XDG_STATE_HOME": str(tmp_path / "ignored"),
    }
    assert tool_directory("config", env, "nt") == tmp_path / "roaming/falcon-axi"
    assert tool_directory("state", env, "nt") == tmp_path / "local/falcon-axi"


def test_explicit_profile_ignores_env_fields_and_partial_env(profiles: dict[str, str]) -> None:
    credential = resolve_credential(
        {
            **profiles,
            "FALCON_AXI_PROFILE": "two",
            "FALCON_AXI_CLIENT_ID": "other",
            "FALCON_AXI_REGION": "eu-1",
            "FALCON_BASE_URL": "https://api.eu-1.crowdstrike.com",
            "FALCON_AXI_MEMBER_CID": "other",
        },
        profile="one",
    )
    assert credential is not None
    assert (credential.client_id, credential.region, credential.member_cid) == ("synthetic-one", "us-2", "synthetic-child")
    assert credential.secret_source == "env:TEST_SECRET"


def test_complete_env_precedes_file_default(profiles: dict[str, str]) -> None:
    credential = resolve_credential({**profiles, "FALCON_AXI_CLIENT_ID": "env-id", "FALCON_AXI_CLIENT_SECRET": "env-secret"})
    assert credential is not None
    assert credential.profile == "env"
    assert credential.client_id == "env-id"


@pytest.mark.parametrize("command", [[], ["detection", "list"], ["auth", "status"]])
@pytest.mark.parametrize("empty_profiles", [False, True])
def test_setup_guidance_preserves_explicit_config_path(command: list[str], empty_profiles: bool, tmp_path: Path) -> None:
    path = tmp_path / "chosen.json"
    if empty_profiles:
        path.write_text(json.dumps({"version": 1, "profiles": {}}))
        path.chmod(0o600)
    values = {"FALCON_AXI_CONFIG": str(tmp_path / "ignored.json"), "TEST_SECRET": "synthetic-secret"}
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("alerts/query-empty.json"))])
    argv = [*command, "--config", str(path)]
    stdout, code = run(argv, recorded, values)
    document = decode(stdout)
    assert code == 1
    assert document["code"] == "PROFILE_REQUIRED"
    assert f"Or configure a profile with a clientSecret SecretRef in {path}" in document["help"]
    assert recorded.requests == []

    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {"test": {"clientId": "synthetic-id", "clientSecret": {"env": "TEST_SECRET"}}},
            }
        )
    )
    path.chmod(0o600)
    _, code = run(argv, recorded, values)
    assert code == 0
    assert recorded.oauth_requests()[0].client_id == "synthetic-id"


@pytest.mark.parametrize("command", [[], ["auth", "status"], ["detection", "list"]])
@pytest.mark.parametrize("config_source", ["flag", "env", "default"])
def test_env_auth_ignores_malformed_unused_config(command: list[str], config_source: str, tmp_path: Path) -> None:
    path = tmp_path / "config.json" if config_source != "default" else Path.home() / ".config/falcon-axi/config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{invalid JSON")
    path.chmod(0o600)
    values = {"FALCON_AXI_CLIENT_ID": "env-id", "FALCON_AXI_CLIENT_SECRET": "env-secret"}
    flags = []
    if config_source == "flag":
        flags = ["--config", str(path)]
    elif config_source == "env":
        values["FALCON_AXI_CONFIG"] = str(path)
    recorded = RecordedTransport([serve("GetQueriesAlertsV2", fixture("alerts/query-empty.json"))])
    stdout, code = run([*command, *flags], recorded, values)
    assert code == 0
    assert recorded.oauth_requests()[0].client_id == "env-id"
    assert "env-secret" not in stdout


@pytest.mark.parametrize("command", [[], ["auth", "status"], ["detection", "list"], ["profile", "list"]])
@pytest.mark.parametrize("env_profile", [False, True])
def test_fixed_legacy_path_requires_migration(command: list[str], env_profile: bool, tmp_path: Path) -> None:
    legacy = Path.home() / ".config/falcon-axi/credentials"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("FALCON_CLIENT_SECRET=legacy-secret")
    legacy.chmod(0o000)
    config = tmp_path / "absent.json"
    values = {"FALCON_AXI_CONFIG": str(config)}
    if env_profile:
        values.update(FALCON_AXI_CLIENT_ID="env-id", FALCON_AXI_CLIENT_SECRET="env-secret")
    recorded = RecordedTransport([])
    stdout, code = run(command, recorded, values)
    assert code == 1
    assert "code: CONFIG_MOVED" in stdout
    assert str(legacy) in stdout
    assert str(config) in stdout
    assert "legacy-secret" not in stdout
    assert recorded.requests == []


def test_default_profile_selects_among_multiple_profiles(profiles: dict[str, str]) -> None:
    path = Path(profiles["FALCON_AXI_CONFIG"])
    document = json.loads(path.read_text())
    document["defaultProfile"] = "two"
    path.write_text(json.dumps(document))
    assert resolve_credential(profiles).profile == "two"


def test_env_aliases_warn_and_new_name_wins(capsys: pytest.CaptureFixture[str]) -> None:
    credential = resolve_credential(
        {
            "FALCON_CLIENT_ID": "old-id",
            "FALCON_CLIENT_SECRET": "old-secret",
            "FALCON_AXI_CLIENT_ID": "new-id",
            "FALCON_AXI_CLIENT_SECRET": "new-secret",
        }
    )
    assert credential.client_id == "new-id"
    assert credential.client_secret == "new-secret"
    notice = capsys.readouterr().err
    assert "FALCON_CLIENT_ID is deprecated; use FALCON_AXI_CLIENT_ID" in notice
    assert "old-secret" not in notice


@pytest.mark.parametrize(
    "region,flags,expected",
    [
        ({}, [], "https://api.us-2.crowdstrike.com"),
        ({"FALCON_AXI_REGION": "eu-1"}, [], "https://api.eu-1.crowdstrike.com"),
        ({"FALCON_AXI_REGION": "eu-1"}, ["--region", "us-1"], "https://api.crowdstrike.com"),
    ],
)
def test_deprecated_base_url_alias_uses_region_precedence(
    region: dict[str, str], flags: list[str], expected: str, capsys: pytest.CaptureFixture[str]
) -> None:
    values = {
        "FALCON_AXI_CLIENT_ID": "env-id",
        "FALCON_AXI_CLIENT_SECRET": "env-secret",
        "FALCON_BASE_URL": "https://api.us-2.crowdstrike.com",
        **region,
    }
    recorded = RecordedTransport([])
    _, code = run(["auth", "status", *flags], recorded, values)
    assert code == 0
    assert recorded.oauth_requests()[0].base_url == expected
    assert "FALCON_BASE_URL is deprecated; use FALCON_AXI_REGION" in capsys.readouterr().err


def test_secret_ref_can_name_an_alias_explicitly(profiles: dict[str, str]) -> None:
    path = Path(profiles["FALCON_AXI_CONFIG"])
    document = json.loads(path.read_text())
    document["profiles"]["one"]["clientSecret"] = {"env": "FALCON_CLIENT_SECRET"}
    path.write_text(json.dumps(document))
    credential = resolve_credential({**profiles, "FALCON_CLIENT_SECRET": "old-secret"}, profile="one")
    assert credential.client_secret == "old-secret"
    assert credential.secret_source == "env:FALCON_CLIENT_SECRET"


def test_missing_referenced_secret_is_auth_required(profiles: dict[str, str]) -> None:
    with pytest.raises(CliError) as error:
        resolve_credential({**profiles, "TEST_SECRET": ""}, profile="one")
    assert error.value.code == "AUTH_REQUIRED"


@pytest.mark.parametrize(
    "flags,region,member",
    [
        ([], "us-2", "synthetic-child"),
        (["--region", "us-1", "--no-member-cid"], "us-1", None),
        (["--member-cid", "synthetic-override-child"], "us-2", "synthetic-override-child"),
    ],
)
def test_profile_region_and_tenant_reach_token_request_and_flags_override(
    profiles: dict[str, str],
    flags: list[str],
    region: str,
    member: str | None,
) -> None:
    recorded = RecordedTransport([], [fixture("oauth2/token-success.json")])
    stdout, code = run(["auth", "status", "--profile", "one", *flags], recorded, profiles)
    assert code == 0
    request = recorded.oauth_requests()[0]
    from falcon_axi.origin import REGIONS

    assert request.base_url == REGIONS[region]
    assert request.member_cid == member
    assert "profile: one" in stdout
    assert 'client_secret_source: "env:TEST_SECRET"' in stdout
    assert "synthetic-secret" not in stdout
    assert (
        "Supply the same tenant selection used for this invocation when following these suggestions" in decode(stdout)["help"]
    ) == (member is not None)


@pytest.mark.parametrize("variable", ["FALCON_AXI_MEMBER_CID", "FALCON_MEMBER_CID"])
def test_auth_status_ignores_environment_tenant_guidance_for_file_profile(profiles: dict[str, str], variable: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(
        ["auth", "status", "--profile", "two"], recorded, {**profiles, variable: "synthetic-ignored-child"}
    )
    assert code == 0
    assert recorded.oauth_requests()[0].member_cid is None
    assert (
        "Supply the same tenant selection used for this invocation when following these suggestions"
        not in decode(stdout)["help"]
    )
    assert "synthetic-ignored-child" not in stdout


def test_resolved_secret_and_its_encoded_forms_are_redacted_in_errors(profiles: dict[str, str]) -> None:
    secret = 'synthetic-"secret?value'

    class FailingTransport:
        def request_oauth_token(self, args: object) -> None:
            from urllib.parse import quote

            raise CliError("UPSTREAM_ERROR", f"{secret} {json.dumps(secret)[1:-1]} {quote(secret, safe='')}")

    stdout, code = run(["auth", "status", "--profile", "one"], FailingTransport(), {**profiles, "TEST_SECRET": secret})
    assert code == 1
    assert "synthetic-" not in stdout
    assert "[redacted]" in stdout


def test_multiple_profiles_require_selection(profiles: dict[str, str]) -> None:
    with pytest.raises(CliError, match="select a profile") as error:
        resolve_credential(profiles)
    assert error.value.code == "PROFILE_AMBIGUOUS"


@pytest.mark.parametrize(
    "ref",
    ["inline-synthetic-secret", {"env": "BAD=NAME"}, {"env": "OK", "file": "/secret"}, {"file": "relative"}, {"stored": True}],
)
def test_invalid_secret_refs_are_rejected_on_load(ref: object, tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"version": 1, "profiles": {"test": {"clientId": "id", "clientSecret": ref}}}))
    path.chmod(0o600)
    with pytest.raises(CliError) as error:
        load_profiles({"FALCON_AXI_CONFIG": str(path)})
    assert error.value.code == "CONFIG_INVALID"
    assert "inline-synthetic-secret" not in error.value.message


def test_profile_list_never_resolves_secrets(profiles: dict[str, str]) -> None:
    stdout, code = run(["profile", "list"], RecordedTransport([]), {**profiles, "TEST_SECRET": ""})
    assert code == 0
    assert "one,two" in stdout
    assert "synthetic-secret" not in stdout


@pytest.mark.parametrize("mode,secret", [(0o644, False), (0o400, True)])
def test_posix_accepts_protected_files(mode: int, secret: bool, tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_text("synthetic")
    path.chmod(mode)
    assert read_private_file(str(path), secret=secret) == "synthetic"


@pytest.mark.parametrize("mode,secret", [(0o664, False), (0o640, True)])
def test_posix_refuses_unprotected_files(mode: int, secret: bool, tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_text("synthetic")
    path.chmod(mode)
    with pytest.raises(CliError) as error:
        read_private_file(str(path), secret=secret)
    assert error.value.code == "CONFIG_INSECURE"


def test_posix_refuses_a_different_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "file"
    path.write_text("synthetic")
    path.chmod(0o600)
    uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: uid + 1)
    with pytest.raises(CliError) as error:
        read_private_file(str(path))
    assert error.value.code == "CONFIG_INSECURE"


def test_windows_reads_ignore_synthetic_modes_and_only_diagnostics_check_acl(tmp_path: Path) -> None:
    path = tmp_path / "file"
    path.write_text("synthetic")
    path.chmod(0o666)
    assert read_private_file(str(path), secret=True, platform="nt", acl=lambda _: False) == "synthetic"
    with pytest.raises(CliError) as error:
        read_private_file(str(path), platform="nt", diagnostic=True, acl=lambda _: False)
    assert error.value.code == "CONFIG_INSECURE"
    assert read_private_file(str(path), platform="nt", diagnostic=True, acl=lambda _: True) == "synthetic"


def test_windows_reparse_points_are_refused_before_acl_or_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "falcon_axi.private_file.os.lstat",
        lambda _: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o666,
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
        ),
    )
    with pytest.raises(CliError) as error:
        read_private_file("synthetic-path", platform="nt")
    assert error.value.code == "CONFIG_INSECURE"


def test_acl_process_passes_path_as_data_and_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def runner(args: list[str], **kwargs: object) -> SimpleNamespace:
        assert args[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]
        assert "synthetic-path" not in args[-1]
        assert kwargs["env"]["FALCON_AXI_ACL_PATH"] == "synthetic-path"  # type: ignore[index]
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(subprocess, "run", runner)
    assert verify_windows_acl("synthetic-path") is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE"])
def test_read_only_stops_search_before_auth(value: str) -> None:
    recorded = RecordedTransport([])
    stdout, code = run(["search", "start", "--query", "*"], recorded, {"FALCON_AXI_READ_ONLY": value})
    assert code == 1
    assert "READ_ONLY_VIOLATION" in stdout
    assert recorded.requests == []


def test_invalid_read_only_fails_closed() -> None:
    stdout, code = run(["config", "path"], RecordedTransport([]), {"FALCON_AXI_READ_ONLY": "yes"})
    assert code == 2
    assert "CONFIG_INVALID" in stdout


def test_package_ships_profile_schema() -> None:
    schema = json.loads(files("falcon_axi").joinpath("axi-credential.schema.json").read_text())
    assert schema["additionalProperties"] is False
    assert schema["properties"]["clientSecret"]["x-secret"] is True


@pytest.mark.parametrize("path", [r"\\server\secret", r"\\?\C:\secret", r"C:secret", "/secret"])
def test_windows_rejects_nonlocal_or_relative_secret_paths_on_load(path: str, tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"version": 1, "profiles": {"test": {"clientId": "id", "clientSecret": {"file": path}}}}))
    with pytest.raises(CliError) as error:
        load_profiles({"FALCON_AXI_CONFIG": str(config)}, platform="nt")
    assert error.value.code == "CONFIG_INVALID"


def test_windows_accepts_absolute_drive_secret_paths_on_load(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "test": {"clientId": "id", "clientSecret": {"file": r"C:\secrets\falcon"}},
                },
            }
        )
    )
    document = load_profiles({"FALCON_AXI_CONFIG": str(config)}, platform="nt")
    assert document["profiles"]["test"]["clientSecret"] == {"file": r"C:\secrets\falcon"}
