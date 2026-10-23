import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
from toon_format import decode

from falcon_axi.cli import _followup_help, _suggestion_for, flag_guard, parse, run
from falcon_axi.command import CommandSpec
from falcon_axi.commands import COMMAND_SPECS, COMMANDS, SUBCOMMANDS
from falcon_axi.core import CliError
from falcon_axi.transport.operations import OPERATIONS
from falcon_axi.version import VERSION
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport

REPO = Path(__file__).resolve().parent.parent.parent


@pytest.mark.parametrize("group", SUBCOMMANDS)
def test_group_help_lists_subcommands_without_authentication(group: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run([*group.split(), "--help"], recorded, {})
    assert exit_code == 0
    assert stdout.splitlines() == [spec.summary for spec in COMMAND_SPECS.values() if spec.name.startswith(f"{group} ")]
    assert recorded.requests == []


@pytest.mark.parametrize("spec", COMMAND_SPECS.values(), ids=lambda spec: spec.name)
def test_every_registered_command_has_help_a_handler_and_operations(spec: CommandSpec) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run([*spec.name.split(), "--help"], recorded, {})
    assert exit_code == 0
    if spec.name not in SUBCOMMANDS:
        assert stdout == spec.help + "\n"
        assert stdout.startswith(f"falcon-axi {spec.name}")
    assert all(operation in OPERATIONS for operation in spec.operations)
    if spec.authentication == "standard":
        assert spec.operations
    assert recorded.requests == []


@pytest.mark.parametrize("command", [name for name in COMMANDS if " " in name])
@pytest.mark.parametrize("flags", [[], ["--help"]])
def test_a_multiword_command_in_one_argument_is_unknown(command: str, flags: list[str]) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run([command, *flags], recorded, {})
    assert exit_code == 2
    assert decode(stdout)["error"] == f"unknown command {command}"
    assert decode(stdout)["code"] == "VALIDATION_ERROR"
    assert recorded.requests == []


def test_the_surface_lists_no_mutating_verb() -> None:
    for verb in ("contain", "update", "assign", "close", "release", "run", "execute", "create", "delete"):
        with pytest.raises(CliError) as first:
            parse([verb])
        assert first.value.code == "VALIDATION_ERROR"
        for noun in ("detection", "host", "vuln", "cve"):
            with pytest.raises(CliError):
                parse([noun, verb])


def test_a_secret_shaped_flag_cannot_be_registered() -> None:
    for name in ("client-secret", "password", "api-key", "token", "passphrase"):
        with pytest.raises(ValueError, match="forbidden"):
            flag_guard(name)
    flag_guard("member-cid")


@pytest.mark.parametrize(
    "command",
    [
        "detection list",
        "host list",
        "account list",
        "vuln list",
        "identity list",
        "identity timeline",
        "container list",
        "image list",
        "image vulnerabilities",
        "serverless list",
    ],
)
def test_continuation_arguments_survive_shell_parsing_and_expansion(command: str) -> None:
    value = 'O\'Brien * $HOME "quoted" \\ $(printf expanded); &|<> []\n'
    flags = {name: value for name in ("region", *COMMAND_SPECS[command].value_flags) if name != "cursor"}
    positionals = (value,) if command == "identity timeline" else ()
    help = _followup_help([f"Run `{_suggestion_for(command, flags, positionals)}` for the next page"], flags, None)
    suggestion = help[0].removeprefix("Run `").removesuffix("` for the next page")
    result = subprocess.run(  # noqa: S603
        ["sh", "-c", f"set -- {suggestion}; printf '%s\\0' \"$@\""],  # noqa: S607
        capture_output=True,
        check=True,
    )
    arguments = result.stdout.decode().split("\0")[:-1]
    assert arguments[: 3 + len(positionals)] == ["falcon-axi", *command.split(), *positionals]
    replayed = arguments[3 + len(positionals) :]
    assert len(replayed) == 2 * len(flags)
    assert dict(zip(replayed[::2], replayed[1::2], strict=True)) == {f"--{name}": value for name in flags}


def test_member_cid_and_no_member_cid_cannot_be_combined() -> None:
    stdout, exit_code = run(
        ["auth", "status", "--member-cid", "cid", "--no-member-cid"], RecordedTransport([]), dict(CREDENTIAL_ENV)
    )
    assert exit_code == 2
    assert "cannot be combined" in stdout


def test_help_never_advertises_a_command_the_cli_does_not_have() -> None:
    shipped = (
        ["--help"],
        ["detection", "list", "--help"],
        ["detection", "show", "--help"],
        ["host", "list", "--help"],
        ["host", "show", "--help"],
        ["vuln", "list", "--help"],
        ["vuln", "show", "--help"],
        ["cve", "list", "--help"],
        ["cve", "show", "--help"],
        ["search", "start", "--help"],
        ["search", "status", "--help"],
        ["search", "stop", "--help"],
        ["identity", "list", "--help"],
        ["identity", "show", "--help"],
        ["identity", "timeline", "--help"],
        ["auth", "status", "--help"],
        ["scopes", "--help"],
    )
    for argv in shipped:
        stdout, exit_code = run(argv, RecordedTransport([]), dict(CREDENTIAL_ENV))
        assert exit_code == 0
        for absent in ("falcon-axi setup", "tenant list"):
            assert absent not in stdout, f"{' '.join(argv)} advertises {absent}"
        if argv in (["detection", "list", "--help"], ["host", "list", "--help"], ["vuln", "list", "--help"]):
            assert "--fields" in stdout
        else:
            assert "--fields" not in stdout, f"{' '.join(argv)} advertises --fields"
    top, _ = run(["--help"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    # Operators see both write-labelled scopes and N3's explicit execution authorization contract.
    assert "RTR execution requires profile opt-in, --execute, and exact host:command --confirm (N3)" in top
    assert "NGSIEM:write" in top
    assert "Identity Protection GraphQL:write" in " ".join(top.split())
    assert VERSION in top
    for command in COMMANDS:
        assert command in top


def test_the_published_version_matches_pyproject() -> None:
    manifest = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert manifest["project"]["version"] == VERSION
    assert manifest["project"]["scripts"]["falcon-axi"] == "falcon_axi.cli:main"


def test_every_fixture_is_wholly_synthetic_and_carries_its_provenance_header() -> None:
    root = REPO / "tests/fixtures"
    count = 0
    for path in sorted(root.glob("*/*.json")):
        count += 1
        text = path.read_text(encoding="utf-8")
        parsed = json.loads(text)
        provenance = parsed.get("provenance")
        assert provenance, f"{path.name} has no provenance header"
        assert provenance["provenance"] == "synthetic"
        assert provenance.get("operation"), f"{path.name} names no operation"
        assert provenance.get("reference", "").startswith("https://")
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", provenance.get("schema_read", ""))
        assert isinstance(parsed.get("response", {}).get("status"), int)
        assert not re.search(r"\b[0-9a-f]{32}\b", text, re.IGNORECASE), f"{path.name} contains a realistic CID or agent id"
        assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", text), f"{path.name} contains a realistic bearer token"
        assert not re.search(r"Bearer\s+[A-Za-z0-9._-]{12,}", text, re.IGNORECASE), (
            f"{path.name} contains an Authorization value"
        )
    assert count >= 15
