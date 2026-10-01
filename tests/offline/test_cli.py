import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
from toon_format import decode

from falcon_axi.cli import COMMAND_FLAGS, COMMANDS, VALUE_FLAGS, _followup_help, _suggestion_for, flag_guard, parse, run
from falcon_axi.core import CliError
from falcon_axi.render import render, truncate
from falcon_axi.version import VERSION
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve

REPO = Path(__file__).resolve().parent.parent.parent


def test_an_unknown_flag_is_rejected_by_name_with_the_valid_flags_inlined() -> None:
    stdout, exit_code = run(["detection", "list", "--sev", "high"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert re.search(r"^error: unknown flag --sev for `detection list`$", stdout, re.MULTILINE)
    assert re.search(r"^code: VALIDATION_ERROR$", stdout, re.MULTILINE)
    assert "Did you mean --severity?" in stdout
    assert "--filter" in stdout


def test_an_unknown_command_or_subcommand_fails_before_any_request() -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["incident", "list"], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert (
        "valid commands: detection list, detection show, host list, host show, host logins, account list, "
        "account show, vuln list, cve show, identity activity, search start, search status, search stop, identity list, "
        "identity show, identity timeline, auth status, scopes" in stdout
    )
    subcommand, _ = run(["detection", "contain"], recorded, dict(CREDENTIAL_ENV))
    assert "valid detection subcommands: list, show" in subcommand
    host, _ = run(["host", "contain"], recorded, dict(CREDENTIAL_ENV))
    assert "valid host subcommands: list, show" in host
    vuln, _ = run(["vuln", "show"], recorded, dict(CREDENTIAL_ENV))
    assert "valid vuln subcommands: list" in vuln
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


def test_limit_above_the_documented_ceiling_is_a_validation_error_naming_it() -> None:
    stdout, exit_code = run(["detection", "list", "--limit", "10001"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "--limit must be an integer from 1 to 10000" in stdout
    for command in ("host", "vuln"):
        capped, code = run([command, "list", "--limit", "5001"], RecordedTransport([]), dict(CREDENTIAL_ENV))
        assert code == 2
        assert "--limit must be an integer from 1 to 5000" in capped


def test_profile_is_refused_honestly_rather_than_silently_ignored() -> None:
    stdout, exit_code = run(["detection", "list", "--profile", "prod"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "profile configuration is not implemented in stage 1" in stdout


@pytest.mark.parametrize(
    "command", ["detection list", "host list", "account list", "vuln list", "identity list", "identity timeline"]
)
def test_continuation_arguments_survive_shell_parsing_and_expansion(command: str) -> None:
    value = 'O\'Brien * $HOME "quoted" \\ $(printf expanded); &|<> []\n'
    flags = {name: value for name in ("region", *COMMAND_FLAGS[command]) if name in VALUE_FLAGS and name != "cursor"}
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
        for absent in ("falcon-axi setup", "--max-rows", "vuln show", "tenant list"):
            assert absent not in stdout, f"{' '.join(argv)} advertises {absent}"
        if argv == ["vuln", "list", "--help"]:
            assert "--fields" in stdout
        else:
            assert "--fields" not in stdout, f"{' '.join(argv)} advertises --fields"
    top, _ = run(["--help"], RecordedTransport([]), dict(CREDENTIAL_ENV))
    # The two write-labelled scopes are named where an operator will see them, and no mutating command is listed.
    assert "lists no command that changes a host, a detection, a policy, or an identity" in top
    assert "NGSIEM:write" in top
    assert "Identity Protection GraphQL:write" in " ".join(top.split())
    assert VERSION in top
    for command in COMMANDS:
        assert command in top


def test_rendered_output_parses_as_toon_and_keeps_the_help_block_intact() -> None:
    recorded = RecordedTransport(
        [
            serve("GetQueriesAlertsV2", fixture("alerts/query-page.json")),
            serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-page.json")),
        ]
    )
    stdout, _ = run(["detection", "list", "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    parsed = decode(stdout)
    assert isinstance(parsed["detections"], list)
    assert len(parsed["help"]) >= 2

    with_commas = render({"count": 1}, ["first, with a comma", 'second with "quotes" and a colon: here'])
    decoded = decode(with_commas)
    assert decoded["help"] == ["first, with a comma", 'second with "quotes" and a colon: here']


def test_truncation_reports_the_full_length_and_leaves_short_values_untouched() -> None:
    assert truncate("short") == ("short", False)
    long = truncate("x" * 900)
    assert long.truncated is True
    assert "truncated, 900 chars total" in long.text


def test_the_published_version_matches_pyproject() -> None:
    manifest = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert manifest["project"]["version"] == VERSION
    assert manifest["project"]["scripts"]["falcon-axi"] == "falcon_axi.cli:main"
    assert manifest["project"]["requires-python"] == ">=3.11"


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
