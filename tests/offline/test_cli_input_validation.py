"""Shared input validation precedes credential resolution and authentication."""

import pytest

from falcon_axi.cli import parse, run
from tests.support.recorded import CREDENTIAL_ENV, NO_CREDENTIAL_ENV, RecordedTransport

INPUTS = [
    (["detection", "list"], "filter", " \t\n"),
    (["host", "list"], "filter", " \t\n"),
    (["account", "list"], "filter", " \t\n"),
    (["vuln", "list"], "filter", " \t\n"),
    (["detection", "list"], "since", "yesterday"),
    (["host", "list"], "since", "yesterday"),
    (["host", "logins", "synthetic-device-01"], "since", "yesterday"),
    (["vuln", "list"], "since", "yesterday"),
    (["search", "start", "--query", "head(2)"], "since", "yesterday"),
    (["identity", "timeline", "00000000-0000-4000-8000-000000000001"], "since", "yesterday"),
]


@pytest.mark.parametrize(("command", "flag", "value"), INPUTS)
@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize("authenticated", [False, True])
def test_invalid_values_fail_before_credentials_or_any_request(
    command: list[str], flag: str, value: str, inline: bool, authenticated: bool
) -> None:
    recorded = RecordedTransport([])
    env = CREDENTIAL_ENV if authenticated else NO_CREDENTIAL_ENV
    arguments = [f"--{flag}={value}"] if inline else [f"--{flag}", value]
    stdout, exit_code = run([*command, *arguments], recorded, dict(env))
    assert exit_code == 2
    assert "code: VALIDATION_ERROR" in stdout
    assert f"--{flag}" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(("command", "flag", "value"), INPUTS)
def test_help_bypasses_value_validation(command: list[str], flag: str, value: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run([*command, f"--{flag}", value, "--help"], recorded, dict(NO_CREDENTIAL_ENV))
    assert exit_code == 0
    assert "falcon-axi" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(("command", "flag", "value"), INPUTS)
def test_valid_values_are_preserved(command: list[str], flag: str, value: str) -> None:
    valid = "24H" if flag == "since" else " username:'synthetic-user' "
    parsed = parse([*command, f"--{flag}", valid])
    assert parsed.flags[flag] == valid
