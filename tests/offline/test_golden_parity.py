"""The cross-language parity gate: every scenario must reproduce TypeScript stage 1 byte for byte."""

import pytest

from tests.support.golden import exit_codes, expected_stdout, replay, scenarios

SCENARIOS = scenarios()


def test_every_generated_scenario_has_an_expected_document() -> None:
    assert len(SCENARIOS) >= 50
    assert sorted(entry["name"] for entry in SCENARIOS) == sorted(exit_codes())


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda entry: entry["name"])
def test_python_reproduces_the_typescript_document(scenario: dict) -> None:
    stdout, exit_code = replay(scenario)
    assert stdout == expected_stdout(scenario["name"])
    assert exit_code == exit_codes()[scenario["name"]]
