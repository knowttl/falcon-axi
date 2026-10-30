"""Recorded-invocation comparisons follow docs/design/v1-python.md §5."""

import re

import pytest
from toon_format import decode

from falcon_axi.commands import COMMANDS
from falcon_axi.version import VERSION
from tests.support.golden import GOLDEN, command_references, expected_stdout, replay, scenarios

SCENARIOS = scenarios()


def test_golden_replay_reports_invalid_token_response_diagnostics() -> None:
    stdout, exit_code = replay(
        {
            "argv": ["host", "list"],
            "oauth": [
                {
                    "response": {
                        "status": 200,
                        "headers": {"Content-Type": "application/json"},
                        "body": {"access_token": False},
                    }
                }
            ],
        }
    )
    document = decode(stdout)
    assert exit_code == 1
    assert document["code"] == "UPSTREAM_ERROR"
    assert document["status"] == 200
    assert document["contentType"] == "application/json"
    assert document["shape"] == [
        {"path": "$", "type": "object"},
        {"path": '$["access_token"]', "type": "boolean"},
    ]
    assert document["shapeTruncated"] is False


def test_every_generated_scenario_has_an_expected_document() -> None:
    assert len(SCENARIOS) >= 50
    names = [entry["name"] for entry in SCENARIOS]
    assert len(names) == len(set(names))
    assert sorted(names) == sorted(path.stem for path in GOLDEN.glob("*.txt") if path.name != "description.txt")
    assert sorted(names) == sorted(path.stem for path in (GOLDEN / "scenarios").glob("*.json"))


def test_command_references_cover_the_ordered_command_surface() -> None:
    references = command_references()
    assert [entry["name"] for entry in references] == list(COMMANDS)
    assert len({entry["order"] for entry in references}) == len(references)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda entry: entry["name"])
def test_python_reproduces_the_typescript_document(scenario: dict) -> None:
    stdout, exit_code = replay(scenario)
    expected = expected_stdout(scenario["name"])
    if scenario["name"] == "help-top":
        expected = re.sub(r"\Afalcon-axi \S+ - ", f"falcon-axi {VERSION} - ", expected, count=1)
    if scenario["name"].startswith("version-"):
        expected = re.sub(r"\A\S+(?=\n\Z)", VERSION, expected, count=1)
    assert stdout == expected
    assert exit_code == scenario["exit_code"]
