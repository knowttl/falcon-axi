"""The generated public documentation is an owned output contract."""

import re
import tomllib
from pathlib import Path
from urllib.parse import unquote

import pytest

from falcon_axi.cli import DESCRIPTION
from falcon_axi.commands import COMMANDS
from scripts import docs
from tests.support.golden import replay, scenarios

REPO = Path(__file__).resolve().parents[2]


def test_readme_reference_covers_exactly_the_shipped_commands() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    table = readme.split(docs.START)[1].split(docs.END)[0].strip()
    names = re.findall(r"^\| `([^`]+)` \|", table, re.MULTILINE)
    assert names == list(COMMANDS)
    assert table == docs.command_table()
    permissions = readme.split(docs.SCOPE_START)[1].split(docs.SCOPE_END)[0].strip()
    assert permissions == docs.permission_table()
    assert (REPO / "docs/commands.md").read_text(encoding="utf-8") == docs.reference()


@pytest.mark.parametrize("drift", ["missing", "extra", "stale"])
def test_check_rejects_documentation_drift_without_writing(drift: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "docs").mkdir()
    readme = tmp_path / "README.md"
    readme.write_text(f"{docs.START}\n{docs.END}\n{docs.SCOPE_START}\n{docs.SCOPE_END}\n", encoding="utf-8")
    monkeypatch.setattr(docs, "REPO", tmp_path)
    assert docs.main([]) == 0
    content = readme.read_text(encoding="utf-8")
    changed = {
        "missing": content.replace("| `host list`", "| `missing command`"),
        "extra": content.replace(docs.END, "| `unshipped` | invalid |\n" + docs.END),
        "stale": content.replace("| Purpose |", "| Outdated |"),
    }[drift]
    readme.write_text(changed, encoding="utf-8")
    assert docs.main(["--check"]) == 1
    assert readme.read_text(encoding="utf-8") == changed
    assert docs.main([]) == 0
    assert docs.main(["--check"]) == 0


def test_readme_example_is_actual_offline_cli_output() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    command, expected = re.search(r"```console\n\$ falcon-axi (.*?)\n(.*?)```", readme, re.DOTALL).groups()
    scenario = next(entry for entry in scenarios() if entry["name"] == "detection-summary-empty")
    assert command.split() == scenario["argv"]
    stdout, code = replay(scenario)
    assert code == 0
    assert stdout == expected


@pytest.mark.parametrize("name", ["README.md", "CONTRIBUTING.md", "docs/read-only.md", "docs/design/README.md"])
def test_public_document_links_and_anchors_resolve(name: str) -> None:
    source = REPO / name
    for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", source.read_text(encoding="utf-8")):
        if "://" in link:
            continue
        path, _, anchor = link.partition("#")
        target = source.parent / unquote(path) if path else source
        assert target.is_file(), link
        if anchor:
            headings = re.findall(r"^#+ (.+)$", target.read_text(encoding="utf-8"), re.MULTILINE)
            slugs = {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-") for heading in headings}
            assert anchor in slugs, link


def test_package_description_matches_cli_description() -> None:
    package = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert package["project"]["description"] == DESCRIPTION
