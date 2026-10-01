import re
import subprocess
import sys
from pathlib import Path

import pytest

from falcon_axi.core import CliError
from falcon_axi.transport.harness import mint_permit, send_permitted_request
from falcon_axi.transport.types import PreparedOperation
from scripts import architecture_check
from scripts.architecture_check import check

REPO = Path(__file__).resolve().parent.parent.parent

PREPARED = PreparedOperation(
    operation_id="GetQueriesAlertsV2", origin="https://api.crowdstrike.com", token="synthetic-token", query={}
)


def test_the_architecture_boundary_check_passes() -> None:
    assert check() is True


def test_the_sink_refuses_a_prepared_request_without_a_valid_permit() -> None:
    for forged in (object(), None, mint_permit().__class__()):
        with pytest.raises(CliError) as error:
            send_permitted_request(PREPARED, forged)  # type: ignore[arg-type]
        assert error.value.code == "READ_ONLY_VIOLATION"


def test_falconpy_is_imported_by_exactly_one_module() -> None:
    offenders = [
        path.relative_to(REPO)
        for path in sorted((REPO / "falcon_axi").rglob("*.py"))
        if path.name != "harness.py"
        and re.search(r"^\s*(import falconpy|from falconpy)", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert offenders == []


def test_no_mcp_dependency_reaches_the_package_or_the_lock() -> None:
    """falcon-mcp is ported from, never imported (docs/design/v1-python.md §2, §6)."""
    for relative in ("pyproject.toml", "uv.lock"):
        text = (REPO / relative).read_text(encoding="utf-8")
        assert 'name = "mcp"' not in text
        assert "falcon-mcp" not in text
    for path in (REPO / "falcon_axi").rglob("*.py"):
        assert not re.search(r"^\s*(import|from)\s+(falcon_)?mcp\b", path.read_text(encoding="utf-8"), re.MULTILINE)


def test_architecture_allows_the_offline_ci_workflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs: {verify: {steps: [{run: uv run scripts/verify.py}]}}", encoding="utf-8")
    monkeypatch.setattr(architecture_check, "REPO", tmp_path)
    assert check() is True


@pytest.mark.parametrize(
    "relative",
    [
        ".github/workflows/release.yml",
        ".github/workflows/ci.yaml",
        ".github/workflows/nested/release.yml",
        ".github/workflows/ci.yml/nested.yml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
    ],
)
def test_architecture_rejects_other_automation(relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = tmp_path / relative
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("jobs: {release: {steps: [{run: uv build}]}}", encoding="utf-8")
    monkeypatch.setattr(architecture_check, "REPO", tmp_path)
    with pytest.raises(AssertionError, match="automation configuration is not authorized"):
        check()


@pytest.mark.parametrize("name", ["FALCON_AXI_LIVE", "FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"])
def test_architecture_rejects_live_variables_in_ci(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"env: {{{name}: synthetic}}", encoding="utf-8")
    monkeypatch.setattr(architecture_check, "REPO", tmp_path)
    with pytest.raises(AssertionError, match="workflow references a live-suite or credential variable"):
        check()


def test_the_help_path_never_imports_falconpy_or_the_encoder() -> None:
    """AXI §10: version and help answer before the heavy imports load."""
    program = (
        "import sys; from falcon_axi.cli import parse, help_text; "
        "help_text(parse(['--help']).command); "
        "print('falconpy' in sys.modules, 'toon_format' in sys.modules)"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", program], capture_output=True, text=True, cwd=REPO, check=True
    )
    assert result.stdout.strip() == "False False"
