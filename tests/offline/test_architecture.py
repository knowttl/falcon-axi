import re
import subprocess
import sys
from pathlib import Path

import pytest

from falcon_axi.core import CliError
from falcon_axi.transport.harness import mint_permit, send_permitted_request
from falcon_axi.transport.types import PreparedOperation
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


def test_this_repository_carries_no_automation_workflow() -> None:
    assert not (REPO / ".github/workflows").exists()


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
