#!/usr/bin/env python3
"""The local architecture boundary (docs/design/v1.md §3.3 property 6, §14.5, §15.4).

Run by `uv run scripts/verify.py` and asserted again by tests/offline/test_architecture.py.
It adds the falconpy-confinement assertions of docs/design/v1-python.md §3.2 to the network,
process-execution, and automation-configuration rules stage 1 already enforced.
"""

import ast
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "falcon_axi"
NETWORK_SINK = PACKAGE / "transport" / "harness.py"
SINK_FUNCTION = "send_permitted_request"

NETWORK_MODULES = {"falconpy", "requests", "http", "httpx", "socket", "urllib", "urllib3", "ssl", "ftplib", "telnetlib"}
#: `urllib.parse` is pure string handling and reaches no network; `urllib.request` does.
ALLOWED_SUBMODULES = {"urllib.parse"}
PROCESS_MODULES = {"subprocess", "multiprocessing", "pty"}
NETWORK_REFERENCE = re.compile(r"\.command\s*\(|requests\.\w+\s*\(|urlopen\s*\(")
AUTOMATION_PATHS = (".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "Jenkinsfile")


def _sources() -> list[Path]:
    return sorted(path for path in PACKAGE.rglob("*.py"))


def _imported_modules(tree: ast.AST) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _network_imports(modules: set[str]) -> set[str]:
    return {module for module in modules if module not in ALLOWED_SUBMODULES and module.split(".")[0] in NETWORK_MODULES}


def _sink_function(tree: ast.AST) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == SINK_FUNCTION:
            return node
    raise AssertionError(f"{NETWORK_SINK.name} no longer defines {SINK_FUNCTION}")


def check() -> bool:
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imported = _imported_modules(tree)
        forbidden = {module for module in imported if module.split(".")[0] in PROCESS_MODULES}
        if forbidden:
            raise AssertionError(f"process execution is forbidden: {path} imports {', '.join(sorted(forbidden))}")
        if path == NETWORK_SINK:
            # falconpy's command() accepts every Falcon operation id, mutating ones included, so
            # exactly one name may be imported from it, and only this function may call it.
            names = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module == "falconpy"
                for alias in node.names
            }
            if names != {"APIHarnessV2"}:
                raise AssertionError(f"{path} may import only APIHarnessV2 from falconpy, found {sorted(names)}")
            body = ast.get_source_segment(text, _sink_function(tree)) or ""
            outside = text.replace(body, "")
            if NETWORK_REFERENCE.search(outside):
                raise AssertionError(f"network reference outside {SINK_FUNCTION}: {path}")
            continue
        reached = _network_imports(imported)
        if reached:
            raise AssertionError(f"network import outside the sealed sink: {path} imports {', '.join(sorted(reached))}")
        if NETWORK_REFERENCE.search(text):
            raise AssertionError(f"network reference outside the sealed sink: {path}")

    # The captain's directive bans automation that could carry a credential at all, which is strictly
    # stronger than scanning those paths for FALCON_AXI_LIVE or the credential variable names (§15.4).
    for relative in AUTOMATION_PATHS:
        if (REPO / relative).exists():
            raise AssertionError(f"automation configuration is not authorized in this repository: {relative}")
    return True


if __name__ == "__main__":
    check()
    sys.stdout.write("architecture boundary ok\n")
