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
AUTOMATION_PATHS = (".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "Jenkinsfile")
WORKFLOW_DIRECTORY = ".github/workflows"
CREDENTIAL_NAMES = (
    "FALCON_AXI_LIVE",
    "FALCON_CLIENT_ID",
    "FALCON_CLIENT_SECRET",
    "FALCON_AXI_CLIENT_ID",
    "FALCON_AXI_CLIENT_SECRET",
)


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
        if path != PACKAGE / "setup.py":
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "write_text",
                    "write_bytes",
                    "mkdir",
                    "unlink",
                    "rename",
                    "touch",
                    "chmod",
                    "remove",
                    "rmdir",
                    "makedirs",
                    "symlink",
                    "symlink_to",
                    "hardlink_to",
                }:
                    raise AssertionError(f"local file mutation outside setup.py: {path}")
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "open"
                    or isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"open", "fdopen"}
                    and ast.unparse(node.func) != "os.open"
                ):
                    mode_index = 0 if isinstance(node.func, ast.Attribute) and node.func.attr == "open" else 1
                    mode = (
                        node.args[mode_index]
                        if len(node.args) > mode_index
                        else next((item.value for item in node.keywords if item.arg == "mode"), ast.Constant("r"))
                    )
                    if not isinstance(mode, ast.Constant) or any(flag in str(mode.value) for flag in "wax+"):
                        raise AssertionError(f"writable file open outside setup.py: {path}")
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "write"
                    and ast.unparse(node.func.value) not in {"sys.stdout", "sys.stderr"}
                ):
                    raise AssertionError(f"local file write outside setup.py: {path}")
                if (
                    isinstance(node.func, ast.Attribute)
                    and ast.unparse(node.func) == "os.open"
                    and any(
                        isinstance(flag, ast.Attribute)
                        and flag.attr in {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
                        for flag in ast.walk(node)
                    )
                ):
                    raise AssertionError(f"writable file open outside setup.py: {path}")
        forbidden = {module for module in imported if module.split(".")[0] in PROCESS_MODULES}
        if forbidden and path not in {PACKAGE / "private_file.py", NETWORK_SINK}:
            raise AssertionError(f"process execution is forbidden: {path} imports {', '.join(sorted(forbidden))}")
        if path == NETWORK_SINK:
            calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and ast.unparse(node.func).startswith("subprocess.")
            ]
            if forbidden != {"subprocess"} or len(calls) != 1 or ast.unparse(calls[0].func) != "subprocess.run":
                raise AssertionError("the network sink permits only one fixed request-worker invocation")
            call = calls[0]
            if (
                not call.args
                or ast.unparse(call.args[0]) != "[sys.executable, '-P', '-m', 'falcon_axi.transport.harness']"
                or not any(
                    item.arg == "timeout" and ast.unparse(item.value) == "remaining_seconds()" for item in call.keywords
                )
                or any(item.arg == "shell" for item in call.keywords)
            ):
                raise AssertionError("the request-worker command and remaining-budget timeout must be fixed")
        if path == PACKAGE / "private_file.py":
            process_imports = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                and any(name.split(".")[0] in PROCESS_MODULES for name in _imported_modules(node))
            ]
            if (
                len(process_imports) != 1
                or not isinstance(process_imports[0], ast.Import)
                or [(alias.name, alias.asname) for alias in process_imports[0].names] != [("subprocess", None)]
            ):
                raise AssertionError("private file checks may import only subprocess without aliases")
            scripts = [
                node.value
                for node in tree.body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "ACL_SCRIPT" for target in node.targets)
            ]
            if len(scripts) != 1 or not isinstance(scripts[0], ast.Constant) or not isinstance(scripts[0].value, str):
                raise AssertionError("the ACL diagnostic must be a literal script")
            calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ]
            runs = [node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "run"]
            if len(runs) != 1 or any(
                isinstance(node.func, ast.Attribute) and node.func.attr not in {"run", "TimeoutExpired"} for node in calls
            ):
                raise AssertionError("private file checks permit only one fixed PowerShell invocation")
            args = runs[0].args[0]
            if (
                not isinstance(args, ast.List)
                or [ast.literal_eval(item) for item in args.elts[:-1]]
                != [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                ]
                or not isinstance(args.elts[-1], ast.Name)
                or args.elts[-1].id != "ACL_SCRIPT"
            ):
                raise AssertionError("private file ACL command must be fixed")
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

    for relative in AUTOMATION_PATHS:
        if (REPO / relative).exists():
            raise AssertionError(f"automation configuration is not authorized in this repository: {relative}")
    for workflow in sorted((REPO / WORKFLOW_DIRECTORY).glob("*")):
        if workflow.name not in {"ci.yml", "release-please.yml"} or not workflow.is_file():
            raise AssertionError(f"automation configuration is not authorized in this repository: {workflow}")
        named = [name for name in CREDENTIAL_NAMES if name in workflow.read_text(encoding="utf-8")]
        if named:
            raise AssertionError(f"workflow references a live-suite or credential variable: {workflow} names {named}")
    return True


if __name__ == "__main__":
    check()
    sys.stdout.write("architecture boundary ok\n")
