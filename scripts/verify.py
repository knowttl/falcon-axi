#!/usr/bin/env python3
"""The single local entry point for the complete offline required-check set (§14.5, §15.4).

`uv run scripts/verify.py` runs ruff, mypy --strict, the architecture boundary check, and the
offline pytest suite. It must stay offline: the suite refuses to open a socket.
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

STEPS: tuple[tuple[str, list[str]], ...] = (
    ("ruff", ["ruff", "check", "falcon_axi", "scripts", "tests"]),
    ("ruff format", ["ruff", "format", "--check", "falcon_axi", "scripts", "tests"]),
    ("mypy", ["mypy", "--strict", "falcon_axi", "scripts"]),
    ("architecture", [sys.executable, "scripts/architecture_check.py"]),
    ("pytest", [sys.executable, "-m", "pytest", "tests/offline", "-q"]),
)


def main() -> int:
    for name, command in STEPS:
        sys.stdout.write(f"verify: {name}\n")
        sys.stdout.flush()
        result = subprocess.run(command, cwd=REPO)  # noqa: S603
        if result.returncode != 0:
            sys.stdout.write(f"verify: {name} failed\n")
            return result.returncode
    sys.stdout.write("verify: ok\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
