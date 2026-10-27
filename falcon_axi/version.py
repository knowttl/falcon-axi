"""Leaf module: version probes answer before the command graph loads."""

import platform
import sys
from collections.abc import Sequence

#: Kept in step with pyproject.toml by an offline test.
VERSION = "0.7.5"  # x-release-please-version


def version_output(argv: Sequence[str]) -> str | None:
    if len(argv) == 1 and argv[0] in ("-v", "-V", "--version"):
        return f"{VERSION}\n"
    return None


def user_agent() -> str:
    return f"falcon-axi/{VERSION} (Python/{platform.python_version()}; {sys.platform})"
