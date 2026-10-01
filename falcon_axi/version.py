"""Leaf module: no import beyond the stdlib, so `--help` stays off the heavy import path."""

import platform
import sys

#: Kept in step with pyproject.toml by an offline test.
VERSION = "0.3.0"


def user_agent() -> str:
    return f"falcon-axi/{VERSION} (Python/{platform.python_version()}; {sys.platform})"
