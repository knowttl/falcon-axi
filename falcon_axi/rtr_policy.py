"""Closed N3 command grammar and strict profile policy, independent of credentials."""

import re
import shlex
from dataclasses import dataclass
from typing import Any

from falcon_axi.core import CliError

# The platforms on which each command was verified to run through the command API.
# Falcon answers a command that the host's platform lacks with "Command not found", so availability is per platform.
# Verified on one Windows and one Linux host; macOS was not tested, and csrutil, a macOS command, ran on neither.
# The interactive console also has help, clear and history, which the command API rejects on every tested platform.
COMMAND_PLATFORMS: dict[str, tuple[str, ...]] = {
    "cat": ("windows", "linux"),
    "cd": ("windows", "linux"),
    "csrutil": (),
    "env": ("windows", "linux"),
    "eventlog": ("windows",),
    "filehash": ("windows", "linux"),
    "getsid": ("windows",),
    "ifconfig": ("linux",),
    "ipconfig": ("windows",),
    "ls": ("windows", "linux"),
    "mount": ("windows", "linux"),
    "netstat": ("windows", "linux"),
    "ps": ("windows", "linux"),
    "reg query": ("windows",),
    "users": ("linux",),
}
COMMANDS = frozenset(COMMAND_PLATFORMS)
_AVAILABILITY_LINES = {
    ("windows", "linux"): "Verified on both Windows and Linux: {}.",
    ("windows",): "Verified on Windows only: {}.",
    ("linux",): "Verified on Linux only: {}.",
    (): "Accepted on neither Windows nor Linux, because it is a macOS command and macOS was not tested: {}.",
}


def platform_availability() -> tuple[str, ...]:
    """One line per availability group, shared by the command help and the skill."""
    lines = []
    for platforms, template in _AVAILABILITY_LINES.items():
        names = sorted(name for name, found in COMMAND_PLATFORMS.items() if found == platforms)
        if names:
            lines.append(template.format(", ".join(names)))
    return tuple(lines)


EXECUTION_SECONDS = 50
CLEANUP_SECONDS = 10
OUTPUT_BYTES = 64 * 1024
OUTPUT_CHUNKS = 64
RESPONSE_BYTES = 1024 * 1024
COMMAND_BYTES = 4096


@dataclass(frozen=True)
class RtrPolicy:
    enabled: bool = False
    commands: frozenset[str] = COMMANDS


def profile_policy(value: Any) -> RtrPolicy:
    if value is None:
        return RtrPolicy()
    if not isinstance(value, dict) or set(value) - {"enabled", "commands"} or type(value.get("enabled")) is not bool:
        raise CliError("CONFIG_INVALID", "rtr requires a boolean enabled and optional commands subset")
    commands = value.get("commands", sorted(COMMANDS))
    if not isinstance(commands, list) or any(not isinstance(item, str) or item not in COMMANDS for item in commands):
        raise CliError("CONFIG_INVALID", "rtr.commands must be a subset of the fixed read-only command set")
    return RtrPolicy(value["enabled"], frozenset(commands))


def parse_command(command: str, allowed: frozenset[str] = COMMANDS) -> str:
    if not allowed <= COMMANDS:
        raise CliError("CONFIG_INVALID", "RTR command restriction cannot widen the standard set")
    if (
        not command
        or len(command.encode("utf-8")) > COMMAND_BYTES
        or any(ord(char) < 32 or ord(char) == 127 for char in command)
        or any(char in command for char in ";|&<>`$\u0085\u2028\u2029")
    ):
        raise CliError("VALIDATION_ERROR", "RTR requires one command without shell syntax or control characters")
    try:
        # Preserve Windows backslashes. Quotes only group RTR data; nothing reaches a shell.
        tokens = shlex.split(command, posix=False)
    except ValueError as error:
        raise CliError("VALIDATION_ERROR", "RTR command has unmatched quotes") from error
    if not tokens:
        raise CliError("VALIDATION_ERROR", "RTR command is empty")
    if any(("(" in token or ")" in token) and not (token[0] in "\"'" and token[-1] == token[0]) for token in tokens):
        raise CliError("VALIDATION_ERROR", "RTR parentheses require a quoted data argument")
    base = "reg query" if tokens[:2] == ["reg", "query"] else tokens[0]
    if base not in allowed:
        raise CliError("READ_ONLY_VIOLATION", "RTR command is outside the effective read-only command set")
    if base == "eventlog" and (len(tokens) < 2 or tokens[1] not in {"view", "list"}):
        raise CliError("READ_ONLY_VIOLATION", "eventlog permits only view and list")
    # csrutil and mount also have modifying native-shell forms. RTR accepts only its read-only responder.
    return "reg" if base == "reg query" else base


def validate_host(host: str) -> None:
    if re.fullmatch(r"[a-fA-F0-9]{32}", host) is None:
        raise CliError("VALIDATION_ERROR", "RTR requires one 32-character device id")


def cat_size_command(command: str, allowed: frozenset[str]) -> str | None:
    tokens = shlex.split(command, posix=False)
    if len(tokens) != 2 or tokens[0] != "cat" or "ls" not in allowed:
        return None
    path = tokens[1].strip("\"'")
    if not path or path.startswith("-") or any(char in path for char in "*?[]"):
        return None
    listing = "ls " + tokens[1]
    parse_command(listing, allowed)
    return listing
