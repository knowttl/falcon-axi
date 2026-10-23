"""Closed N3 command grammar and strict profile policy, independent of credentials."""

import re
import shlex
from dataclasses import dataclass
from typing import Any

from falcon_axi.core import CliError

COMMANDS = frozenset(
    {
        "cat",
        "cd",
        "clear",
        "csrutil",
        "env",
        "eventlog",
        "filehash",
        "getsid",
        "help",
        "history",
        "ifconfig",
        "ipconfig",
        "ls",
        "mount",
        "netstat",
        "ps",
        "reg query",
        "users",
    }
)
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
