"""Command declarations and the invocation data their handlers consume."""

from __future__ import annotations

import shlex
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from falcon_axi.core import CliError

if TYPE_CHECKING:
    from falcon_axi.auth import Session
    from falcon_axi.credentials import Credential
    from falcon_axi.domain import CommandOutput
    from falcon_axi.transport.operations import OperationId
    from falcon_axi.transport.types import Transport


def string(value: str | bool | None) -> str | None:
    return value if isinstance(value, str) else None


def suggestion_for(command: str, flags: Mapping[str, str | bool], positionals: Sequence[str] = ()) -> str:
    """Replay query-shaping flags into a next-page suggestion (§7.2)."""
    parts = ["falcon-axi", *command.split(), *positionals]
    if flags.get("all"):
        parts.append("--all")
    for name in (
        "filter",
        "hostname",
        "platform",
        "host",
        "severity",
        "status",
        "product",
        "since",
        "limit",
        "max-rows",
        "fields",
        "name",
        "email",
        "domain",
        "type",
        "category",
    ):
        value = flags.get(name)
        if isinstance(value, str):
            parts.extend((f"--{name}", value))
    return shlex.join(parts)


@dataclass(frozen=True)
class CommandSpec:
    name: str
    help: str
    summary: str
    handler: Callable[[Invocation], CommandOutput]
    operations: tuple[OperationId, ...]
    flags: tuple[str, ...] = ()
    value_flags: tuple[str, ...] = ()
    limit_ceiling: tuple[int, str] | None = None
    positional: tuple[str, str] | None = None
    authentication: Literal["none", "standard", "diagnostic"] = "standard"


def limit_of(flags: Mapping[str, str | bool], spec: CommandSpec) -> int:
    from falcon_axi.domain import DEFAULT_LIMIT

    assert spec.limit_ceiling is not None
    ceiling, source = spec.limit_ceiling
    value = flags.get("limit")
    if value is None:
        return DEFAULT_LIMIT
    try:
        parsed = int(str(value), 10)
    except ValueError:
        parsed = -1
    if parsed < 1 or parsed > ceiling:
        raise CliError(
            "VALIDATION_ERROR",
            f"--limit must be an integer from 1 to {ceiling}",
            [
                f"{ceiling} is the documented {source} ceiling",
                f"Run `falcon-axi {spec.name} --limit {DEFAULT_LIMIT}` for the default page",
            ],
        )
    return parsed


@dataclass(frozen=True)
class Invocation:
    spec: CommandSpec
    transport: Transport
    flags: Mapping[str, str | bool]
    positionals: tuple[str, ...]
    env: Mapping[str, str]
    _session: Session | None = None
    _credential: Credential | None = None

    @property
    def session(self) -> Session:
        assert self._session is not None
        return self._session

    @property
    def credential(self) -> Credential:
        assert self._credential is not None
        return self._credential

    def text(self, name: str) -> str | None:
        return string(self.flags.get(name))

    @property
    def limit(self) -> int:
        return limit_of(self.flags, self.spec)

    @property
    def suggestion(self) -> str:
        return suggestion_for(self.spec.name, self.flags, self.positionals)
