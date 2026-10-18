"""argv parsing, flag guard, dispatch, and exit codes (docs/design/v1.md §8, §10)."""

import os
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from falcon_axi.command import Invocation, limit_of
from falcon_axi.command import string as _str
from falcon_axi.command import suggestion_for as _suggestion_for
from falcon_axi.commands import COMMAND_SPECS, COMMANDS, SUBCOMMANDS
from falcon_axi.core import CliError
from falcon_axi.credentials import (
    Credential,
    read_only,
    resolve_credential,
)
from falcon_axi.cve import validate_cve_id
from falcon_axi.detection import list_detections
from falcon_axi.diagnostics import tenant_line
from falcon_axi.fql import (
    DetectionQuery,
    since_seconds,
    window,
)
from falcon_axi.identity import DEFAULT_SINCE as IDENTITY_DEFAULT_SINCE
from falcon_axi.identity import (
    _identity_query_of,
    activity_query,
    parse_categories,
    validate_entity_id,
    validate_identity_query,
)
from falcon_axi.origin import REGIONS, assert_trusted_origin, resolve_base_url
from falcon_axi.redaction import redact_text, redaction_scope
from falcon_axi.render import raw, render
from falcon_axi.skill import HOME_GUIDANCE, skill_hint
from falcon_axi.version import VERSION
from falcon_axi.vuln import parse_fields
from falcon_axi.walk import max_rows_of

DESCRIPTION = "Read CrowdStrike Falcon detections, hosts, vulnerabilities, and NG-SIEM searches from the shell"
HOME_ROWS = 5

GLOBAL_FLAGS = ("help", "region", "allow-unknown-origin", "member-cid", "no-member-cid", "config", "profile")
GLOBAL_VALUE_FLAGS = frozenset({"region", "config", "profile", "member-cid"})

_SECRET_SHAPE = re.compile(r"(secret|password|token|key|passphrase)", re.IGNORECASE)


def flag_guard(name: str) -> None:
    """No secret ever travels through argv (docs/design/v1.md §5.3).

    The member CID is a documented exception to this guard because it is an identifier rather than a
    credential, and the guard pattern deliberately does not match it.
    """
    if _SECRET_SHAPE.search(name):
        raise ValueError(f"secret-shaped flag --{name} is forbidden")


for _name in (*GLOBAL_FLAGS, *(flag for spec in COMMAND_SPECS.values() for flag in spec.flags)):
    flag_guard(_name)


@dataclass(frozen=True)
class Parsed:
    command: str
    flags: Mapping[str, str | bool]
    positionals: tuple[str, ...]


def _valid_flags(command: str) -> list[str]:
    spec = COMMAND_SPECS.get(command)
    return [f"--{name}" for name in (*GLOBAL_FLAGS, *(spec.flags if spec else ()))]


def _unknown_flag(name: str, command: str) -> CliError:
    valid = _valid_flags(command)
    guess = next(
        (candidate for candidate in valid if candidate[2:].startswith(name) or name.startswith(candidate[2:5])),
        None,
    )
    return CliError(
        "VALIDATION_ERROR",
        f"unknown flag --{name} for `{command}`",
        [
            *([f"Did you mean {guess}?"] if guess else []),
            f"valid flags for `{command}`: {', '.join(valid)}",
        ],
    )


def parse(argv: Sequence[str]) -> Parsed:
    command: str = "home"
    index = 0
    first = argv[0] if argv else None
    if first in SUBCOMMANDS:
        noun = str(first)
        second = argv[1] if len(argv) > 1 else None
        if second in SUBCOMMANDS[noun]:
            command = f"{noun} {second}"
            index = 2
        else:
            raise CliError(
                "VALIDATION_ERROR",
                f"unknown {noun} subcommand {second or ''}".strip(),
                [f"valid {noun} subcommands: {', '.join(SUBCOMMANDS[noun])}"],
            )
    elif first is not None and " " not in first and first in COMMAND_SPECS:
        command = str(first)
        index = 1
    elif first is not None and not first.startswith("-"):
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown command {first}",
            [
                f"valid commands: {', '.join(COMMANDS)}",
                "Run `falcon-axi --help` for the command list",
            ],
        )

    flags: dict[str, str | bool] = {}
    positionals: list[str] = []
    while index < len(argv):
        token = argv[index]
        if not token.startswith("--"):
            positionals.append(token)
            index += 1
            continue
        name, separator, inline = token[2:].partition("=")
        spec = COMMAND_SPECS.get(command)
        if name not in GLOBAL_FLAGS and (spec is None or name not in spec.flags):
            raise _unknown_flag(name, command)
        if name in GLOBAL_VALUE_FLAGS or (spec is not None and name in spec.value_flags):
            if separator:
                value: str | None = inline
            else:
                index += 1
                value = argv[index] if index < len(argv) else None
            if value is None or value == "" or value.startswith("--"):
                raise CliError("VALIDATION_ERROR", f"--{name} requires a value")
            flags[name] = value
        else:
            flags[name] = True
        index += 1

    if flags.get("help"):
        return Parsed(command, flags, tuple(positionals))
    if flags.get("member-cid") and flags.get("no-member-cid"):
        raise CliError(
            "VALIDATION_ERROR",
            "--member-cid and --no-member-cid cannot be combined",
            ["Use `--member-cid <cid>` to select a child tenant or `--no-member-cid` to clear an inherited selection"],
        )
    spec = COMMAND_SPECS.get(command)
    if spec and spec.positional and len(positionals) != 1:
        subject, remedy = spec.positional
        raise CliError(
            "VALIDATION_ERROR",
            f"{command} requires exactly one {subject}",
            [remedy],
        )
    if command == "cve show":
        validate_cve_id(positionals[0])
    if (spec is None or spec.positional is None) and positionals:
        raise CliError(
            "VALIDATION_ERROR",
            f"`{command}` accepts no positional arguments",
            [f"valid flags for `{command}`: {', '.join(_valid_flags(command))}"],
        )
    max_rows_of(flags)
    if "limit" in flags:
        limit_of(flags, COMMAND_SPECS[command])
    if "fields" in flags:
        parse_fields(str(flags["fields"]))
    if "filter" in flags and not str(flags["filter"]).strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    if "since" in flags:
        window(str(flags["since"]))
    if command == "identity list":
        validate_identity_query(_identity_query_of(flags))
    if command in ("identity show", "identity timeline"):
        validate_entity_id(positionals[0])
    if command == "identity timeline":
        if "category" in flags:
            parse_categories(str(flags["category"]))
        since_seconds(_str(flags.get("since")) or IDENTITY_DEFAULT_SINCE)
    if command == "identity activity":
        activity_query(positionals[0])
    return Parsed(command, flags, tuple(positionals))


def help_text(command: str) -> str:
    if command in COMMAND_SPECS:
        return COMMAND_SPECS[command].help
    return "\n".join(
        [
            f"falcon-axi {VERSION} - {DESCRIPTION}",
            "",
            "Commands:",
            *(spec.summary for spec in COMMAND_SPECS.values()),
            "",
            "Global flags:",
            "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
            "  --config <path>, --profile <name>",
            "",
            f"Regions: {', '.join(REGIONS)}",
            "",
            "falcon-axi lists no command that changes a host, a detection, a policy, or an identity. It",
            "requires Alerts:read, Hosts:read, Vulnerabilities:read, Vulnerabilities (Falcon Intelligence):read,",
            "NGSIEM:read, Identity Protection Entities:read, and Identity Protection Timeline:read, plus two",
            "write-labelled scopes: NGSIEM:write for `search start`, `search stop`, and `identity activity`, and",
            "Identity Protection GraphQL:write for `identity list`, `identity show`, and `identity timeline`,",
            "which Falcon requires even for read-only queries.",
            "The `account` commands also need Assets:read, a license-gated scope that only some tenants can grant.",
            "The `indicator` commands require the license-gated Indicators (Falcon Intelligence):read scope.",
        ]
    )


@dataclass(frozen=True)
class Resolved:
    session: Any
    credential: Credential


def _session(
    transport: Any,
    flags: Mapping[str, str | bool],
    env: Mapping[str, str],
    credential: Credential | None = None,
    *,
    diagnostic: bool = False,
) -> Resolved:
    from falcon_axi.auth import authenticate

    credential = credential or resolve_credential(
        env, config=_str(flags.get("config")), profile=_str(flags.get("profile")), diagnostic=diagnostic
    )
    allow_unknown_origin = bool(flags.get("allow-unknown-origin"))
    base_url = resolve_base_url(region=_str(flags.get("region")) or credential.region)
    assert_trusted_origin(base_url, allow_unknown_origin)
    return Resolved(
        session=authenticate(
            transport,
            credential=credential,
            base_url=base_url,
            member_cid=None if flags.get("no-member-cid") else _str(flags.get("member-cid")) or credential.member_cid,
            allow_unknown_origin=allow_unknown_origin,
        ),
        credential=credential,
    )


def _home_view(
    transport: Any, flags: Mapping[str, str | bool], env: Mapping[str, str], bin: str, hints: tuple[str, ...] = ()
) -> tuple[str, int]:
    head: dict[str, Any] = {"bin": bin, "description": DESCRIPTION}
    try:
        resolved = _session(transport, flags, env)
    except Exception as error:
        known = error if isinstance(error, CliError) else CliError("UNKNOWN", "an unexpected error occurred")
        return (
            render(
                {**head, "error": known.message, "code": known.code, **known.details},
                (*_followup_help(known.help, flags, _str(flags.get("member-cid"))), *hints),
            ),
            known.exit_code,
        )
    head["tenant"] = raw(tenant_line(resolved.session))
    listed = list_detections(
        transport,
        resolved.session,
        query=DetectionQuery(),
        limit=HOME_ROWS,
        credential=resolved.credential,
        suggestion=_suggestion_for("detection list", flags),
    )
    return (
        render(
            {**head, **listed.value},
            (
                *_followup_help(
                    [
                        *listed.help,
                        *HOME_GUIDANCE,
                    ],
                    flags,
                    resolved.session.member_cid,
                ),
                *hints,
            ),
        ),
        0,
    )


def _followup_help(help: Sequence[str], flags: Mapping[str, str | bool], member_cid: str | None) -> tuple[str, ...]:
    suffix = ""
    region = _str(flags.get("region"))
    if region:
        suffix += f" --region {shlex.quote(region)}"
    for name in ("config", "profile"):
        value = _str(flags.get(name))
        if value:
            suffix += f" --{name} {shlex.quote(value)}"
    for name in ("allow-unknown-origin", "no-member-cid"):
        if flags.get(name):
            suffix += f" --{name}"
    command = re.compile(r"`(falcon-axi .*)`", re.DOTALL)
    contextual = tuple(command.sub(lambda match: f"`{match.group(1)}{suffix}`", item) for item in help)
    if member_cid and any(command.search(item) for item in help):
        contextual += ("Supply the same tenant selection used for this invocation when following these suggestions",)
    return contextual


def _run(
    argv: Sequence[str],
    transport: Any = None,
    env: Mapping[str, str] | None = None,
    bin: str | None = None,
) -> tuple[str, int]:
    """Returns the stdout document and the exit code. The transport is the only substitution point (§14.2)."""
    values = os.environ if env is None else env
    if transport is None:
        from falcon_axi.transport import http_transport

        transport = http_transport
    flags: Mapping[str, str | bool] = {}
    try:
        parsed = parse(argv)
        flags = parsed.flags
        if parsed.flags.get("help"):
            return f"{help_text(parsed.command)}\n", 0
        forced_read_only = read_only(values)
        if forced_read_only and parsed.command in ("search start", "search stop", "identity activity"):
            raise CliError("READ_ONLY_VIOLATION", "FALCON_AXI_READ_ONLY forbids search lifecycle changes")
        if parsed.command == "home":
            return _home_view(transport, parsed.flags, values, bin or "falcon-axi", skill_hint(values) if not argv else ())
        spec = COMMAND_SPECS[parsed.command]
        resolved = None
        if spec.authentication != "none":
            resolved = _session(transport, flags, values, diagnostic=spec.authentication == "diagnostic")
        output = spec.handler(
            Invocation(
                spec,
                transport,
                flags,
                parsed.positionals,
                values,
                resolved.session if resolved else None,
                resolved.credential if resolved else None,
            )
        )
        member_cid = resolved.session.member_cid if resolved else _str(flags.get("member-cid"))
        return render(output.value, _followup_help(output.help, flags, member_cid)), 0
    except Exception as error:
        known = error if isinstance(error, CliError) else CliError("UNKNOWN", "an unexpected error occurred")
        return (
            render(
                {"error": known.message, "code": known.code, **known.details},
                _followup_help(known.help, flags, _str(flags.get("member-cid"))),
            ),
            known.exit_code,
        )


def run(
    argv: Sequence[str],
    transport: Any = None,
    env: Mapping[str, str] | None = None,
    bin: str | None = None,
) -> tuple[str, int]:
    with redaction_scope():
        stdout, exit_code = _run(argv, transport, env, bin)
        return redact_text(stdout), exit_code


def main() -> int:
    stdout, exit_code = run(sys.argv[1:], bin=sys.argv[0] or "falcon-axi")
    sys.stdout.write(stdout)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
