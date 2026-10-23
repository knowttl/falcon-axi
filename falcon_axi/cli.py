"""argv parsing, flag guard, dispatch, and exit codes (docs/design/v1.md §8, §10)."""

import os
import re
import shlex
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from falcon_axi.command import Invocation, limit_of
from falcon_axi.command import string as _str
from falcon_axi.command import suggestion_for as _suggestion_for
from falcon_axi.core import CliError
from falcon_axi.credentials import (
    Credential,
    read_only,
    resolve_credential,
)
from falcon_axi.data_protection import validate_sort as validate_data_protection_sort
from falcon_axi.fql import (
    DetectionQuery,
    since_seconds,
    window,
)
from falcon_axi.origin import REGIONS, assert_trusted_origin, resolve_base_url
from falcon_axi.policy import validate_policy_type
from falcon_axi.redaction import redact_text, redaction_scope
from falcon_axi.render import raw, render
from falcon_axi.shield import check_filters
from falcon_axi.skill import HOME_GUIDANCE, skill_hint
from falcon_axi.version import VERSION, version_output

DESCRIPTION = (
    "Read CrowdStrike Falcon detections, hosts, accounts, vulnerabilities, CVE intelligence, "
    "indicators, identities, and NG-SIEM searches from the shell"
)
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


@dataclass(frozen=True)
class Parsed:
    command: str
    flags: Mapping[str, str | bool]
    positionals: tuple[str, ...]


def _valid_flags(command: str) -> list[str]:
    from falcon_axi.commands import COMMAND_SPECS

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
    from falcon_axi.commands import COMMAND_SPECS, COMMANDS, SUBCOMMANDS
    from falcon_axi.cve import validate_cve_id
    from falcon_axi.domain import parse_fields
    from falcon_axi.identity import DEFAULT_SINCE as IDENTITY_DEFAULT_SINCE
    from falcon_axi.identity import (
        _identity_query_of,
        activity_query,
        parse_categories,
        rule_query,
        validate_entity_id,
        validate_identity_query,
    )
    from falcon_axi.walk import max_rows_of

    for name in (*GLOBAL_FLAGS, *(flag for spec in COMMAND_SPECS.values() for flag in spec.flags)):
        flag_guard(name)

    command: str = "home"
    index = 0
    first = argv[0] if argv else None
    if first in SUBCOMMANDS and not (
        first in COMMAND_SPECS and (len(argv) == 1 or (argv[1].startswith("-") and argv[1] != "--help"))
    ):
        noun = str(first)
        index = 1
        while noun in SUBCOMMANDS:
            child = argv[index] if len(argv) > index else None
            if child == "--help" and index == len(argv) - 1:
                return Parsed(noun, {"help": True}, ())
            if child not in SUBCOMMANDS[noun]:
                raise CliError(
                    "VALIDATION_ERROR",
                    f"unknown {noun} subcommand {child or ''}".strip(),
                    [f"valid {noun} subcommands: {', '.join(SUBCOMMANDS[noun])}"],
                )
            noun = f"{noun} {child}"
            index += 1
        command = noun
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
    if command in ("exclusion list", "exclusion show"):
        from falcon_axi.exclusion import validate_type

        validate_type(_str(flags.get("type")), limit_of(flags, spec) if spec and spec.limit_ceiling else 20)
    if command == "cve show":
        validate_cve_id(positionals[0])
    if command == "shield list":
        check_filters(flags)
    if (spec is None or spec.positional is None) and positionals:
        raise CliError(
            "VALIDATION_ERROR",
            f"`{command}` accepts no positional arguments",
            [f"valid flags for `{command}`: {', '.join(_valid_flags(command))}"],
        )
    max_rows_of(flags)
    if "limit" in flags:
        limit_of(flags, COMMAND_SPECS[command])
    if "wait" in flags:
        try:
            wait = int(str(flags["wait"]), 10)
        except ValueError:
            wait = 0
        if not 1 <= wait <= 50:
            raise CliError("VALIDATION_ERROR", "--wait must be an integer from 1 to 50 seconds")
    if "fields" in flags:
        assert spec is not None
        parse_fields(str(flags["fields"]), spec.extra_fields, spec.default_fields)
    if "filter" in flags and not str(flags["filter"]).strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    if command == "serverless list" and "filter" not in flags:
        raise CliError(
            "VALIDATION_ERROR",
            "serverless list requires --filter",
            ["Run `falcon-axi serverless list --filter \"cloud_provider:'aws'\"`"],
        )
    if command == "data-policy list" and flags.get("platform") not in ("win", "mac"):
        raise CliError(
            "VALIDATION_ERROR",
            "--platform is required: win or mac",
            ["Run `falcon-axi data-policy list --platform win` for Windows policies"],
        )
    if command in ("classification list", "data-policy list"):
        validate_data_protection_sort(_str(flags.get("sort")), command == "data-policy list")
    if "since" in flags:
        window(str(flags["since"]))
    if command in ("identity list", "identity assessment"):
        validate_identity_query(_identity_query_of(flags))
    if command == "identity rule list":
        rule_query(flags)
    if command in ("identity show", "identity timeline"):
        validate_entity_id(positionals[0])
    if command == "identity timeline":
        if "category" in flags:
            parse_categories(str(flags["category"]))
        since_seconds(_str(flags.get("since")) or IDENTITY_DEFAULT_SINCE)
    if command == "identity activity":
        activity_query(positionals[0])
    if command in ("ioc hosts", "ioc processes"):
        from falcon_axi.ioc import validate_observation

        validate_observation(positionals[0], command == "ioc processes", _str(flags.get("host")))
    if command in ("policy list", "policy members"):
        validate_policy_type(_str(flags.get("type")))
    if command == "process show":
        from falcon_axi.process import validate_process_id

        validate_process_id(positionals[0])
    if command == "sandbox list":
        from falcon_axi.sandbox import sandbox_filter

        sandbox_filter(_str(flags.get("sha256")), _str(flags.get("filter")))
    return Parsed(command, flags, tuple(positionals))


def help_text(command: str) -> str:
    from falcon_axi.commands import COMMAND_SPECS, SUBCOMMANDS

    if command in SUBCOMMANDS:
        return "\n".join(spec.summary for spec in COMMAND_SPECS.values() if spec.name.startswith(f"{command} "))
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
            "RTR execution requires profile opt-in, --execute, and exact host:command --confirm (N3). It",
            "requires Alerts:read, Hosts:read, Vulnerabilities:read, Vulnerabilities (Falcon Intelligence):read,",
            "NGSIEM:read, Identity Protection Entities:read, Identity Protection Timeline:read, and",
            "Identity Protection Assessment:read, plus two",
            "write-labelled scopes: NGSIEM:write for `search start`, `search stop`, and `identity activity`, and",
            "Identity Protection GraphQL:write for the fixed Identity Protection query commands,",
            "which Falcon requires even for read-only queries.",
            "The `account`, `asset`, `application`, and `login` commands need license-gated Assets:read.",
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
    from falcon_axi.detection import list_detections
    from falcon_axi.diagnostics import tenant_line

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
    if any(command.search(item) and "<original-filter>" in item for item in help):
        contextual += (
            "Replace <original-filter> with your original --filter value when continuing; CID filters are not echoed",
        )
    return contextual


def _run(
    argv: Sequence[str],
    transport: Any = None,
    env: Mapping[str, str] | None = None,
    bin: str | None = None,
    emit_preview: Callable[[str], None] | None = None,
) -> tuple[str, int]:
    """Returns the stdout document and the exit code. The transport is the only substitution point (§14.2)."""
    started = time.monotonic()
    from falcon_axi.commands import COMMAND_SPECS
    from falcon_axi.transport.budget import request_budget

    values = os.environ if env is None else env
    if transport is None:
        from falcon_axi.transport import http_transport

        transport = http_transport
    flags: Mapping[str, str | bool] = {}
    preview = ""
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
        deadline = started + int(str(flags["wait"])) if "wait" in flags else None
        with request_budget(deadline):
            resolved = None
            if spec.authentication != "none":
                resolved = _session(transport, flags, values, diagnostic=spec.authentication == "diagnostic")
            invocation = Invocation(
                spec,
                transport,
                flags,
                parsed.positionals,
                values,
                resolved.session if resolved else None,
                resolved.credential if resolved else None,
            )
            output = spec.handler(invocation)
            if parsed.command == "rtr run" and flags.get("execute"):
                from falcon_axi.rtr_run import execute

                preview = redact_text(render(output.value))
                if emit_preview is not None:
                    emit_preview(preview)
                    preview = ""
                output = execute(invocation)
        member_cid = resolved.session.member_cid if resolved else _str(flags.get("member-cid"))
        return preview + render(output.value, _followup_help(output.help, flags, member_cid)), 0
    except Exception as error:
        known = error if isinstance(error, CliError) else CliError("UNKNOWN", "an unexpected error occurred")
        return (
            preview
            + render(
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
    *,
    emit_preview: Callable[[str], None] | None = None,
) -> tuple[str, int]:
    version = version_output(argv)
    if version is not None:
        return version, 0
    with redaction_scope():
        stdout, exit_code = _run(argv, transport, env, bin, emit_preview)
        return redact_text(stdout), exit_code


def main() -> int:
    def emit_preview(document: str) -> None:
        sys.stdout.write(document)
        sys.stdout.flush()

    stdout = version_output(sys.argv[1:])
    exit_code = 0
    if stdout is None:
        stdout, exit_code = run(sys.argv[1:], bin=sys.argv[0] or "falcon-axi", emit_preview=emit_preview)
    sys.stdout.write(stdout)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
