"""argv parsing, flag guard, dispatch, and exit codes (docs/design/v1.md §8, §10)."""

import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from falcon_axi.core import CliError
from falcon_axi.credentials import Credential, resolve_credential, setup_help
from falcon_axi.detection import DEFAULT_LIMIT, QUERY_CEILING, list_detections, show_detection
from falcon_axi.fql import SEVERITIES, STATUSES, DetectionQuery
from falcon_axi.origin import REGIONS, assert_trusted_origin, resolve_base_url
from falcon_axi.render import mask_cid, raw, render
from falcon_axi.version import VERSION

DESCRIPTION = "Read CrowdStrike Falcon detections from the shell (read-only)"
HOME_ROWS = 5

Command = Literal["home", "detection list", "detection show", "auth status"]

GLOBAL_FLAGS = ("help", "region", "allow-unknown-origin", "member-cid", "no-member-cid")

COMMAND_FLAGS: Mapping[str, tuple[str, ...]] = {
    "home": (),
    "detection list": ("filter", "severity", "status", "since", "limit", "cursor"),
    "detection show": ("full",),
    "auth status": (),
}

VALUE_FLAGS = frozenset({"region", "member-cid", "filter", "severity", "status", "since", "limit", "cursor"})

_SECRET_SHAPE = re.compile(r"(secret|password|token|key|passphrase)", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s")


def flag_guard(name: str) -> None:
    """No secret ever travels through argv (docs/design/v1.md §5.3).

    The member CID is a documented exception to this guard because it is an identifier rather than a
    credential, and the guard pattern deliberately does not match it.
    """
    if _SECRET_SHAPE.search(name):
        raise ValueError(f"secret-shaped flag --{name} is forbidden")


for _name in (*GLOBAL_FLAGS, *(flag for flags in COMMAND_FLAGS.values() for flag in flags)):
    flag_guard(_name)


@dataclass(frozen=True)
class Parsed:
    command: Command
    flags: Mapping[str, str | bool]
    positionals: tuple[str, ...]


def _valid_flags(command: str) -> list[str]:
    return [f"--{name}" for name in (*GLOBAL_FLAGS, *COMMAND_FLAGS[command])]


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
    command: Command = "home"
    index = 0
    first = argv[0] if argv else None
    if first == "detection":
        second = argv[1] if len(argv) > 1 else None
        if second in ("list", "show"):
            command = f"detection {second}"  # type: ignore[assignment]
            index = 2
        else:
            raise CliError(
                "VALIDATION_ERROR",
                f"unknown detection subcommand {second or ''}".strip(),
                ["valid detection subcommands: list, show"],
            )
    elif first == "auth":
        second = argv[1] if len(argv) > 1 else None
        if second == "status":
            command = "auth status"
            index = 2
        else:
            raise CliError(
                "VALIDATION_ERROR",
                f"unknown auth subcommand {second or ''}".strip(),
                ["valid auth subcommands: status"],
            )
    elif first is not None and not first.startswith("-"):
        raise CliError(
            "VALIDATION_ERROR",
            f"unknown command {first}",
            [
                "valid commands: detection list, detection show, auth status",
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
        if name == "profile":
            raise CliError(
                "VALIDATION_ERROR",
                "profile configuration is not implemented in stage 1",
                ["Select a region with `--region` and a tenant with `--member-cid` or FALCON_MEMBER_CID"],
            )
        if name not in GLOBAL_FLAGS and name not in COMMAND_FLAGS[command]:
            raise _unknown_flag(name, command)
        if name in VALUE_FLAGS:
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
    if command == "detection show" and len(positionals) != 1:
        raise CliError(
            "VALIDATION_ERROR",
            "detection show requires exactly one detection identifier",
            ["Run `falcon-axi detection list` to see current detection identifiers"],
        )
    if command != "detection show" and positionals:
        raise CliError(
            "VALIDATION_ERROR",
            f"`{command}` accepts no positional arguments",
            [f"valid flags for `{command}`: {', '.join(_valid_flags(command))}"],
        )
    if "limit" in flags:
        _limit_of(flags)
    return Parsed(command, flags, tuple(positionals))


def _limit_of(flags: Mapping[str, str | bool]) -> int:
    value = flags.get("limit")
    if value is None:
        return DEFAULT_LIMIT
    try:
        parsed = int(str(value), 10)
    except ValueError:
        parsed = -1
    if parsed < 1 or parsed > QUERY_CEILING:
        raise CliError(
            "VALIDATION_ERROR",
            f"--limit must be an integer from 1 to {QUERY_CEILING}",
            [
                f"{QUERY_CEILING} is the documented Alerts query ceiling",
                f"Run `falcon-axi detection list --limit {DEFAULT_LIMIT}` for the default page",
            ],
        )
    return parsed


def _str(value: str | bool | None) -> str | None:
    return value if isinstance(value, str) else None


def _query_of(flags: Mapping[str, str | bool]) -> DetectionQuery:
    return DetectionQuery(
        filter=_str(flags.get("filter")),
        severity=_str(flags.get("severity")),
        status=_str(flags.get("status")),
        since=_str(flags.get("since")),
    )


def _suggestion_for(command: str, flags: Mapping[str, str | bool]) -> str:
    """Replays every non-sensitive flag of this invocation into a next-page suggestion (§7.2)."""
    parts = [f"falcon-axi {command}"]
    for name in ("region", "filter", "severity", "status", "since", "limit"):
        value = flags.get(name)
        if isinstance(value, str):
            quoted = f'"{value}"' if _WHITESPACE.search(value) else value
            parts.append(f"--{name} {quoted}")
    if flags.get("allow-unknown-origin"):
        parts.append("--allow-unknown-origin")
    return " ".join(parts)


def _member_cid_of(flags: Mapping[str, str | bool], env: Mapping[str, str]) -> str | None:
    if flags.get("no-member-cid"):
        return None
    return _str(flags.get("member-cid")) or env.get("FALCON_MEMBER_CID") or None


def help_text(command: str) -> str:
    if command == "detection list":
        return "\n".join(
            [
                "falcon-axi detection list [--severity <name>] [--status <name>] [--since <window>] "
                "[--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                f"--severity   one of {', '.join(SEVERITIES)}",
                f"--status     one of {', '.join(STATUSES)}",
                "--since      relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted, relative dates are lowercase",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Filterable fields include severity_name, status, tactic, technique, created_timestamp, and device.hostname.",
                "Examples:",
                "  falcon-axi detection list --severity high --since 24h",
                "  falcon-axi detection list --filter \"severity_name:'Critical'+status:'new'\"",
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        )
    if command == "detection show":
        return "\n".join(
            [
                "falcon-axi detection show <composite id> [--full]",
                "",
                "--full       print long fields such as the command line without truncation",
                "",
                'Example: falcon-axi detection show "ldt:aid:1234"',
                "",
                "This command is read-only and requires only Alerts:read.",
            ]
        )
    if command == "auth status":
        return "\n".join(
            [
                "falcon-axi auth status",
                "",
                "Reports whether a credential resolved, from which channel, and which region it resolved to.",
                "No credential value, bearer token, or tenant CID is ever printed.",
            ]
        )
    return "\n".join(
        [
            f"falcon-axi {VERSION} - {DESCRIPTION}",
            "",
            "Commands:",
            "  detection list            list detections from the Falcon Alerts collection",
            "  detection show <id>       the full detail for one detection",
            "  auth status               whether a credential resolved, and where to",
            "",
            "Global flags:",
            "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
            "",
            f"Regions: {', '.join(REGIONS)}",
            "",
            "falcon-axi is read-only: it lists no mutating command and requires only Alerts:read for the",
            "commands stage 1 ships. Host and vulnerability domains are not implemented yet.",
        ]
    )


@dataclass(frozen=True)
class Resolved:
    session: Any
    credential: Credential


def _session(transport: Any, flags: Mapping[str, str | bool], env: Mapping[str, str]) -> Resolved:
    from falcon_axi.auth import authenticate

    credential = resolve_credential(env)
    if not credential:
        raise CliError("AUTH_REQUIRED", "no Falcon credential found", setup_help(env))
    allow_unknown_origin = bool(flags.get("allow-unknown-origin"))
    base_url = resolve_base_url(region=_str(flags.get("region")), env_base_url=env.get("FALCON_BASE_URL"))
    assert_trusted_origin(base_url, allow_unknown_origin)
    return Resolved(
        session=authenticate(
            transport,
            credential=credential,
            base_url=base_url,
            member_cid=_member_cid_of(flags, env),
            allow_unknown_origin=allow_unknown_origin,
        ),
        credential=credential,
    )


def _tenant_line(active: Any) -> str:
    region = active.region or "an unlisted Falcon cloud"
    retarget = f" (re-targeted from {active.retargeted_from})" if active.retargeted_from else ""
    if active.member_cid:
        return f"{region}{retarget} member CID {mask_cid(active.member_cid)}"
    return f"{region}{retarget} (own CID unavailable)"


def _auth_status(transport: Any, flags: Mapping[str, str | bool], env: Mapping[str, str]) -> tuple[dict[str, Any], list[str]]:
    credential = resolve_credential(env)
    if not credential:
        return {"credential_resolved": False}, list(setup_help(env))
    resolved = _session(transport, flags, env)
    limit = resolved.session.rate_limit.limit
    remaining = resolved.session.rate_limit.remaining
    value: dict[str, Any] = {"credential_resolved": True, "credential_channel": credential.channel}
    if credential.path:
        value["credential_path"] = credential.path
    value["tenant"] = raw(_tenant_line(resolved.session))
    value["scopes"] = raw("read-only client recommended; falcon-axi requests no write scope")
    if limit is not None and remaining is not None:
        value["rate_limit"] = raw(f"{remaining} of {limit} requests remaining")
    return value, ["Run `falcon-axi detection list` to read detections with this credential"]


def _home_view(transport: Any, flags: Mapping[str, str | bool], env: Mapping[str, str], bin: str) -> tuple[str, int]:
    head: dict[str, Any] = {"bin": bin, "description": DESCRIPTION}
    try:
        resolved = _session(transport, flags, env)
    except Exception as error:
        known = error if isinstance(error, CliError) else CliError("UNKNOWN", "an unexpected error occurred")
        return render({**head, "error": known.message, "code": known.code, **known.details}, known.help), known.exit_code
    head["tenant"] = raw(_tenant_line(resolved.session))
    listed = list_detections(
        transport,
        resolved.session,
        query=DetectionQuery(),
        limit=HOME_ROWS,
        credential=resolved.credential,
        suggestion="falcon-axi detection list",
    )
    return (
        render(
            {**head, **listed.value},
            [
                *listed.help,
                "Run `falcon-axi detection list` to see more detections",
                "Run `falcon-axi auth status` to check the credential and region",
            ],
        ),
        0,
    )


def run(
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
    try:
        parsed = parse(argv)
        if parsed.flags.get("help"):
            return f"{help_text(parsed.command)}\n", 0
        if parsed.command == "home":
            return _home_view(transport, parsed.flags, values, bin or "falcon-axi")
        if parsed.command == "auth status":
            value, help = _auth_status(transport, parsed.flags, values)
            return render(value, help), 0
        resolved = _session(transport, parsed.flags, values)
        if parsed.command == "detection list":
            output = list_detections(
                transport,
                resolved.session,
                query=_query_of(parsed.flags),
                limit=_limit_of(parsed.flags),
                cursor=_str(parsed.flags.get("cursor")),
                credential=resolved.credential,
                suggestion=_suggestion_for("detection list", parsed.flags),
            )
        else:
            output = show_detection(transport, resolved.session, parsed.positionals[0], bool(parsed.flags.get("full")))
        return render(output.value, output.help), 0
    except Exception as error:
        known = error if isinstance(error, CliError) else CliError("UNKNOWN", "an unexpected error occurred")
        return render({"error": known.message, "code": known.code, **known.details}, known.help), known.exit_code


def main() -> int:
    stdout, exit_code = run(sys.argv[1:], bin=sys.argv[0] or "falcon-axi")
    sys.stdout.write(stdout)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
