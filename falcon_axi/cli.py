"""argv parsing, flag guard, dispatch, and exit codes (docs/design/v1.md §8, §10)."""

import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from falcon_axi.core import CliError
from falcon_axi.credentials import Credential, resolve_credential, setup_help
from falcon_axi.detection import QUERY_CEILING as ALERTS_CEILING
from falcon_axi.detection import list_detections, show_detection
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput
from falcon_axi.fql import (
    HOST_STATUSES,
    PLATFORMS,
    SEVERITIES,
    STATUSES,
    VULN_SEVERITIES,
    VULN_STATUSES,
    DetectionQuery,
    HostQuery,
    VulnQuery,
)
from falcon_axi.host import QUERY_CEILING as HOSTS_CEILING
from falcon_axi.host import list_hosts, show_host
from falcon_axi.origin import REGIONS, assert_trusted_origin, resolve_base_url
from falcon_axi.render import mask_cid, raw, render
from falcon_axi.scopes import scope_matrix
from falcon_axi.version import VERSION
from falcon_axi.vuln import QUERY_CEILING as SPOTLIGHT_CEILING
from falcon_axi.vuln import list_vulnerabilities

DESCRIPTION = "Read CrowdStrike Falcon detections, hosts, and vulnerabilities from the shell (read-only)"
HOME_ROWS = 5

Command = Literal[
    "home",
    "detection list",
    "detection show",
    "host list",
    "host show",
    "vuln list",
    "auth status",
    "scopes",
]

#: The subcommands each noun takes; the valid-command list and every suggestion derive from it (§11.2).
SUBCOMMANDS: Mapping[str, tuple[str, ...]] = {
    "detection": ("list", "show"),
    "host": ("list", "show"),
    "vuln": ("list",),
    "auth": ("status",),
}

GLOBAL_FLAGS = ("help", "region", "allow-unknown-origin", "member-cid", "no-member-cid")

COMMAND_FLAGS: Mapping[str, tuple[str, ...]] = {
    "home": (),
    "detection list": ("filter", "severity", "status", "since", "limit", "cursor"),
    "detection show": ("full",),
    "host list": ("filter", "hostname", "platform", "status", "since", "limit", "cursor"),
    "host show": (),
    "vuln list": ("filter", "host", "severity", "status", "since", "limit", "cursor"),
    "auth status": (),
    "scopes": (),
}

#: Each list command's row ceiling is the API's own documented maximum (§7.3).
LIMIT_CEILINGS: Mapping[str, tuple[int, str]] = {
    "detection list": (ALERTS_CEILING, "Alerts query"),
    "host list": (HOSTS_CEILING, "Hosts query"),
    "vuln list": (SPOTLIGHT_CEILING, "Spotlight query"),
}

#: `<noun> show` takes exactly one identifier, and names where to find one when it is missing.
SHOW_COMMANDS: Mapping[str, tuple[str, str]] = {
    "detection show": ("detection identifier", "falcon-axi detection list"),
    "host show": ("device identifier", "falcon-axi host list"),
}

#: The valid-command list every suggestion derives from, so none can name a command that does not exist.
COMMANDS: tuple[str, ...] = tuple(name for name in COMMAND_FLAGS if name != "home")

VALUE_FLAGS = frozenset(
    {"region", "member-cid", "filter", "severity", "status", "since", "limit", "cursor", "hostname", "platform", "host"}
)

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
    if first in SUBCOMMANDS:
        noun = str(first)
        second = argv[1] if len(argv) > 1 else None
        if second in SUBCOMMANDS[noun]:
            command = f"{noun} {second}"  # type: ignore[assignment]
            index = 2
        else:
            raise CliError(
                "VALIDATION_ERROR",
                f"unknown {noun} subcommand {second or ''}".strip(),
                [f"valid {noun} subcommands: {', '.join(SUBCOMMANDS[noun])}"],
            )
    elif first == "scopes":
        command = "scopes"
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
    if command in SHOW_COMMANDS and len(positionals) != 1:
        subject, remedy = SHOW_COMMANDS[command]
        raise CliError(
            "VALIDATION_ERROR",
            f"{command} requires exactly one {subject}",
            [f"Run `{remedy}` to see current {subject}s"],
        )
    if command not in SHOW_COMMANDS and positionals:
        raise CliError(
            "VALIDATION_ERROR",
            f"`{command}` accepts no positional arguments",
            [f"valid flags for `{command}`: {', '.join(_valid_flags(command))}"],
        )
    if "limit" in flags:
        _limit_of(flags, command)
    return Parsed(command, flags, tuple(positionals))


def _limit_of(flags: Mapping[str, str | bool], command: str) -> int:
    ceiling, source = LIMIT_CEILINGS[command]
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
                f"Run `falcon-axi {command} --limit {DEFAULT_LIMIT}` for the default page",
            ],
        )
    return parsed


def _str(value: str | bool | None) -> str | None:
    return value if isinstance(value, str) else None


def _detection_query_of(flags: Mapping[str, str | bool]) -> DetectionQuery:
    return DetectionQuery(
        filter=_str(flags.get("filter")),
        severity=_str(flags.get("severity")),
        status=_str(flags.get("status")),
        since=_str(flags.get("since")),
    )


def _host_query_of(flags: Mapping[str, str | bool]) -> HostQuery:
    return HostQuery(
        filter=_str(flags.get("filter")),
        hostname=_str(flags.get("hostname")),
        platform=_str(flags.get("platform")),
        status=_str(flags.get("status")),
        since=_str(flags.get("since")),
    )


def _vuln_query_of(flags: Mapping[str, str | bool]) -> VulnQuery:
    return VulnQuery(
        filter=_str(flags.get("filter")),
        host=_str(flags.get("host")),
        severity=_str(flags.get("severity")),
        status=_str(flags.get("status")),
        since=_str(flags.get("since")),
    )


def _suggestion_for(command: str, flags: Mapping[str, str | bool]) -> str:
    """Replays every non-sensitive flag of this invocation into a next-page suggestion (§7.2)."""
    parts = [f"falcon-axi {command}"]
    for name in ("region", "filter", "hostname", "platform", "host", "severity", "status", "since", "limit"):
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
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {ALERTS_CEILING})",
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
    if command == "host list":
        return "\n".join(
            [
                "falcon-axi host list [--hostname <name>] [--platform <name>] [--status <name>] "
                "[--since <window>] [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--hostname   hostname to match; Hosts filters accept wildcards, so WIN-* works",
                f"--platform   one of {', '.join(PLATFORMS)}",
                f"--status     one of {', '.join(HOST_STATUSES)}",
                "--since      last_seen within a relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted, relative dates are lowercase",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {HOSTS_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Filterable fields include hostname, platform_name, os_version, agent_version, status,",
                "last_seen, first_seen, machine_domain, and local_ip.",
                "Examples:",
                "  falcon-axi host list --platform windows --since 24h",
                "  falcon-axi host list --filter \"hostname:'WIN-*'+platform_name:'Windows'\"",
                "",
                "This command is read-only and requires only Hosts:read. It reports containment status as",
                "data and cannot change it.",
            ]
        )
    if command == "host show":
        return "\n".join(
            [
                "falcon-axi host show <device id>",
                "",
                "The device id is the agent id Falcon calls the AID, as printed by `falcon-axi host list`.",
                "",
                "Example: falcon-axi host show abc123",
                "",
                "This command is read-only and requires only Hosts:read.",
            ]
        )
    if command == "vuln list":
        return "\n".join(
            [
                "falcon-axi vuln list [--host <device id>] [--severity <name>] [--status <name>] "
                "[--since <window>] [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--host       device id (AID) whose vulnerabilities to read",
                f"--severity   one of {', '.join(VULN_SEVERITIES)}",
                f"--status     one of {', '.join(VULN_STATUSES)}",
                "--since      created_timestamp within a relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {SPOTLIGHT_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "A filter is required, from a shorthand flag or --filter, because Spotlight requires one.",
                "Wildcards are unsupported and a `*` is refused before the request is made.",
                "Filterable fields include aid, cve.id, cve.severity, cve.exprt_rating, cve.exploit_status,",
                "status, and created_timestamp.",
                "Examples:",
                "  falcon-axi vuln list --severity critical --status open",
                "  falcon-axi vuln list --filter \"status:'open'+cve.exploit_status:'90'\"",
                "",
                "This command is read-only and requires only Vulnerabilities:read.",
            ]
        )
    if command == "scopes":
        return "\n".join(
            [
                "falcon-axi scopes",
                "",
                "Prints the command-to-scope matrix for provisioning a read-only API client.",
                "It is local only: it makes no request and needs no credential.",
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
            "  host list                 list hosts from the Falcon Hosts collection",
            "  host show <device id>     the full detail for one host",
            "  vuln list                 list Spotlight vulnerabilities; a filter is required",
            "  auth status               whether a credential resolved, and where to",
            "  scopes                    the command-to-scope matrix, with no request made",
            "",
            "Global flags:",
            "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
            "",
            f"Regions: {', '.join(REGIONS)}",
            "",
            "falcon-axi is read-only: it lists no mutating command and requires only Alerts:read,",
            "Hosts:read, and Vulnerabilities:read.",
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


def _read(transport: Any, parsed: Parsed, resolved: Resolved) -> CommandOutput:
    command = parsed.command
    flags = parsed.flags
    if command == "detection list":
        return list_detections(
            transport,
            resolved.session,
            query=_detection_query_of(flags),
            limit=_limit_of(flags, command),
            cursor=_str(flags.get("cursor")),
            credential=resolved.credential,
            suggestion=_suggestion_for(command, flags),
        )
    if command == "detection show":
        return show_detection(transport, resolved.session, parsed.positionals[0], bool(flags.get("full")))
    if command == "host list":
        return list_hosts(
            transport,
            resolved.session,
            query=_host_query_of(flags),
            limit=_limit_of(flags, command),
            cursor=_str(flags.get("cursor")),
            credential=resolved.credential,
            suggestion=_suggestion_for(command, flags),
        )
    if command == "host show":
        return show_host(transport, resolved.session, parsed.positionals[0])
    return list_vulnerabilities(
        transport,
        resolved.session,
        query=_vuln_query_of(flags),
        limit=_limit_of(flags, command),
        cursor=_str(flags.get("cursor")),
        credential=resolved.credential,
        suggestion=_suggestion_for(command, flags),
    )


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
                "Run `falcon-axi host list --filter \"hostname:'WIN-*'\"` to search hosts",
                "Run `falcon-axi scopes` to see what this API client needs",
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
        if parsed.command == "scopes":
            matrix = scope_matrix()
            return render(matrix.value, matrix.help), 0
        if parsed.command == "auth status":
            value, help = _auth_status(transport, parsed.flags, values)
            return render(value, help), 0
        resolved = _session(transport, parsed.flags, values)
        output = _read(transport, parsed, resolved)
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
