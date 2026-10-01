"""argv parsing, flag guard, dispatch, and exit codes (docs/design/v1.md §8, §10)."""

import os
import re
import shlex
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from falcon_axi.core import CliError
from falcon_axi.credentials import Credential, resolve_credential, setup_help
from falcon_axi.cve import show_cve, validate_cve_id
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
    since_seconds,
)
from falcon_axi.host import QUERY_CEILING as HOSTS_CEILING
from falcon_axi.host import list_hosts, show_host
from falcon_axi.identity import DEFAULT_SINCE as IDENTITY_DEFAULT_SINCE
from falcon_axi.identity import (
    ENTITY_TYPES,
    TIMELINE_CATEGORIES,
    IdentityQuery,
    identity_timeline,
    list_identities,
    parse_categories,
    show_identity,
    validate_entity_id,
    validate_identity_query,
)
from falcon_axi.identity import QUERY_CEILING as IDENTITY_CEILING
from falcon_axi.origin import REGIONS, assert_trusted_origin, resolve_base_url
from falcon_axi.render import mask_cid, raw, render
from falcon_axi.scopes import scope_matrix
from falcon_axi.search import DEFAULT_REPOSITORY, DEFAULT_SINCE, search_status, start_search, stop_search
from falcon_axi.version import VERSION
from falcon_axi.vuln import EXTRA_FIELDS, list_vulnerabilities, parse_fields
from falcon_axi.vuln import QUERY_CEILING as SPOTLIGHT_CEILING

DESCRIPTION = "Read CrowdStrike Falcon detections, hosts, vulnerabilities, and NG-SIEM searches from the shell"
HOME_ROWS = 5

Command = Literal[
    "home",
    "detection list",
    "detection show",
    "host list",
    "host show",
    "vuln list",
    "cve show",
    "search start",
    "search status",
    "search stop",
    "identity list",
    "identity show",
    "identity timeline",
    "auth status",
    "scopes",
]

#: The subcommands each noun takes; the valid-command list and every suggestion derive from it (§11.2).
SUBCOMMANDS: Mapping[str, tuple[str, ...]] = {
    "detection": ("list", "show"),
    "host": ("list", "show"),
    "vuln": ("list",),
    "cve": ("show",),
    "search": ("start", "status", "stop"),
    "identity": ("list", "show", "timeline"),
    "auth": ("status",),
}

GLOBAL_FLAGS = ("help", "region", "allow-unknown-origin", "member-cid", "no-member-cid")

COMMAND_FLAGS: Mapping[str, tuple[str, ...]] = {
    "home": (),
    "detection list": ("filter", "severity", "status", "since", "limit", "cursor"),
    "detection show": ("full",),
    "host list": ("filter", "hostname", "platform", "status", "since", "limit", "cursor"),
    "host show": (),
    "vuln list": ("filter", "host", "severity", "status", "since", "limit", "cursor", "fields"),
    "cve show": (),
    "search start": ("query", "repository", "since"),
    "search status": ("repository",),
    "search stop": ("repository",),
    "identity list": ("name", "email", "domain", "type", "limit", "cursor"),
    "identity show": ("full",),
    "identity timeline": ("since", "category", "limit", "cursor"),
    "auth status": (),
    "scopes": (),
}

#: Each list command's row ceiling is the API's own documented maximum (§7.3).
LIMIT_CEILINGS: Mapping[str, tuple[int, str]] = {
    "detection list": (ALERTS_CEILING, "Alerts query"),
    "host list": (HOSTS_CEILING, "Hosts query"),
    "vuln list": (SPOTLIGHT_CEILING, "Spotlight query"),
    "identity list": (IDENTITY_CEILING, "falcon-mcp Identity Protection page"),
    "identity timeline": (IDENTITY_CEILING, "falcon-mcp Identity Protection page"),
}

#: Each command that takes exactly one identifier, with the line that says where to find one.
SHOW_COMMANDS: Mapping[str, tuple[str, str]] = {
    "detection show": ("detection identifier", "Run `falcon-axi detection list` to see current detection identifiers"),
    "host show": ("device identifier", "Run `falcon-axi host list` to see current device identifiers"),
    "cve show": ("CVE identifier", "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228"),
    "search status": ("search identifier", "A search identifier comes from `falcon-axi search start --query '<cql>'`"),
    "search stop": ("search identifier", "A search identifier comes from `falcon-axi search start --query '<cql>'`"),
    "identity show": ("identity id", "Run `falcon-axi identity list` to see current identity ids"),
    "identity timeline": ("identity id", "Run `falcon-axi identity list` to see current identity ids"),
}

#: The valid-command list every suggestion derives from, so none can name a command that does not exist.
COMMANDS: tuple[str, ...] = tuple(name for name in COMMAND_FLAGS if name != "home")

VALUE_FLAGS = frozenset(
    {
        "region",
        "member-cid",
        "filter",
        "severity",
        "status",
        "since",
        "limit",
        "cursor",
        "hostname",
        "platform",
        "host",
        "query",
        "repository",
        "fields",
        "name",
        "email",
        "domain",
        "type",
        "category",
    }
)

_SECRET_SHAPE = re.compile(r"(secret|password|token|key|passphrase)", re.IGNORECASE)


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
            [remedy],
        )
    if command == "cve show":
        validate_cve_id(positionals[0])
    if command not in SHOW_COMMANDS and positionals:
        raise CliError(
            "VALIDATION_ERROR",
            f"`{command}` accepts no positional arguments",
            [f"valid flags for `{command}`: {', '.join(_valid_flags(command))}"],
        )
    if "limit" in flags:
        _limit_of(flags, command)
    if "fields" in flags:
        parse_fields(str(flags["fields"]))
    if command == "identity list":
        validate_identity_query(_identity_query_of(flags))
    if command in ("identity show", "identity timeline"):
        validate_entity_id(positionals[0])
    if command == "identity timeline":
        if "category" in flags:
            parse_categories(str(flags["category"]))
        since_seconds(_str(flags.get("since")) or IDENTITY_DEFAULT_SINCE)
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


def _identity_query_of(flags: Mapping[str, str | bool]) -> IdentityQuery:
    return IdentityQuery(
        name=_str(flags.get("name")),
        email=_str(flags.get("email")),
        domain=_str(flags.get("domain")),
        type=_str(flags.get("type")),
    )


def _suggestion_for(command: str, flags: Mapping[str, str | bool], positionals: Sequence[str] = ()) -> str:
    """Replays every non-sensitive flag of this invocation into a next-page suggestion (§7.2)."""
    parts = ["falcon-axi", *command.split(), *positionals]
    for name in (
        "region",
        "filter",
        "hostname",
        "platform",
        "host",
        "severity",
        "status",
        "since",
        "limit",
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
    if flags.get("allow-unknown-origin"):
        parts.append("--allow-unknown-origin")
    return shlex.join(parts)


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
                "[--since <window>] [--filter <FQL>] [--limit N] [--cursor <token>] [--fields <names>]",
                "",
                "--host       device id (AID) whose vulnerabilities to read",
                f"--severity   one of {', '.join(VULN_SEVERITIES)}",
                f"--status     one of {', '.join(VULN_STATUSES)}",
                "--since      created_timestamp within a relative window such as 24h or 7d",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {SPOTLIGHT_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                f"--fields     extra columns, comma-separated: {', '.join(EXTRA_FIELDS)}",
                "",
                "Default columns are id, cve, severity, and hostname. --fields adds columns from that",
                "allowlist; an unknown name is refused and the valid names are listed.",
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
    if command == "cve show":
        return "\n".join(
            [
                "falcon-axi cve show <CVE-ID>",
                "",
                "Reads one CVE from Falcon Intelligence. It is not Spotlight host exposure:",
                "an empty result means CrowdStrike Intelligence has no entry, not that no host is affected.",
                "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228.",
                "",
                "Default fields are cve, severity, cvss_v3_score, exploit_status, publish_date, updated,",
                "and description. Related actor, report, threat, and affected-product lists are counts.",
                "This command does not expand those lists, and there is no cve list command.",
                "",
                "Example: falcon-axi cve show CVE-2021-44228",
                "",
                "This command is read-only and requires Vulnerabilities (Falcon Intelligence):read.",
                "That scope is license-gated. Spotlight's Vulnerabilities:read does not satisfy it, and a",
                "scope missing from the API client picker means the tenant has no Falcon Intelligence subscription.",
                "Whether --member-cid carries this scope is unverified.",
            ]
        )
    if command == "search start":
        return "\n".join(
            [
                "falcon-axi search start --query <CQL> [--repository <name>] [--since <window>]",
                "",
                "--query      the CQL search to run; required",
                f"--repository repository or view to search (default {DEFAULT_REPOSITORY})",
                f"--since      window to search, such as 24h or 7d (default {DEFAULT_SINCE})",
                "",
                "CQL is pipe-based and is neither FQL nor SQL: a filter, then commands.",
                "Start from a tag or field filter and pipe into commands, and bound the result set in the",
                "query itself with `| head(N)` or an aggregate; there is no --limit and no --cursor.",
                "Examples:",
                "  falcon-axi search start --query '#event_simpleName=ProcessRollup2 | head(5)'",
                "  falcon-axi search start --query '#event_simpleName=ProcessRollup2 "
                "| groupBy([ComputerName], function=count())' --since 7d",
                "",
                "This command starts a job on the tenant and requires NGSIEM:write, the one write scope",
                "falcon-axi asks for. Poll it with `falcon-axi search status <id>`.",
            ]
        )
    if command == "search status":
        return "\n".join(
            [
                "falcon-axi search status <search id> [--repository <name>]",
                "",
                f"--repository the repository the job was started against (default {DEFAULT_REPOSITORY})",
                "",
                "One call is one poll: it reports running, cancelled, or done, and carries the events once",
                "the job is done. Compare parsed_query with the query you sent, because NG-SIEM turns an",
                "unrecognised word into a free-text stage rather than an error.",
                "",
                "Example: falcon-axi search status abc123",
                "",
                "This command is read-only and requires only NGSIEM:read.",
            ]
        )
    if command == "search stop":
        return "\n".join(
            [
                "falcon-axi search stop <search id> [--repository <name>]",
                "",
                f"--repository the repository the job was started against (default {DEFAULT_REPOSITORY})",
                "",
                "Cancels one search job falcon-axi started. It changes no tenant data, no host, and no",
                "detection: the only thing it stops is the job.",
                "",
                "Example: falcon-axi search stop abc123",
                "",
                "This command requires NGSIEM:write, the one write scope falcon-axi asks for.",
            ]
        )
    if command == "identity list":
        return "\n".join(
            [
                "falcon-axi identity list [--name <pattern>] [--email <pattern>] [--domain <name>] "
                "[--type <kind>] [--limit N] [--cursor <token>]",
                "",
                "--name       display name pattern; `*` is a wildcard, so `Admin*` works",
                "--email      UPN or email pattern, for example `*@example.com`",
                "--domain     Active Directory domain to match",
                f"--type       one of {', '.join(ENTITY_TYPES)}; omit for both",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {IDENTITY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Lists the Falcon Identity Protection directory: users and endpoints with their risk. Filters",
                "combine with AND. Archived identities are excluded, and a bare `*` is refused.",
                "Examples:",
                "  falcon-axi identity list --name 'Admin*' --type user",
                "  falcon-axi identity list --email '*@example.com'",
                "",
                "This command sends only a fixed read-only Identity Protection query. It requires Identity Protection",
                "Entities:read and Identity Protection GraphQL:write; the GraphQL scope is labelled write because",
                "Falcon requires it even for reads (captain exception N2), and falcon-axi cannot change any identity.",
            ]
        )
    if command == "identity show":
        return "\n".join(
            [
                "falcon-axi identity show <identity id> [--full]",
                "",
                "--full       list every association; the default lists the first 25",
                "",
                "The identity id is an entity GUID, as printed by `falcon-axi identity list`. For an Active Directory",
                "user it is the account object GUID. Prints risk, risk factors, accounts, associations, and open",
                "incidents.",
                "",
                "Example: falcon-axi identity show 00000000-0000-0000-0000-000000000001",
                "",
                "This command sends only a fixed read-only Identity Protection query. It requires Identity Protection",
                "Entities:read and Identity Protection GraphQL:write (captain exception N2).",
            ]
        )
    if command == "identity timeline":
        return "\n".join(
            [
                "falcon-axi identity timeline <identity id> [--since <window>] [--category <names>] "
                "[--limit N] [--cursor <token>]",
                "",
                f"--since      relative window such as 24h or 7d (default {IDENTITY_DEFAULT_SINCE})",
                f"--category   comma-separated, from {', '.join(TIMELINE_CATEGORIES)}",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {IDENTITY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Prints the identity's recent activity, newest first: authentications, service access, LDAP and",
                "RPC activity, and alerts, each with its user, endpoint, and address.",
                "Examples:",
                "  falcon-axi identity timeline 00000000-0000-0000-0000-000000000001 --since 24h",
                "  falcon-axi identity timeline 00000000-0000-0000-0000-000000000001 --category threat,audit",
                "",
                "This command sends only a fixed read-only Identity Protection query. It requires Identity Protection",
                "Timeline:read and Identity Protection GraphQL:write (captain exception N2).",
            ]
        )
    if command == "scopes":
        return "\n".join(
            [
                "falcon-axi scopes",
                "",
                "Prints the command-to-scope matrix for provisioning the API client.",
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
            "  cve show <CVE-ID>         Falcon Intelligence detail for one CVE",
            "  search start              start an NG-SIEM CQL search job",
            "  search status <id>        poll one search job and read its events",
            "  search stop <id>          cancel one search job",
            "  identity list             list Identity Protection users and endpoints with their risk",
            "  identity show <id>        one identity's risk, accounts, associations, and open incidents",
            "  identity timeline <id>    one identity's recent activity",
            "  auth status               whether a credential resolved, and where to",
            "  scopes                    the command-to-scope matrix, with no request made",
            "",
            "Global flags:",
            "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
            "",
            f"Regions: {', '.join(REGIONS)}",
            "",
            "falcon-axi lists no command that changes a host, a detection, a policy, or an identity. It",
            "requires Alerts:read, Hosts:read, Vulnerabilities:read, Vulnerabilities (Falcon Intelligence):read,",
            "NGSIEM:read, Identity Protection Entities:read, and Identity Protection Timeline:read, plus two",
            "write-labelled scopes: NGSIEM:write for `search start` and `search stop`, and Identity Protection",
            "GraphQL:write for the `identity` commands, which Falcon requires even for read-only queries.",
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
    value["scopes"] = raw(
        "read scopes, plus NGSIEM:write for `search start` and `search stop`, "
        "and Identity Protection GraphQL:write for the `identity` commands, alone"
    )
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
    if command == "cve show":
        return show_cve(transport, resolved.session, parsed.positionals[0])
    if command == "search start":
        return start_search(
            transport,
            resolved.session,
            query=_str(flags.get("query")) or "",
            repository=_str(flags.get("repository")) or DEFAULT_REPOSITORY,
            since=_str(flags.get("since")) or DEFAULT_SINCE,
        )
    if command == "search status":
        return search_status(
            transport,
            resolved.session,
            parsed.positionals[0],
            repository=_str(flags.get("repository")) or DEFAULT_REPOSITORY,
        )
    if command == "search stop":
        return stop_search(
            transport,
            resolved.session,
            parsed.positionals[0],
            repository=_str(flags.get("repository")) or DEFAULT_REPOSITORY,
        )
    if command == "identity list":
        return list_identities(
            transport,
            resolved.session,
            query=_identity_query_of(flags),
            limit=_limit_of(flags, command),
            cursor=_str(flags.get("cursor")),
            credential=resolved.credential,
            suggestion=_suggestion_for(command, flags),
        )
    if command == "identity show":
        return show_identity(transport, resolved.session, parsed.positionals[0], bool(flags.get("full")))
    if command == "identity timeline":
        return identity_timeline(
            transport,
            resolved.session,
            parsed.positionals[0],
            since=_str(flags.get("since")) or IDENTITY_DEFAULT_SINCE,
            categories=(_str(flags.get("category")) or "",) if flags.get("category") else (),
            limit=_limit_of(flags, command),
            cursor=_str(flags.get("cursor")),
            credential=resolved.credential,
            suggestion=_suggestion_for(command, flags, parsed.positionals),
        )
    return list_vulnerabilities(
        transport,
        resolved.session,
        query=_vuln_query_of(flags),
        limit=_limit_of(flags, command),
        cursor=_str(flags.get("cursor")),
        credential=resolved.credential,
        suggestion=_suggestion_for(command, flags),
        fields=parse_fields(_str(flags.get("fields")) or "") if flags.get("fields") else (),
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
                "Run `falcon-axi cve show <CVE-ID>` for Falcon Intelligence on one CVE",
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
