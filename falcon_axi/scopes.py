"""`falcon-axi scopes`: the command-to-scope matrix, projected from operation and document registries (§8.3).

It is local-only and authentication-free, and because it is generated from the registry it cannot
drift from what falcon-axi actually calls and cannot name a write scope beyond the two the captain's exceptions
admit: no other registered operation has one (§4.3, §4.4, §5.7).
"""

from typing import Any

from falcon_axi.domain import CommandOutput
from falcon_axi.render import raw
from falcon_axi.transport.graphql import GRAPHQL_DOCUMENTS
from falcon_axi.transport.operations import OPERATIONS, OperationId

#: Each command's operations; GraphQL documents also contribute domain read scopes (§8.1).
COMMAND_OPERATIONS: tuple[tuple[str, tuple[OperationId, ...]], ...] = (
    ("detection list", ("GetQueriesAlertsV2", "PostEntitiesAlertsV2")),
    ("detection show", ("PostEntitiesAlertsV2",)),
    ("host list", ("QueryDevicesByFilter", "PostDeviceDetailsV2")),
    ("host show", ("PostDeviceDetailsV2",)),
    ("host logins", ("QueryDeviceLoginHistoryV2",)),
    ("account list", ("query_accounts", "get_accounts")),
    ("account show", ("get_accounts",)),
    ("vuln list", ("combinedQueryVulnerabilities",)),
    ("cve show", ("GetVulnerabilities",)),
    ("identity activity", ("StartSearchV1",)),
    ("search start", ("StartSearchV1",)),
    ("search status", ("GetSearchStatusV1",)),
    ("search stop", ("StopSearchV1",)),
    ("identity list", ("api_preempt_proxy_post_graphql",)),
    ("identity show", ("api_preempt_proxy_post_graphql",)),
    ("identity timeline", ("api_preempt_proxy_post_graphql",)),
)


def _command_scopes(command: str, ids: tuple[OperationId, ...]) -> list[str]:
    """An operation's own scopes, then the domain read scope of each GraphQL document the command sends."""
    scopes = [scope for id in ids for scope in OPERATIONS[id].scopes]
    scopes += [scope for entry in GRAPHQL_DOCUMENTS.values() if entry.command == command for scope in entry.read_scopes]
    return scopes


def scope_rows() -> list[dict[str, str]]:
    """One row per registered scope, naming the commands that need it, in registry order."""
    commands: dict[str, list[str]] = {}
    for command, ids in COMMAND_OPERATIONS:
        for scope in _command_scopes(command, ids):
            listed = commands.setdefault(scope, [])
            if command not in listed:
                listed.append(command)
    return [
        {
            "scope": scope,
            "access": "write" if scope.endswith(":write") else "read",
            "commands": ", ".join(named),
            "required": "yes",
        }
        for scope, named in commands.items()
    ]


def scope_matrix() -> CommandOutput:
    value: dict[str, Any] = {
        "posture": raw(
            "read-only except two write-labelled scopes: NGSIEM:write for NG-SIEM search start and stop "
            "(captain exception N1), and Identity Protection GraphQL:write for fixed read-only identity queries "
            "(captain exception N2)"
        ),
        "scopes": scope_rows(),
        "member_cid_token_scope": raw("unresolved (Flight Control read may be required; see design section 17.7)"),
    }
    return CommandOutput(
        value=value,
        help=(
            "Grant these scopes in the Falcon console under Support and resources > API clients and keys",
            "Grant read access only, apart from NGSIEM:write and Identity Protection GraphQL:write; "
            "falcon-axi needs no other write scope",
            "Identity Protection GraphQL:write is labelled write because Falcon requires it even for read-only queries; "
            "falcon-axi sends only its own fixed read queries, never caller-supplied GraphQL (captain exception N2)",
            "Omit NGSIEM:write and `search start` and `search stop` fail with SCOPE_DENIED",
            "Omit Identity Protection GraphQL:write and the `identity` commands fail with SCOPE_DENIED",
            "Assets:read is license-gated to Falcon Discover or Exposure Management; "
            "omit it and only the `account` commands fail with SCOPE_DENIED",
        ),
    )
