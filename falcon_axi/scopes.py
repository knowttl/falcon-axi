"""`falcon-axi scopes`: the command-to-scope matrix, projected from the operation registry (§8.3).

It is local-only and authentication-free, and because it is generated from the registry it cannot
drift from what falcon-axi actually calls and cannot name a write scope beyond the one captain
exception N1 admits: no other registered operation has one (§4.3, §5.7).
"""

from typing import Any

from falcon_axi.domain import CommandOutput
from falcon_axi.render import raw
from falcon_axi.transport.operations import OPERATIONS, OperationId

#: Each command's operations; its required scope set is their union (§8.1).
COMMAND_OPERATIONS: tuple[tuple[str, tuple[OperationId, ...]], ...] = (
    ("detection list", ("GetQueriesAlertsV2", "PostEntitiesAlertsV2")),
    ("detection show", ("PostEntitiesAlertsV2",)),
    ("host list", ("QueryDevicesByFilter", "PostDeviceDetailsV2")),
    ("host show", ("PostDeviceDetailsV2",)),
    ("vuln list", ("combinedQueryVulnerabilities",)),
    ("cve show", ("GetVulnerabilities",)),
    ("search start", ("StartSearchV1",)),
    ("search status", ("GetSearchStatusV1",)),
    ("search stop", ("StopSearchV1",)),
)


def scope_rows() -> list[dict[str, str]]:
    """One row per registered scope, naming the commands that need it, in registry order."""
    commands: dict[str, list[str]] = {}
    for command, ids in COMMAND_OPERATIONS:
        for id in ids:
            for scope in OPERATIONS[id].scopes:
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
        "posture": raw("read-only except NG-SIEM search start and stop, the one write scope captain exception N1 admits"),
        "scopes": scope_rows(),
        "member_cid_token_scope": raw("unresolved (Flight Control read may be required; see design section 17.7)"),
    }
    return CommandOutput(
        value=value,
        help=(
            "Grant these scopes in the Falcon console under Support and resources > API clients and keys",
            "Grant read access only, apart from NGSIEM:write; falcon-axi needs no other write scope",
            "Omit NGSIEM:write to provision a wholly read-only client, and the `search` commands then fail with SCOPE_DENIED",
        ),
    )
