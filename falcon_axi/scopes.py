"""`falcon-axi scopes`: the command-to-scope matrix, projected from operation and document registries (§8.3).

It is local-only and authentication-free, and because it is generated from the registry it cannot
drift from what falcon-axi actually calls and cannot name a write scope beyond the two the captain's exceptions
admit: no other registered operation has one (§4.3, §4.4, §5.7).
"""

from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.domain import CommandOutput
from falcon_axi.render import raw
from falcon_axi.transport.graphql import GRAPHQL_DOCUMENTS
from falcon_axi.transport.operations import OPERATIONS, OperationId


def _command_scopes(command: str, ids: tuple[OperationId, ...]) -> list[str]:
    """An operation's own scopes, then the domain read scope of each GraphQL document the command sends."""
    scopes = [scope for id in ids for scope in OPERATIONS[id].scopes]
    scopes += [scope for entry in GRAPHQL_DOCUMENTS.values() if entry.command == command for scope in entry.read_scopes]
    return scopes


def scope_rows() -> list[dict[str, str]]:
    """One row per registered scope, naming the commands that need it, in registry order."""
    commands: dict[str, list[str]] = {}
    from falcon_axi.commands import COMMAND_SPECS

    for spec in COMMAND_SPECS.values():
        command, ids = spec.name, spec.operations
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
            "read-only except two write-labelled scopes: NGSIEM:write for NG-SIEM search start and stop and identity activity "
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
            "Omit NGSIEM:write and `search start`, `search stop`, and `identity activity` fail with SCOPE_DENIED",
            "Omit Identity Protection GraphQL:write and `identity list`, `identity show`, `identity timeline`, "
            "and `identity assessment` "
            "fail with SCOPE_DENIED",
            "Assets:read is license-gated to Falcon Discover or Exposure Management; "
            "omit it and only the `account` commands fail with SCOPE_DENIED",
        ),
    )


def _scopes(ctx: Invocation) -> CommandOutput:
    return scope_matrix()


COMMAND_SPECS = (
    CommandSpec(
        name="scopes",
        help="\n".join(
            [
                "falcon-axi scopes",
                "",
                "Prints the command-to-scope matrix for provisioning the API client.",
                "It is local only: it makes no request and needs no credential.",
            ]
        ),
        summary="  scopes                    the command-to-scope matrix, with no request made",
        handler=_scopes,
        operations=(),
        authentication="none",
    ),
)
