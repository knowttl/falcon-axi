"""The complete scoped-operation surface of falcon-axi v1 (docs/design/v1.md §2.1, §3.3).

The union is closed: adding a member requires both §2.2 citations in the same change.
When falcon-mcp has no tool for the operation, the second citation is falconpy's generated
endpoint table plus another first-party CrowdStrike SDK (PSFalcon), not a missing falcon-mcp row.

The read tier admits only read-scoped operations. Captain exceptions N1 and N2 admit the two
write-labelled effects defined below (docs/design/v1.md §4.3, §4.4); each is confined to its own
id allowlist and scope, and N2 additionally requires fixed read-only query documents.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, get_args

from falcon_axi.core import CliError

OperationId = Literal[
    "GetQueriesAlertsV2",
    "PostEntitiesAlertsV2",
    "QueryDevicesByFilter",
    "PostDeviceDetailsV2",
    "combinedQueryVulnerabilities",
    "GetVulnerabilities",
    "QueryDeviceLoginHistoryV2",
    "query_accounts",
    "get_accounts",
    "StartSearchV1",
    "GetSearchStatusV1",
    "StopSearchV1",
    "api_preempt_proxy_post_graphql",
]

OPERATION_IDS: tuple[str, ...] = get_args(OperationId)

Effect = Literal["read", "search-lifecycle", "graphql-query"]
EFFECTS: tuple[str, ...] = get_args(Effect)

#: The whole of captain exception N1 (docs/design/v1.md §4.3): the only ids whose effect may be
#: `search-lifecycle`, and so the only ids that may cite a write scope. `GetSearchStatusV1` is not
#: a member because it is an ordinary `NGSIEM:read` read of a job falcon-axi already started.
SEARCH_LIFECYCLE_IDS: frozenset[str] = frozenset({"StartSearchV1", "StopSearchV1"})

#: The one write scope N1 admits; the N2 scope is confined to the separate GraphQL tier.
SEARCH_LIFECYCLE_SCOPES: tuple[str, ...] = ("NGSIEM:write",)


#: The whole of captain exception N2 (docs/design/v1.md §4.4): the only id whose effect may be
#: `graphql-query`. It is write-labelled because Falcon scopes the one Identity Protection GraphQL
#: endpoint `WRITE` even for a read-only query, and the same endpoint also accepts mutations.
#: falcon-axi therefore never sends caller-supplied GraphQL: only the fixed query documents in
#: `falcon_axi/transport/graphql.py` reach it.
GRAPHQL_QUERY_IDS: frozenset[str] = frozenset({"api_preempt_proxy_post_graphql"})

#: The one write-labelled scope N2 admits. The per-document `:read` scopes live with the documents.
GRAPHQL_QUERY_SCOPES: tuple[str, ...] = ("Identity Protection GraphQL:write",)


@dataclass(frozen=True)
class Evidence:
    doc_url: str
    doc_scope: str
    #: Second citation (§2.2). falcon-mcp when it has a tool; otherwise falconpy's generated
    #: endpoint table plus PSFalcon. The field name is the historical citation.
    falcon_mcp: str


@dataclass(frozen=True)
class FalconOperation:
    id: OperationId
    method: Literal["GET", "POST", "DELETE"]
    path: str
    scopes: tuple[str, ...]
    effect: Effect
    evidence: Evidence


ALERTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/alerts/"
HOSTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/hosts/"
SPOTLIGHT_DOC = "https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/"
INTEL_DOC = "https://developer.crowdstrike.com/api-reference/collections/intel/"
DISCOVER_DOC = "https://developer.crowdstrike.com/api-reference/collections/discover/"
NGSIEM_DOC = "https://developer.crowdstrike.com/api-reference/collections/ngsiem/"
IDENTITY_PROTECTION_DOC = "https://developer.crowdstrike.com/api-reference/collections/identity-protection/"

CANONICAL: tuple[FalconOperation, ...] = (
    FalconOperation(
        id="GetQueriesAlertsV2",
        method="GET",
        path="/alerts/queries/alerts/v2",
        scopes=("Alerts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=ALERTS_DOC,
            doc_scope="Alerts: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps GetQueriesAlertsV2 to Alerts:read for search_detections",
        ),
    ),
    FalconOperation(
        id="PostEntitiesAlertsV2",
        method="POST",
        path="/alerts/entities/alerts/v2",
        scopes=("Alerts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=ALERTS_DOC,
            doc_scope="Alerts: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps PostEntitiesAlertsV2 to Alerts:read "
                "as the hydrate step of search_detections"
            ),
        ),
    ),
    FalconOperation(
        id="QueryDevicesByFilter",
        method="GET",
        path="/devices/queries/devices/v1",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps QueryDevicesByFilter to Hosts:read for search_hosts",
        ),
    ),
    FalconOperation(
        id="PostDeviceDetailsV2",
        method="POST",
        path="/devices/entities/devices/v2",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps PostDeviceDetailsV2 to Hosts:read for search_hosts and get_host_details"
            ),
        ),
    ),
    FalconOperation(
        id="combinedQueryVulnerabilities",
        method="GET",
        path="/spotlight/combined/vulnerabilities/v1",
        scopes=("Vulnerabilities:read",),
        effect="read",
        evidence=Evidence(
            doc_url=SPOTLIGHT_DOC,
            doc_scope="Vulnerabilities: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps combinedQueryVulnerabilities to "
                "Vulnerabilities:read for search_vulnerabilities"
            ),
        ),
    ),
    FalconOperation(
        id="GetVulnerabilities",
        method="POST",
        path="/intel/entities/vulnerabilities/GET/v1",
        scopes=("Vulnerabilities (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Vulnerabilities (Falcon Intelligence): READ",
            falcon_mcp=(
                "falcon-mcp has no tool for GetVulnerabilities. "
                "falconpy/_endpoint/_intel.py maps GetVulnerabilities to POST "
                "/intel/entities/vulnerabilities/GET/v1. PSFalcon Get-FalconCve wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="QueryDeviceLoginHistoryV2",
        method="POST",
        path="/devices/combined/devices/login-history/v2",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for QueryDeviceLoginHistoryV2. "
                "falconpy/_endpoint/_hosts.py maps QueryDeviceLoginHistoryV2 to POST "
                "/devices/combined/devices/login-history/v2. PSFalcon Get-FalconHost -Login wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="query_accounts",
        method="GET",
        path="/discover/queries/accounts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for query_accounts. "
                "falconpy/_endpoint/_discover.py maps query_accounts to GET /discover/queries/accounts/v1. "
                "PSFalcon Get-FalconAsset -Account wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="get_accounts",
        method="GET",
        path="/discover/entities/accounts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for get_accounts. "
                "falconpy/_endpoint/_discover.py maps get_accounts to GET /discover/entities/accounts/v1. "
                "PSFalcon Get-FalconAsset -Account -Id wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="StartSearchV1",
        method="POST",
        path="/humio/api/v1/repositories/{repository}/queryjobs",
        scopes=SEARCH_LIFECYCLE_SCOPES,
        effect="search-lifecycle",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: WRITE",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps StartSearchV1 to NGSIEM:write for search_ngsiem",
        ),
    ),
    FalconOperation(
        id="GetSearchStatusV1",
        method="GET",
        path="/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        scopes=("NGSIEM:read",),
        effect="read",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetSearchStatusV1 to NGSIEM:read as the poll step of search_ngsiem"
            ),
        ),
    ),
    FalconOperation(
        id="StopSearchV1",
        method="DELETE",
        path="/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        scopes=SEARCH_LIFECYCLE_SCOPES,
        effect="search-lifecycle",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: WRITE",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps StopSearchV1 to NGSIEM:write for search_ngsiem cleanup",
        ),
    ),
    FalconOperation(
        id="api_preempt_proxy_post_graphql",
        method="POST",
        path="/identity-protection/combined/graphql/v1",
        scopes=GRAPHQL_QUERY_SCOPES,
        effect="graphql-query",
        evidence=Evidence(
            doc_url=IDENTITY_PROTECTION_DOC,
            doc_scope="Identity Protection GraphQL: WRITE",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps api_preempt_proxy_post_graphql to Identity Protection "
                "Entities, Timeline, Detections, and Assessment :read plus Identity Protection GraphQL:write "
                "for idp_investigate_entity, which builds only `query` documents"
            ),
        ),
    ),
)

#: Routes whose shape marks a Falcon mutation; no registered operation may match one (§3.3 property 5).
MUTATION_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/entities/[^/]+/action", re.IGNORECASE),
    re.compile(r"/queries/[^/]+/action", re.IGNORECASE),
    re.compile(r"/real-time-response/", re.IGNORECASE),
)

_READ_SCOPE = re.compile(r":\s*READ$", re.IGNORECASE)
_WRITE_SCOPE = re.compile(r":\s*WRITE$", re.IGNORECASE)

#: A path variable is the only caller-supplied value that reaches a URL path (§3.3 property 7).
PATH_VARIABLE = re.compile(r"\{([a-z_]+)\}")
_PATH_SEPARATORS = ("/", "\\", "%")
_DOT_SEGMENTS = (".", "..")


def _seal_effect(entry: FalconOperation) -> None:
    """The three enforcement tiers (§3.3 properties 2 and 4).

    A read must cite a `: READ` scope and use a read verb. The `search-lifecycle` tier exists only
    for the ids captain exception N1 names, and each must cite `NGSIEM: WRITE` and carry exactly
    the one write scope the exception admits. The `graphql-query` tier exists only for the one id
    captain exception N2 names, which must cite `Identity Protection GraphQL: WRITE`, carry exactly
    that scope, and be a POST. No other write scope is representable in any tier.
    """
    if entry.effect == "read":
        if not _READ_SCOPE.search(entry.evidence.doc_scope):
            raise ValueError(f"operation {entry.id} does not cite a read scope")
        if entry.method not in ("GET", "POST"):
            raise ValueError(f"operation {entry.id} has an unsupported method")
        if any(scope.endswith(":write") for scope in entry.scopes):
            raise ValueError(f"operation {entry.id} is a read but declares a write scope")
        return
    if entry.effect == "graphql-query":
        if entry.id not in GRAPHQL_QUERY_IDS:
            raise ValueError(f"operation {entry.id} is not admitted by captain exception N2")
        if not _WRITE_SCOPE.search(entry.evidence.doc_scope):
            raise ValueError(f"operation {entry.id} does not cite the Identity Protection GraphQL write scope")
        if entry.scopes != GRAPHQL_QUERY_SCOPES:
            raise ValueError(f"operation {entry.id} declares a scope outside captain exception N2")
        if entry.method != "POST":
            raise ValueError(f"operation {entry.id} has an unsupported method")
        return
    if entry.effect != "search-lifecycle":
        raise ValueError(f"operation {entry.id} declares an unknown effect")
    if entry.id not in SEARCH_LIFECYCLE_IDS:
        raise ValueError(f"operation {entry.id} is not admitted by captain exception N1")
    if not _WRITE_SCOPE.search(entry.evidence.doc_scope):
        raise ValueError(f"operation {entry.id} does not cite the NGSIEM write scope")
    if entry.scopes != SEARCH_LIFECYCLE_SCOPES:
        raise ValueError(f"operation {entry.id} declares a scope outside captain exception N1")
    if entry.method not in ("POST", "DELETE"):
        raise ValueError(f"operation {entry.id} has an unsupported method")


def _second_citation(entry: FalconOperation) -> bool:
    """§2.2: falcon-mcp, or falconpy's generated table plus PSFalcon when falcon-mcp has no tool."""
    text = entry.evidence.falcon_mcp
    if "api_scopes.py" in text and "maps " in text:
        return True
    return (
        f"falcon-mcp has no tool for {entry.id}" in text
        and "falconpy/_endpoint/" in text
        and f"maps {entry.id} to {entry.method} {entry.path}" in text
        and "PSFalcon " in text
    )


def _seal(entry: FalconOperation) -> FalconOperation:
    _seal_effect(entry)
    if not entry.path.startswith("/"):
        raise ValueError(f"operation {entry.id} has a malformed path")
    if not entry.scopes:
        raise ValueError(f"operation {entry.id} declares no scope")
    if not (entry.evidence.doc_url and entry.evidence.doc_scope and entry.evidence.falcon_mcp):
        raise ValueError(f"operation {entry.id} is missing evidence")
    if not _second_citation(entry):
        raise ValueError(f"operation {entry.id} is missing its §2.2 corroboration")
    if any(pattern.search(entry.path) for pattern in MUTATION_ROUTE_PATTERNS):
        raise ValueError(f"operation {entry.id} matches a known mutation route")
    return entry


#: The frozen registry. Every descriptor, its `scopes` tuple, its `evidence`, and this mapping are immutable.
OPERATIONS: Mapping[str, FalconOperation] = MappingProxyType({entry.id: _seal(entry) for entry in CANONICAL})


def operation(id: str) -> FalconOperation:
    """Resolves the canonical descriptor for an operation id.

    Deny by default: an id that is not a key of the registry, or a descriptor whose own id
    disagrees with its key or whose effect is outside the sealed union, fails with
    READ_ONLY_VIOLATION before any request is prepared.
    """
    resolved = OPERATIONS.get(id)
    if resolved is None or resolved.id != id or resolved.effect not in EFFECTS:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {id} is not a registered falcon-axi operation",
            ["falcon-axi issues only the operations in its closed registry; report this as a bug"],
        )
    return resolved


def path_arguments(descriptor: FalconOperation, supplied: Mapping[str, str]) -> dict[str, str]:
    """Validates the path variables a route interpolates (§3.3 property 7).

    A path variable is the only caller-supplied value that reaches a URL path, so a separator or a
    whole-value dot segment could retarget the request at a route the resolved descriptor never
    selected, defeating the closed registry. falcon-mcp guards `repository` for the same reason;
    falcon-axi guards every variable of every route, because the search id is caller-supplied too.
    """
    required = set(PATH_VARIABLE.findall(descriptor.path))
    if set(supplied) != required:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {descriptor.id} was prepared with the wrong path variables",
            ["falcon-axi interpolates only the path variables its registry declares; report this as a bug"],
        )
    for name, value in supplied.items():
        if not value.strip() or any(character in value for character in _PATH_SEPARATORS) or value in _DOT_SEGMENTS:
            raise CliError(
                "VALIDATION_ERROR",
                f"the {name} must be a plain name",
                [
                    "`/`, `\\`, and `%` are refused, and so are `.` and `..`, because the value reaches a URL path",
                    "Pass a bare repository or search name, for example `search-all`",
                ],
            )
    return dict(supplied)


def registered_scopes(ids: Sequence[str]) -> tuple[str, ...]:
    """The scopes the registered operations require, for operator provisioning (§5.7)."""
    return tuple(sorted({scope for id in ids for scope in operation(id).scopes}))
