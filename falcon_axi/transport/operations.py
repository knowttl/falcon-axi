"""The complete scoped-operation surface of falcon-axi v1 (docs/design/v1.md §2.1, §3.3).

The union is closed: adding a member requires both §2.2 citations in the same change.
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
]

OPERATION_IDS: tuple[str, ...] = get_args(OperationId)


@dataclass(frozen=True)
class Evidence:
    doc_url: str
    doc_scope: str
    falcon_mcp: str


@dataclass(frozen=True)
class FalconOperation:
    id: OperationId
    method: Literal["GET", "POST"]
    path: str
    scopes: tuple[str, ...]
    effect: Literal["read"]
    evidence: Evidence


ALERTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/alerts/"
HOSTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/hosts/"
SPOTLIGHT_DOC = "https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/"

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
)

#: Routes whose shape marks a Falcon mutation; no registered operation may match one (§3.3 property 5).
MUTATION_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/entities/[^/]+/action", re.IGNORECASE),
    re.compile(r"/queries/[^/]+/action", re.IGNORECASE),
    re.compile(r"/real-time-response/", re.IGNORECASE),
)

_READ_SCOPE = re.compile(r":\s*READ$", re.IGNORECASE)


def _seal(entry: FalconOperation) -> FalconOperation:
    if entry.effect != "read":
        raise ValueError(f"operation {entry.id} is not a read")
    if entry.method not in ("GET", "POST"):
        raise ValueError(f"operation {entry.id} has an unsupported method")
    if not entry.path.startswith("/"):
        raise ValueError(f"operation {entry.id} has a malformed path")
    if not entry.scopes:
        raise ValueError(f"operation {entry.id} declares no scope")
    if not (entry.evidence.doc_url and entry.evidence.doc_scope and entry.evidence.falcon_mcp):
        raise ValueError(f"operation {entry.id} is missing evidence")
    if not _READ_SCOPE.search(entry.evidence.doc_scope):
        raise ValueError(f"operation {entry.id} does not cite a read scope")
    if any(pattern.search(entry.path) for pattern in MUTATION_ROUTE_PATTERNS):
        raise ValueError(f"operation {entry.id} matches a known mutation route")
    return entry


#: The frozen registry. Every descriptor, its `scopes` tuple, its `evidence`, and this mapping are immutable.
OPERATIONS: Mapping[str, FalconOperation] = MappingProxyType({entry.id: _seal(entry) for entry in CANONICAL})


def operation(id: str) -> FalconOperation:
    """Resolves the canonical descriptor for an operation id.

    Deny by default: an id that is not a key of the registry, or a descriptor whose own id
    disagrees with its key, fails with READ_ONLY_VIOLATION before any request is prepared.
    """
    resolved = OPERATIONS.get(id)
    if resolved is None or resolved.id != id or resolved.effect != "read":
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {id} is not a registered falcon-axi read operation",
            ["falcon-axi issues only the read operations in its closed registry; report this as a bug"],
        )
    return resolved


def registered_scopes(ids: Sequence[str]) -> tuple[str, ...]:
    """The read scopes the registered operations require, for operator provisioning (§5.7)."""
    return tuple(sorted({scope for id in ids for scope in operation(id).scopes}))
