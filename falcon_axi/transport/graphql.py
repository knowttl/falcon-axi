"""The closed registry of GraphQL query documents (docs/design/v1.md §4.4, captain exception N2).

Identity Protection exposes one GraphQL endpoint. Falcon scopes it `WRITE` even for a read-only
query, and the same endpoint accepts mutations, so the registered operation alone proves nothing
about what a request does. What makes the exception safe is here: a caller names a document and
supplies variables, the transport resolves the text from this frozen mapping, and no command, flag,
environment variable, or config key can supply GraphQL. There is no passthrough and no way to
reach a `mutation`.

Variables travel only as the JSON `variables` object, never interpolated into the text, so a
caller-supplied value cannot change a document's shape.

The variable type names (`UUID`, `Cursor`, `DateTimeInput`, `TimelineEventCategory`) and the
argument and field names come from CrowdStrike's and falcon-mcp's own queries, because the public
reference does not publish the schema (§4.4, §17).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.transport.operations import GRAPHQL_QUERY_IDS, FalconOperation

_NAME = re.compile(r"^[a-z][a-z_]*$")
_VARIABLE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
_TOKEN = re.compile(r"[{}]|[A-Za-z_][A-Za-z0-9_]*")
_READ_SCOPE = re.compile(r":read$")
#: A document may contain none of these anywhere: not as an operation, not as a field, not as a fragment.
_FORBIDDEN_WORDS = frozenset({"mutation", "subscription", "fragment"})


@dataclass(frozen=True)
class GraphqlDocument:
    name: str
    #: The one command that sends it, which is where `scopes` lists its read scope.
    command: str
    text: str
    variables: tuple[str, ...]
    #: The Identity Protection domain scope the query needs besides the endpoint's write scope.
    read_scopes: tuple[str, ...]


_ENTITY_FIELDS = """entityId
      primaryDisplayName
      secondaryDisplayName
      type
      riskScore
      riskScoreSeverity"""

_LIST = """query IdentityList(
  $first: Int
  $after: Cursor
  $name: String
  $email: String
  $domains: [String!]
) {
  entities(
    TYPES_ARGUMENTarchived: false
    primaryDisplayNamePattern: $name
    secondaryDisplayNamePattern: $email
    domains: $domains
    first: $first
    after: $after
  ) {
    nodes {
      ENTITY_FIELDS
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}"""


def _list_document(name: str, types_argument: str) -> GraphqlDocument:
    return GraphqlDocument(
        name=name,
        command="identity list",
        text=_LIST.replace("TYPES_ARGUMENT", types_argument).replace("ENTITY_FIELDS", _ENTITY_FIELDS),
        variables=("first", "after", "name", "email", "domains"),
        read_scopes=("Identity Protection Entities:read",),
    )


_SHOW = """query IdentityShow($entityIds: [UUID!]) {
  entities(entityIds: $entityIds, first: 1) {
    nodes {
      ENTITY_FIELDS
      riskFactors {
        type
        severity
      }
      associations {
        bindingType
        ... on EntityAssociation {
          entity {
            entityId
            primaryDisplayName
          }
        }
        ... on LocalAdminLocalUserAssociation {
          accountName
        }
        ... on LocalAdminDomainEntityAssociation {
          entity {
            entityId
            primaryDisplayName
          }
        }
        ... on GeoLocationAssociation {
          geoLocation {
            country
            city
          }
        }
      }
      openIncidents(first: 10) {
        nodes {
          type
          startTime
          endTime
          compromisedEntities {
            entityId
            primaryDisplayName
          }
        }
      }
      accounts {
        ... on ActiveDirectoryAccountDescriptor {
          domain
          samAccountName
          ou
          passwordAttributes {
            lastChange
          }
          expirationTime
        }
        ... on SsoUserAccountDescriptor {
          dataSource
          mostRecentActivity
          title
          creationTime
          passwordAttributes {
            lastChange
          }
        }
      }
    }
  }
}"""

#: The event types whose selection falcon-mcp requests; each carries the entity, endpoint, and
#: address fields the timeline rows render.
_ACTIVITY_EVENT_TYPES = (
    "TimelineUserOnEndpointActivityEvent",
    "TimelineAuthenticationEvent",
    "TimelineSuccessfulAuthenticationEvent",
    "TimelineFailedAuthenticationEvent",
    "TimelineServiceAccessEvent",
    "TimelineLdapSearchEvent",
    "TimelineDceRpcEvent",
    "TimelineRemoteCodeExecutionEvent",
)

_ACTIVITY_FIELDS = """... on EVENT_TYPE {
        sourceEntity {
          entityId
          primaryDisplayName
        }
        targetEntity {
          entityId
          primaryDisplayName
        }
        geoLocation {
          country
          city
        }
        userDisplayName
        endpointDisplayName
        ipAddress
      }"""

_TIMELINE = """query IdentityTimeline(
  $entityIds: [UUID!]
  $startTime: DateTimeInput
  $categories: [TimelineEventCategory!]
  $first: Int
  $after: Cursor
) {
  timeline(
    sourceEntityQuery: {entityIds: $entityIds}
    startTime: $startTime
    categories: $categories
    sortOrder: DESCENDING
    first: $first
    after: $after
  ) {
    nodes {
      eventId
      eventType
      eventSeverity
      timestamp
      ... on TimelineAlertEvent {
        sourceEntity {
          entityId
          primaryDisplayName
        }
      }
      ACTIVITY_EVENTS
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}"""


def _seal_document(entry: GraphqlDocument) -> GraphqlDocument:
    """Proves lexically that a document is one `query` and nothing else (the runtime half of §4.4).

    The offline suite additionally parses every document with graphql-core and pins its root fields.
    """
    if not _NAME.match(entry.name):
        raise ValueError(f"graphql document {entry.name} has a malformed name")
    if '"' in entry.text or "#" in entry.text:
        raise ValueError(f"graphql document {entry.name} contains a string or a comment")
    tokens = _TOKEN.findall(entry.text)
    words = [piece for piece in tokens if piece not in ("{", "}")]
    if not words or words[0] != "query":
        raise ValueError(f"graphql document {entry.name} is not a query")
    if _FORBIDDEN_WORDS.intersection(words):
        raise ValueError(f"graphql document {entry.name} names a mutation, subscription, or fragment")
    depth = 0
    top_level_queries = 0
    for piece in tokens:
        if piece == "{":
            depth += 1
        elif piece == "}":
            depth -= 1
        elif depth == 0 and piece == "query":
            top_level_queries += 1
    if depth != 0 or top_level_queries != 1:
        raise ValueError(f"graphql document {entry.name} is not exactly one query operation")
    if set(_VARIABLE.findall(entry.text)) != set(entry.variables):
        raise ValueError(f"graphql document {entry.name} declares variables its text does not match")
    if not entry.read_scopes or not all(_READ_SCOPE.search(scope) for scope in entry.read_scopes):
        raise ValueError(f"graphql document {entry.name} must carry read scopes only")
    return entry


_CANONICAL = (
    _list_document("identity_list", ""),
    _list_document("identity_list_users", "types: [USER]\n    "),
    _list_document("identity_list_endpoints", "types: [ENDPOINT]\n    "),
    GraphqlDocument(
        name="identity_show",
        command="identity show",
        text=_SHOW.replace("ENTITY_FIELDS", _ENTITY_FIELDS),
        variables=("entityIds",),
        read_scopes=("Identity Protection Entities:read",),
    ),
    GraphqlDocument(
        name="identity_timeline",
        command="identity timeline",
        text=_TIMELINE.replace(
            "ACTIVITY_EVENTS",
            "\n      ".join(_ACTIVITY_FIELDS.replace("EVENT_TYPE", event) for event in _ACTIVITY_EVENT_TYPES),
        ),
        variables=("entityIds", "startTime", "categories", "first", "after"),
        read_scopes=("Identity Protection Timeline:read",),
    ),
)

#: The frozen document registry. These are the only GraphQL texts falcon-axi can send.
GRAPHQL_DOCUMENTS: Mapping[str, GraphqlDocument] = MappingProxyType({entry.name: _seal_document(entry) for entry in _CANONICAL})

_DOCUMENT_TEXTS = frozenset(entry.text for entry in GRAPHQL_DOCUMENTS.values())


def document(name: str) -> GraphqlDocument:
    resolved = GRAPHQL_DOCUMENTS.get(name)
    if resolved is None:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"graphql document {name} is not a registered falcon-axi document",
            ["falcon-axi sends only the query documents in its closed registry; report this as a bug"],
        )
    return resolved


def request_body(
    descriptor: FalconOperation,
    document_name: str | None,
    variables: Mapping[str, Any] | None,
    body: Any,
) -> Any:
    """The request body a registered operation sends; for the GraphQL operation it is built here.

    The GraphQL operation takes a document name and variables and never a body, and every other
    operation takes a body and never a document, so GraphQL text has exactly one way in.
    """
    if descriptor.id not in GRAPHQL_QUERY_IDS:
        if document_name is not None or variables is not None:
            raise CliError(
                "READ_ONLY_VIOLATION",
                f"operation {descriptor.id} does not take a graphql document",
                ["falcon-axi sends a graphql document only through its registered graphql operation; report this as a bug"],
            )
        return body
    if document_name is None or body is not None:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {descriptor.id} takes a registered document name and variables, never a body",
            ["falcon-axi sends only the query documents in its closed registry; report this as a bug"],
        )
    chosen = document(document_name)
    supplied = dict(variables or {})
    if set(supplied) - set(chosen.variables):
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"graphql document {chosen.name} was prepared with undeclared variables",
            ["falcon-axi supplies only the variables a registered document declares; report this as a bug"],
        )
    return {"query": chosen.text, "variables": supplied}


def is_registered_query(body: Any) -> bool:
    """Whether a body is exactly a registered document plus variables, for the network sink's last check."""
    return isinstance(body, Mapping) and body.get("query") in _DOCUMENT_TEXTS and set(body) <= {"query", "variables"}
