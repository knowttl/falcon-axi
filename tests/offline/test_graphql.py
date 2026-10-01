"""The GraphQL document registry and captain exception N2 (docs/design/v1.md §3.3, §4.4)."""

import dataclasses
import re

import pytest
import requests_mock
from graphql import OperationType, parse
from graphql.language import FieldNode, OperationDefinitionNode

from falcon_axi.core import CliError
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.graphql import (
    GRAPHQL_DOCUMENTS,
    _seal_document,
    document,
    is_registered_query,
    request_body,
)
from falcon_axi.transport.harness import mint_permit, send_permitted_request
from falcon_axi.transport.operations import OPERATIONS
from falcon_axi.transport.types import PreparedOperation, RequestArgs

GRAPHQL_URL = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"
GRAPHQL = OPERATIONS["api_preempt_proxy_post_graphql"]
#: The only root fields falcon-axi's documents may select; `incidents` and `securityAssessment` are not shipped.
ALLOWED_ROOT_FIELDS = {"entities", "timeline"}
JSON = {"Content-Type": "application/json"}


def test_the_registry_holds_exactly_the_documents_the_identity_commands_send() -> None:
    assert sorted(GRAPHQL_DOCUMENTS) == [
        "identity_list",
        "identity_list_endpoints",
        "identity_list_users",
        "identity_show",
        "identity_timeline",
    ]
    assert {entry.command for entry in GRAPHQL_DOCUMENTS.values()} == {"identity list", "identity show", "identity timeline"}


@pytest.mark.parametrize("name", sorted(GRAPHQL_DOCUMENTS))
def test_every_document_parses_as_exactly_one_query_with_an_allowed_root_field(name: str) -> None:
    parsed = parse(GRAPHQL_DOCUMENTS[name].text)
    assert len(parsed.definitions) == 1
    definition = parsed.definitions[0]
    assert isinstance(definition, OperationDefinitionNode)
    assert definition.operation is OperationType.QUERY
    roots = {selection.name.value for selection in definition.selection_set.selections if isinstance(selection, FieldNode)}
    assert roots and roots <= ALLOWED_ROOT_FIELDS


@pytest.mark.parametrize("name", sorted(GRAPHQL_DOCUMENTS))
def test_every_document_declares_exactly_the_variables_it_uses_and_carries_only_read_scopes(name: str) -> None:
    entry = GRAPHQL_DOCUMENTS[name]
    parsed = parse(entry.text)
    definition = parsed.definitions[0]
    assert isinstance(definition, OperationDefinitionNode)
    declared = {variable.variable.name.value for variable in definition.variable_definitions or ()}
    used = set(re.findall(r"\$(\w+)", entry.text))
    assert declared == used == set(entry.variables)
    assert entry.read_scopes and all(scope.endswith(":read") for scope in entry.read_scopes)


def test_no_document_names_a_mutation_a_subscription_a_fragment_a_string_or_a_comment() -> None:
    for entry in GRAPHQL_DOCUMENTS.values():
        assert not re.search(r"\b(mutation|subscription|fragment)\b", entry.text)
        assert '"' not in entry.text
        assert "#" not in entry.text


def test_the_runtime_seal_refuses_a_document_that_is_not_one_query() -> None:
    base = GRAPHQL_DOCUMENTS["identity_show"]
    hostile = (
        ("mutation Reset($entityIds: [UUID!]) { entities(entityIds: $entityIds) { nodes { entityId } } }", "is not a query"),
        (f"{base.text}\nmutation Other {{ entities {{ nodes {{ entityId }} }} }}", "mutation, subscription, or fragment"),
        (f"{base.text}\nfragment F on Entity {{ entityId }}", "mutation, subscription, or fragment"),
        ("query Q($entityIds: [UUID!]) { mutation { entityId } }", "mutation, subscription, or fragment"),
        (
            'query Q($entityIds: [UUID!]) { entities(entityIds: $entityIds, name: "x") { nodes { entityId } } }',
            "string or a comment",
        ),
        (
            "query Q($entityIds: [UUID!]) { # hi\n entities(entityIds: $entityIds) { nodes { entityId } } }",
            "string or a comment",
        ),
        ("query Q($entityIds: [UUID!]) { entities(entityIds: $entityIds) { nodes { entityId }", "exactly one query"),
        (f"{base.text}\nquery Second {{ entities {{ nodes {{ entityId }} }} }}", "exactly one query"),
        ("{ entities { nodes { entityId } } }", "is not a query"),
    )
    for text, reason in hostile:
        with pytest.raises(ValueError, match=reason):
            _seal_document(dataclasses.replace(base, text=text))


def test_the_runtime_seal_refuses_a_write_scope_or_a_variable_mismatch() -> None:
    base = GRAPHQL_DOCUMENTS["identity_show"]
    with pytest.raises(ValueError, match="read scopes only"):
        _seal_document(dataclasses.replace(base, read_scopes=("Identity Protection Entities:write",)))
    with pytest.raises(ValueError, match="read scopes only"):
        _seal_document(dataclasses.replace(base, read_scopes=()))
    with pytest.raises(ValueError, match="variables"):
        _seal_document(dataclasses.replace(base, variables=("entityIds", "other")))


def test_the_document_registry_resists_mutation() -> None:
    with pytest.raises(TypeError):
        GRAPHQL_DOCUMENTS["identity_show"] = GRAPHQL_DOCUMENTS["identity_list"]  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        GRAPHQL_DOCUMENTS["identity_show"].text = "mutation { x }"  # type: ignore[misc]


def test_an_unregistered_document_name_is_refused() -> None:
    with pytest.raises(CliError) as error:
        document("identity_reset_password")
    assert error.value.code == "READ_ONLY_VIOLATION"


def test_variables_travel_in_the_json_variables_object_and_never_in_the_document_text() -> None:
    hostile = 'x") { entityId } } mutation { y'
    body = request_body(GRAPHQL, "identity_list", {"first": 5, "name": hostile}, None)
    assert body["query"] == GRAPHQL_DOCUMENTS["identity_list"].text
    assert body["variables"] == {"first": 5, "name": hostile}
    assert hostile not in body["query"]


def test_the_graphql_operation_takes_a_document_and_never_a_body() -> None:
    for body, name in (({"query": "mutation { x }"}, None), ({"query": "mutation { x }"}, "identity_list"), (None, None)):
        with pytest.raises(CliError) as error:
            request_body(GRAPHQL, name, {}, body)
        assert error.value.code == "READ_ONLY_VIOLATION"
    with pytest.raises(CliError) as error:
        request_body(GRAPHQL, "identity_list", {"query": "{ x }"}, None)
    assert error.value.code == "READ_ONLY_VIOLATION"


def test_no_other_operation_accepts_a_document_or_variables() -> None:
    other = OPERATIONS["PostEntitiesAlertsV2"]
    for name, variables in (("identity_list", None), (None, {"first": 1})):
        with pytest.raises(CliError) as error:
            request_body(other, name, variables, {"composite_ids": []})
        assert error.value.code == "READ_ONLY_VIOLATION"
    assert request_body(other, None, None, {"composite_ids": ["a"]}) == {"composite_ids": ["a"]}


def test_the_transport_posts_one_registered_document_to_the_graphql_route() -> None:
    with requests_mock.Mocker() as mock:
        mock.post(GRAPHQL_URL, json={"data": {"entities": {"nodes": []}}}, headers=JSON)
        response = HttpTransport().request(
            "api_preempt_proxy_post_graphql",
            RequestArgs(
                base_url="https://api.crowdstrike.com",
                token="synthetic-token",
                document="identity_show",
                variables={"entityIds": ["00000000-0000-4000-8000-000000000001"]},
            ),
        )
    request = mock.request_history[0]
    assert (request.method, request.path) == ("POST", "/identity-protection/combined/graphql/v1")
    assert request.json() == {
        "query": GRAPHQL_DOCUMENTS["identity_show"].text,
        "variables": {"entityIds": ["00000000-0000-4000-8000-000000000001"]},
    }
    assert request.headers["Authorization"] == "Bearer synthetic-token"
    assert response.status == 200


def test_the_transport_refuses_raw_graphql_before_anything_is_sent() -> None:
    with requests_mock.Mocker() as mock:
        with pytest.raises(CliError) as error:
            HttpTransport().request(
                "api_preempt_proxy_post_graphql",
                RequestArgs(
                    base_url="https://api.crowdstrike.com",
                    token="synthetic-token",
                    body={"query": "mutation { disableAccount }"},
                ),
            )
    assert error.value.code == "READ_ONLY_VIOLATION"
    assert mock.request_history == []


def test_the_sink_refuses_an_unregistered_graphql_body_even_with_a_valid_permit() -> None:
    """The sink checks the body itself, so a prepared request built any other way still cannot carry a mutation."""
    for body in (
        {"query": "mutation { disableAccount }"},
        {"query": GRAPHQL_DOCUMENTS["identity_list"].text, "operationName": "x", "extensions": {}},
        None,
        "query { entities { nodes { entityId } } }",
    ):
        assert not is_registered_query(body)
        with requests_mock.Mocker() as mock:
            with pytest.raises(CliError) as error:
                send_permitted_request(
                    PreparedOperation(
                        operation_id="api_preempt_proxy_post_graphql",
                        origin="https://api.crowdstrike.com",
                        token="synthetic-token",
                        body=body,
                    ),
                    mint_permit(),
                )
        assert error.value.code == "READ_ONLY_VIOLATION"
        assert mock.request_history == []
    assert is_registered_query({"query": GRAPHQL_DOCUMENTS["identity_list"].text, "variables": {}})
