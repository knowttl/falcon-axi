"""The mechanical form of Invariant R (docs/design/v1.md §3.3, §14.5)."""

import dataclasses

import pytest

from falcon_axi.core import CliError
from falcon_axi.transport.operations import (
    MUTATION_ROUTE_PATTERNS,
    OPERATION_IDS,
    OPERATIONS,
    operation,
    registered_scopes,
)

EXPECTED = {
    "GetQueriesAlertsV2": {
        "method": "GET",
        "path": "/alerts/queries/alerts/v2",
        "scopes": ("Alerts:read",),
        "doc_scope": "Alerts: READ",
    },
    "PostEntitiesAlertsV2": {
        "method": "POST",
        "path": "/alerts/entities/alerts/v2",
        "scopes": ("Alerts:read",),
        "doc_scope": "Alerts: READ",
    },
    "QueryDevicesByFilter": {
        "method": "GET",
        "path": "/devices/queries/devices/v1",
        "scopes": ("Hosts:read",),
        "doc_scope": "Hosts: READ",
    },
    "PostDeviceDetailsV2": {
        "method": "POST",
        "path": "/devices/entities/devices/v2",
        "scopes": ("Hosts:read",),
        "doc_scope": "Hosts: READ",
    },
    "combinedQueryVulnerabilities": {
        "method": "GET",
        "path": "/spotlight/combined/vulnerabilities/v1",
        "scopes": ("Vulnerabilities:read",),
        "doc_scope": "Vulnerabilities: READ",
    },
}


def test_the_registry_contains_exactly_the_five_registered_read_operations() -> None:
    assert sorted(OPERATIONS) == sorted(EXPECTED)
    assert sorted(OPERATION_IDS) == sorted(EXPECTED)


def test_every_descriptor_equals_its_canonical_value_and_carries_read_evidence() -> None:
    for id, expected in EXPECTED.items():
        descriptor = OPERATIONS[id]
        assert descriptor.id == id
        assert descriptor.method == expected["method"]
        assert descriptor.path == expected["path"]
        assert descriptor.scopes == expected["scopes"]
        assert descriptor.effect == "read"
        assert descriptor.evidence.doc_scope == expected["doc_scope"]
        assert descriptor.evidence.doc_scope.upper().endswith(": READ")
        assert descriptor.evidence.doc_url.startswith("https://")
        assert "api_scopes.py" in descriptor.evidence.falcon_mcp


def test_no_registered_path_matches_a_known_mutation_route() -> None:
    for descriptor in OPERATIONS.values():
        for pattern in MUTATION_ROUTE_PATTERNS:
            assert pattern.search(descriptor.path) is None, f"{descriptor.id} matches {pattern.pattern}"


def test_every_registered_scope_is_a_read_scope() -> None:
    for scope in registered_scopes(list(EXPECTED)):
        assert scope.endswith(":read")


def test_the_registry_and_every_nested_value_resist_mutation() -> None:
    with pytest.raises(TypeError):
        OPERATIONS["GetQueriesAlertsV2"] = OPERATIONS["PostEntitiesAlertsV2"]  # type: ignore[index]
    descriptor = OPERATIONS["GetQueriesAlertsV2"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.path = "/entities/devices/action"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.evidence.doc_scope = "Hosts: WRITE"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        descriptor.scopes.append("Hosts:write")  # type: ignore[attr-defined]
    assert OPERATIONS["GetQueriesAlertsV2"].path == "/alerts/queries/alerts/v2"
    assert OPERATIONS["GetQueriesAlertsV2"].evidence.doc_scope == "Alerts: READ"
    assert OPERATIONS["GetQueriesAlertsV2"].scopes == ("Alerts:read",)


def test_an_unregistered_operation_id_fails_with_read_only_violation_before_anything_is_sent() -> None:
    with pytest.raises(CliError) as error:
        operation("PatchEntitiesAlertsV3")
    assert error.value.code == "READ_ONLY_VIOLATION"
    with pytest.raises(CliError):
        operation("get")
