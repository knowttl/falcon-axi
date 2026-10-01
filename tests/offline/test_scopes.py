"""`falcon-axi scopes`, the registry projection (docs/design/v1.md §5.7, §8.1, §8.3)."""

from toon_format import decode

from falcon_axi.cli import COMMANDS, run
from falcon_axi.scopes import COMMAND_OPERATIONS, scope_rows
from falcon_axi.transport.graphql import GRAPHQL_DOCUMENTS
from falcon_axi.transport.operations import OPERATIONS
from tests.support.recorded import NO_CREDENTIAL_ENV, RecordedTransport


def test_the_matrix_is_local_only_and_needs_no_credential() -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["scopes"], recorded, dict(NO_CREDENTIAL_ENV))
    assert exit_code == 0
    assert recorded.requests == []
    assert stdout.startswith("posture: read-only except two write-labelled scopes")


def test_every_printed_scope_comes_from_the_registry_with_its_access_derived_from_it() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    parsed = decode(stdout)
    registered = {scope for descriptor in OPERATIONS.values() for scope in descriptor.scopes} | {
        scope for entry in GRAPHQL_DOCUMENTS.values() for scope in entry.read_scopes
    }
    assert {row["scope"] for row in parsed["scopes"]} == registered
    for row in parsed["scopes"]:
        assert row["access"] == ("write" if row["scope"].endswith(":write") else "read")


def test_the_only_write_scopes_in_the_matrix_are_the_two_the_captain_exceptions_admit() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    parsed = decode(stdout)
    write_rows = {row["scope"]: row["commands"] for row in parsed["scopes"] if row["access"] == "write"}
    assert write_rows == {
        "NGSIEM:write": "identity activity, search start, search stop",
        "Identity Protection GraphQL:write": "identity list, identity show, identity timeline",
    }


def test_provisioning_hints_describe_each_write_scope_without_claiming_the_other_is_read_only() -> None:
    stdout, exit_code = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    assert exit_code == 0
    hints = decode(stdout)["help"]
    assert "Omit NGSIEM:write and `search start`, `search stop`, and `identity activity` fail with SCOPE_DENIED" in hints
    assert (
        "Omit Identity Protection GraphQL:write and `identity list`, `identity show`, and `identity timeline` "
        "fail with SCOPE_DENIED" in hints
    )
    assert not any("wholly read-only client" in hint for hint in hints)


def test_the_identity_commands_list_their_per_document_read_scopes() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    rows = {row["scope"]: row for row in decode(stdout)["scopes"]}
    assert rows["Identity Protection Entities:read"]["commands"] == "identity list, identity show"
    assert rows["Identity Protection Timeline:read"]["commands"] == "identity timeline"
    assert rows["Identity Protection Entities:read"]["access"] == "read"


def test_the_matrix_names_only_commands_the_cli_ships() -> None:
    for command, _ in COMMAND_OPERATIONS:
        assert command in COMMANDS
    named = {command for row in scope_rows() for command in row["commands"].split(", ")}
    assert named == {command for command, _ in COMMAND_OPERATIONS}


def test_it_preserves_the_unresolved_member_cid_question_rather_than_claiming_it_settled() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    assert "member_cid_token_scope: unresolved" in stdout
    assert "Flight Control" in stdout
