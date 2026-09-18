"""`falcon-axi scopes`, the registry projection (docs/design/v1.md §5.7, §8.1, §8.3)."""

from toon_format import decode

from falcon_axi.cli import COMMANDS, run
from falcon_axi.scopes import COMMAND_OPERATIONS, scope_rows
from falcon_axi.transport.operations import OPERATIONS
from tests.support.recorded import NO_CREDENTIAL_ENV, RecordedTransport


def test_the_matrix_is_local_only_and_needs_no_credential() -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["scopes"], recorded, dict(NO_CREDENTIAL_ENV))
    assert exit_code == 0
    assert recorded.requests == []
    assert stdout.startswith("posture: read-only; falcon-axi requests no write scope")


def test_every_printed_scope_is_a_read_scope_from_the_registry() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    parsed = decode(stdout)
    registered = {scope for descriptor in OPERATIONS.values() for scope in descriptor.scopes}
    assert {row["scope"] for row in parsed["scopes"]} == registered
    for row in parsed["scopes"]:
        assert row["access"] == "read"
        assert row["scope"].endswith(":read")


def test_the_matrix_names_only_commands_the_cli_ships() -> None:
    for command, _ in COMMAND_OPERATIONS:
        assert command in COMMANDS
    named = {command for row in scope_rows() for command in row["commands"].split(", ")}
    assert named == {command for command, _ in COMMAND_OPERATIONS}


def test_it_preserves_the_unresolved_member_cid_question_rather_than_claiming_it_settled() -> None:
    stdout, _ = run(["scopes"], RecordedTransport([]), dict(NO_CREDENTIAL_ENV))
    assert "member_cid_token_scope: unresolved" in stdout
    assert "Flight Control" in stdout
    assert "write" not in stdout.replace("no write scope", "").replace("never needs a write scope", "")
