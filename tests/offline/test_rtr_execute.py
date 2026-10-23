"""Synthetic N3 lifecycle, refusals, ownership, and cleanup through the real core."""

import dataclasses
import json
import os
import signal
import time
from pathlib import Path

import pytest
import requests_mock

from falcon_axi.cli import run as cli_run
from falcon_axi.core import CliError
from falcon_axi.credentials import load_profiles
from falcon_axi.redaction import redaction_scope, register_secret
from falcon_axi.rtr_execute import execute_run
from falcon_axi.rtr_journal import Journal
from falcon_axi.rtr_policy import COMMANDS, OUTPUT_BYTES, OUTPUT_CHUNKS, RESPONSE_BYTES, parse_command
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.budget import BudgetExpired, remaining_seconds, request_budget
from falcon_axi.transport.harness import _worker_reply, mint_permit, send_permitted_request
from falcon_axi.transport.operations import RTR_EXECUTION_IDS, _seal, operation
from falcon_axi.transport.rtr import _AUTHORITY, RunAuthority
from falcon_axi.transport.types import PreparedOperation, RequestArgs
from tests.support.recorded import RecordedTransport, response, serve

HOST = "a" * 32
ORIGIN = "https://api.crowdstrike.com"
TOKEN = "synthetic-rtr-token"


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "triage": {
                        "clientId": "synthetic-client",
                        "clientSecret": {"env": "TEST_RTR_SECRET"},
                        "rtr": {"enabled": True},
                    }
                },
                "defaultProfile": "triage",
            }
        )
    )
    path.chmod(0o600)
    return {
        "FALCON_AXI_CONFIG": str(path),
        "TEST_RTR_SECRET": "synthetic-secret",
        "FALCON_AXI_WRITE_LOG": str(tmp_path / "writes.log"),
        "XDG_STATE_HOME": str(tmp_path / "rtr-state"),
    }


@pytest.fixture
def transport():
    return RecordedTransport(
        [
            serve("RTR_InitSession", response(201, {"resources": [{"session_id": "synthetic-session"}]})),
            serve("RTR_ExecuteCommand", response(201, {"resources": [{"cloud_request_id": "synthetic-command"}]})),
            serve(
                "RTR_CheckCommandStatus",
                response(200, {"resources": [{"stdout": "synthetic output", "complete": True, "sequence_id": 0}]}),
            ),
            serve("RTR_DeleteSession", response(204, None)),
        ]
    )


def records(env):
    return [json.loads(line) for line in Path(env["FALCON_AXI_WRITE_LOG"]).read_text().splitlines()]


def replace_profile(env, value):
    path = Path(env["FALCON_AXI_CONFIG"])
    document = json.loads(path.read_text())
    document["profiles"]["triage"]["rtr"] = value
    path.write_text(json.dumps(document))


def fail(error):
    def responder(args):
        raise error

    return responder


def run(transport, env, command="ps", confirmation=None):
    return execute_run(transport, env, HOST, command, confirmation if confirmation is not None else f"{HOST}:{command}")


def cli(transport, env, *extra, command="ps", emit_preview=None):
    return cli_run(
        ["rtr", "run", HOST, "--command", command, *extra],
        transport=transport,
        env=env,
        emit_preview=emit_preview,
    )


@pytest.mark.parametrize("read_only", ["0", "1"])
def test_cli_preview_is_local_and_shows_effective_limits(env, transport, read_only):
    env["FALCON_AXI_READ_ONLY"] = read_only
    output, code = cli(transport, env)
    assert code == 0
    assert "preview:" in output
    assert f"host: {HOST}" in output
    assert "execution_seconds: 50" in output
    assert "output_bytes: 65536" in output
    assert "session_deletion: mandatory" in output
    assert transport.requests == []
    assert not Path(env["FALCON_AXI_WRITE_LOG"]).exists()


def test_cli_emits_preview_before_initialization_and_deletes_on_success(env, transport):
    emitted = []

    def initialize(args):
        assert len(emitted) == 1
        assert "command: ps" in emitted[0]
        return response(201, {"resources": [{"session_id": "synthetic-session"}]})

    transport.responders.insert(0, serve("RTR_InitSession", initialize))
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps", emit_preview=emitted.append)
    assert code == 0
    assert "synthetic output" in output
    assert "cleanup: deleted" in output
    assert records(env)[-1]["cleanup"] == "deleted"
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


@pytest.mark.parametrize(
    "extra",
    [
        ("--execute",),
        ("--execute", "--confirm", "yes"),
        ("--execute", "--confirm", f"{'b' * 32}:ps"),
        ("--execute", "--confirm", f"{HOST}:ls"),
        ("--confirm", f"{HOST}:ps"),
    ],
)
def test_cli_requires_both_execution_flags_and_exact_confirmation(env, transport, extra):
    output, code = cli(transport, env, *extra)
    assert code == 2
    assert "VALIDATION_ERROR" in output
    assert transport.requests == []


@pytest.mark.parametrize("command", ["runscript", "eventlog backup", "eventlog export", "reg delete HKLM", "ps; ls"])
def test_cli_disallowed_commands_never_authenticate(env, transport, command):
    _, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:{command}", command=command)
    assert code != 0
    assert transport.requests == []


@pytest.mark.parametrize("policy", [{"enabled": False}, {"enabled": True, "commands": ["ls"]}])
def test_cli_profile_refusal_precedes_all_requests(env, transport, policy):
    replace_profile(env, policy)
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "READ_ONLY_VIOLATION" in output
    assert transport.requests == []


def test_cli_read_only_wins_over_opt_in_and_confirmation(env, transport):
    env["FALCON_AXI_READ_ONLY"] = "1"
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "READ_ONLY_VIOLATION" in output
    assert transport.requests == []


@pytest.mark.parametrize(
    "operation,error",
    [
        ("RTR_ExecuteCommand", CliError("NETWORK_UNREACHABLE", "synthetic failure")),
        ("RTR_CheckCommandStatus", BudgetExpired()),
    ],
)
def test_cli_lifecycle_error_deletes_before_returning(env, transport, operation, error):
    transport.responders.insert(0, serve(operation, fail(error)))
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "cleanup: deleted" in output
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM])
def test_cli_interrupt_deletes_and_restores_signal_handler(env, transport, number):
    previous = signal.getsignal(number)

    def interrupt(args):
        signal.raise_signal(number)

    transport.responders.insert(0, serve("RTR_CheckCommandStatus", interrupt))
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "interrupted" in output
    assert "cleanup: deleted" in output
    assert signal.getsignal(number) == previous
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


def test_cli_ambiguous_init_requires_manual_recovery_without_replay(env, transport):
    transport.responders.insert(0, serve("RTR_InitSession", fail(BudgetExpired())))
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "cleanup: unknown" in output
    assert "Reconcile the host's sessions in Falcon before retrying" in output
    assert len(transport.operation_requests("RTR_InitSession")) == 1
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert transport.operation_requests("RTR_DeleteSession") == []


def test_cli_output_cap_is_explicit_and_session_is_deleted(env, transport):
    transport.responders.insert(
        0,
        serve(
            "RTR_CheckCommandStatus",
            response(
                200,
                {
                    "resources": [{"stdout": "x" * (OUTPUT_BYTES + 1), "complete": True, "sequence_id": 0}],
                },
            ),
        ),
    )
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 0
    assert "truncated: true" in output
    assert "complete: false" in output
    assert "cleanup: deleted" in output
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


def test_cli_failed_cleanup_is_never_success(env, transport):
    transport.responders.insert(0, serve("RTR_DeleteSession", response(500, {})))
    output, code = cli(transport, env, "--execute", "--confirm", f"{HOST}:ps")
    assert code == 1
    assert "cleanup: failed" in output
    assert "complete: true" in output


def test_cli_preview_redacts_sensitive_command_arguments(env, transport):
    output, code = cli(transport, env, command="cat synthetic-secret")
    assert code == 0
    assert "synthetic-secret" not in output
    assert "cat [redacted]" in output
    assert transport.requests == []


def test_cli_region_and_tenant_flags_apply_to_whole_lifecycle(env, transport):
    transport.oauth = [response(201, {"access_token": "synthetic-rtr-token"}, {"x-cs-region": "eu-1"})]
    _, code = cli(
        transport,
        env,
        "--execute",
        "--confirm",
        f"{HOST}:ps",
        "--region",
        "eu-1",
        "--member-cid",
        "synthetic-child",
    )
    assert code == 0
    assert transport.oauth_requests()[0].member_cid == "synthetic-child"
    assert transport.oauth_requests()[0].base_url == "https://api.eu-1.crowdstrike.com"
    for _, args in [value for kind, value in transport.requests if kind == "operation"]:
        assert args.base_url == "https://api.eu-1.crowdstrike.com"


def test_success_deletes_the_returned_session_and_journals_without_output(env, transport):
    result = run(transport, env)
    assert result.output == "synthetic output"
    assert (result.complete, result.truncated, result.cleanup) == (True, False, "deleted")
    assert [request[1][0] for request in transport.requests if request[0] == "operation"] == [
        "RTR_InitSession",
        "RTR_ExecuteCommand",
        "RTR_CheckCommandStatus",
        "RTR_DeleteSession",
    ]
    assert records(env)[0]["phase"] == "intent"
    assert records(env)[-1]["cleanup"] == "deleted"
    assert "synthetic output" not in Path(env["FALCON_AXI_WRITE_LOG"]).read_text()
    assert Path(env["FALCON_AXI_WRITE_LOG"]).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "policy",
    [
        None,
        {"enabled": False},
        {"enabled": True, "commands": []},
        {"enabled": True, "commands": ["ls"]},
    ],
)
def test_profile_refuses_before_authentication(env, transport, policy):
    path = Path(env["FALCON_AXI_CONFIG"])
    document = json.loads(path.read_text())
    document["profiles"]["triage"].pop("rtr")
    path.write_text(json.dumps(document))
    if policy is not None:
        replace_profile(env, policy)
    with pytest.raises(CliError, match="profile opt-in|effective read-only"):
        run(transport, env)
    assert transport.requests == []


@pytest.mark.parametrize("value", ["1", "true", "TRUE"])
def test_read_only_defeats_opt_in_and_confirmation(env, transport, value):
    env["FALCON_AXI_READ_ONLY"] = value
    with pytest.raises(CliError, match="READ_ONLY"):
        run(transport, env)
    assert transport.requests == []


def test_environment_credentials_never_opt_in(env, transport):
    env.update(FALCON_AXI_CLIENT_ID="synthetic-env", FALCON_AXI_CLIENT_SECRET="synthetic-env-secret")
    with pytest.raises(CliError, match="profile opt-in"):
        run(transport, env)
    assert transport.requests == []


def test_file_profile_named_env_can_opt_in(env, transport):
    path = Path(env["FALCON_AXI_CONFIG"])
    document = json.loads(path.read_text())
    document["profiles"]["env"] = document["profiles"].pop("triage")
    document["defaultProfile"] = "env"
    path.write_text(json.dumps(document))
    assert run(transport, env).complete is True


@pytest.mark.parametrize("operation", ["RTR_InitSession", "RTR_ExecuteCommand", "RTR_CheckCommandStatus", "RTR_DeleteSession"])
@pytest.mark.parametrize("rival_host", [HOST, HOST.upper()])
def test_overlapping_host_run_is_refused_before_requests(env, transport, operation, rival_host):
    rival = RecordedTransport([])
    original = transport.responders.copy()

    def overlap(args):
        with pytest.raises(CliError, match="Another local RTR run") as error:
            execute_run(
                rival,
                {**env, "FALCON_AXI_WRITE_LOG": env["FALCON_AXI_WRITE_LOG"] + ".other"},
                rival_host,
                "ps",
                f"{rival_host}:ps",
            )
        assert error.value.code == "READ_ONLY_VIOLATION"
        assert rival.requests == []
        return next(answer for responder in original if (answer := responder(operation, args)) is not None)

    transport.responders.insert(0, serve(operation, overlap))
    assert run(transport, env).cleanup == "deleted"
    transport.responders = original
    assert run(transport, env).complete is True


@pytest.mark.parametrize("confirmation", ["", "yes", "*:ps", HOST + ":ps ", HOST + ":ls"])
def test_confirmation_must_match_byte_for_byte(env, transport, confirmation):
    with pytest.raises(CliError) as error:
        run(transport, env, confirmation=confirmation)
    assert error.value.exit_code == 2
    assert transport.requests == []


@pytest.mark.parametrize(
    "command",
    [
        "get file",
        "put file",
        "runscript x",
        "reg set x",
        "reg delete x",
        "reg queryx x",
        "psx",
        "eventlog backup x",
        "eventlog export x",
        "eventlog",
        "ps;ls",
        "ps\nls",
        "cat x > y",
        "ps | ls",
        "cat $(ps)",
        'cat "$(ps)"',
        "cat `ps`",
        'cat "`ps`"',
        "cat x && ps",
        "cat x || ps",
        'cat "x;ps"',
        'cat "x|ps"',
        'cat "x&&ps"',
        'cat "x>y"',
        "cat (ps)",
        "cat 'unclosed",
        "cat\x00x",
    ],
)
def test_bad_command_is_refused_before_authentication(env, transport, command):
    with pytest.raises(CliError):
        run(transport, env, command)
    assert transport.requests == []


@pytest.mark.parametrize("command", sorted(COMMANDS - {"eventlog"}) + ["eventlog view Application", "eventlog list"])
def test_standard_command_tokens_are_admitted(command):
    assert parse_command(command) in {command.split()[0], "reg"}


@pytest.mark.parametrize(
    "command",
    [
        r'cat "C:\Program Files (x86)\Vendor\config.txt"',
        r"cat 'C:\Program Files (x86)\Vendor\config.txt'",
    ],
)
def test_quoted_parenthesized_path_is_sent_unchanged(env, transport, command):
    result = run(transport, env, command)
    assert result.complete is True
    assert transport.operation_requests("RTR_ExecuteCommand")[0].body == {
        "base_command": "cat",
        "command_string": command,
        "session_id": "synthetic-session",
    }
    assert result.cleanup == "deleted"


@pytest.mark.parametrize(
    "policy",
    [
        None,
        {},
        {"enabled": 1},
        {"enabled": True, "other": True},
        {"enabled": True, "commands": ["get"]},
        {"enabled": True, "commands": "ps"},
    ],
)
def test_profile_schema_rejects_widening_and_invalid_types(env, policy):
    replace_profile(env, policy)
    with pytest.raises(CliError) as error:
        load_profiles(env)
    assert error.value.code == "CONFIG_INVALID"


@pytest.mark.parametrize(
    "operation,error",
    [
        ("RTR_ExecuteCommand", CliError("NETWORK_UNREACHABLE", "synthetic send failure")),
        ("RTR_CheckCommandStatus", BudgetExpired()),
        ("RTR_CheckCommandStatus", KeyboardInterrupt()),
    ],
)
def test_failure_after_init_always_deletes(env, transport, operation, error):
    transport.responders.insert(0, serve(operation, fail(error)))
    with pytest.raises(type(error)):
        run(transport, env)
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1
    assert records(env)[-1]["cleanup"] == "deleted"


def test_cleanup_has_a_fresh_budget_after_execution_timeout(env, transport):
    def cleanup(args):
        assert 0 < remaining_seconds() <= 10
        return response(204, None)

    transport.responders.insert(0, serve("RTR_CheckCommandStatus", fail(BudgetExpired())))
    transport.responders.insert(0, serve("RTR_DeleteSession", cleanup))
    with pytest.raises(BudgetExpired):
        run(transport, env)
    assert records(env)[-1]["cleanup"] == "deleted"


def test_delete_failure_is_an_explicit_failed_outcome(env, transport):
    transport.responders.insert(0, serve("RTR_DeleteSession", response(500, {})))
    with pytest.raises(CliError, match="deletion") as error:
        run(transport, env)
    assert error.value.details["cleanup"] == "failed"
    assert error.value.details["complete"] is True
    assert error.value.details["output"] == "synthetic output"
    assert error.value.details["truncated"] is False
    assert records(env)[-1]["cleanup"] == "failed"
    assert records(env)[-1]["command_outcome"] == "complete"


def test_lost_init_is_unknown_owned_work_and_is_never_replayed(env, transport):
    transport.responders.insert(0, serve("RTR_InitSession", fail(BudgetExpired())))
    with pytest.raises(CliError, match="initialization outcome is unknown"):
        run(transport, env)
    assert len(transport.operation_requests("RTR_InitSession")) == 1
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert transport.operation_requests("RTR_DeleteSession") == []
    assert records(env)[-1]["cleanup"] == "unknown"


@pytest.mark.parametrize(
    "status,code,guidance",
    [
        (401, "AUTH_FAILED", "Run `falcon-axi auth status` after updating the credential"),
        (
            403,
            "SCOPE_DENIED",
            "Grant Real time response:read to the API client in the Falcon console "
            "under Support and resources > API clients and keys",
        ),
        (429, "RATE_LIMITED", "Wait for the rate limit window to reset and retry"),
    ],
)
def test_init_refusal_preserves_actionable_error_and_recovery(env, transport, status, code, guidance):
    transport.responders.insert(0, serve("RTR_InitSession", response(status, {})))
    with pytest.raises(CliError) as error:
        run(transport, env)
    assert error.value.code == code
    assert guidance in error.value.help
    assert error.value.details["cleanup"] == "unknown"
    assert error.value.details["run"] == records(env)[-1]["run"]
    assert error.value.details["output"] == ""
    assert records(env)[-1]["cleanup"] == "unknown"
    assert len(transport.operation_requests("RTR_InitSession")) == 1
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert transport.operation_requests("RTR_DeleteSession") == []


def test_init_scope_refusal_retains_required_scopes_when_outcome_write_fails(env, transport, monkeypatch):
    original = Journal.append

    def append(journal, record):
        if record["phase"] == "outcome":
            raise CliError("CONFIG_INSECURE", "synthetic outcome flush failure")
        original(journal, record)

    monkeypatch.setattr(Journal, "append", append)
    transport.responders.insert(0, serve("RTR_InitSession", response(403, {})))
    with pytest.raises(CliError) as error:
        run(transport, env)
    assert error.value.code == "SCOPE_DENIED"
    assert error.value.details["required_scopes"] == ["Real time response:read"]
    assert error.value.details["cleanup"] == "unknown"
    assert error.value.details["run"] == records(env)[0]["run"]
    assert error.value.details["journal_error"]["code"] == "CONFIG_INSECURE"


def test_intent_failure_prevents_authentication(env, transport, monkeypatch):
    monkeypatch.setattr(Journal, "append", lambda *args: (_ for _ in ()).throw(CliError("CONFIG_INSECURE", "synthetic")))
    with pytest.raises(CliError, match="synthetic"):
        run(transport, env)
    assert transport.requests == []


def test_outcome_failure_still_deletes_the_session(env, transport, monkeypatch):
    original = Journal.append

    def append(journal, record):
        if record["phase"] == "outcome":
            raise CliError("CONFIG_INSECURE", "synthetic outcome flush failure")
        original(journal, record)

    monkeypatch.setattr(Journal, "append", append)
    with pytest.raises(CliError, match="outcome flush") as error:
        run(transport, env)
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1
    assert error.value.details["cleanup"] == "deleted"
    assert error.value.details["output"] == "synthetic output"
    assert error.value.details["complete"] is True
    assert error.value.details["truncated"] is False
    assert error.value.details["run"] == records(env)[0]["run"]
    assert error.value.details["journal_error"]["code"] == "CONFIG_INSECURE"


@pytest.mark.parametrize(
    "operation,cleanup,message,output,complete",
    [
        ("RTR_DeleteSession", "failed", "deletion", "synthetic output", True),
        ("RTR_InitSession", "unknown", "synthetic lifecycle failure", "", False),
        ("RTR_ExecuteCommand", "deleted", "synthetic lifecycle failure", "", False),
    ],
)
def test_outcome_failure_preserves_lifecycle_recovery(
    env, transport, monkeypatch, operation, cleanup, message, output, complete
):
    original = Journal.append

    def append(journal, record):
        if record["phase"] == "outcome":
            raise CliError("CONFIG_INSECURE", "synthetic outcome flush failure")
        original(journal, record)

    monkeypatch.setattr(Journal, "append", append)
    transport.responders.insert(0, serve(operation, fail(CliError("NETWORK_UNREACHABLE", "synthetic lifecycle failure"))))
    with pytest.raises(CliError, match=message) as error:
        run(transport, env)
    assert error.value.details == {
        "cleanup": cleanup,
        "run": records(env)[0]["run"],
        "output": output,
        "complete": complete,
        "truncated": False,
        "journal_error": {"code": "CONFIG_INSECURE", "message": "synthetic outcome flush failure"},
    }


def test_output_byte_cap_returns_incomplete_and_deletes(env, transport):
    transport.responders.insert(
        0,
        serve(
            "RTR_CheckCommandStatus",
            response(
                200,
                {
                    "resources": [
                        {
                            "stdout": "x" * (OUTPUT_BYTES + 1),
                            "complete": True,
                            "sequence_id": 0,
                        }
                    ]
                },
            ),
        ),
    )
    result = run(transport, env)
    assert len(result.output.encode()) == OUTPUT_BYTES
    assert (result.complete, result.truncated, result.cleanup) == (False, True, "deleted")


def test_output_chunk_cap_is_finite(env, transport, monkeypatch):
    monkeypatch.setattr("falcon_axi.rtr_execute.time.sleep", lambda _: None)
    transport.responders.insert(
        0, serve("RTR_CheckCommandStatus", response(200, {"resources": [{"complete": False, "sequence_id": 0}]}))
    )
    result = run(transport, env)
    assert len(transport.operation_requests("RTR_CheckCommandStatus")) == OUTPUT_CHUNKS
    assert (result.complete, result.truncated, result.cleanup) == (False, True, "deleted")


def test_journal_and_output_are_redacted_before_truncation(env, transport):
    transport.responders.insert(
        0,
        serve(
            "RTR_CheckCommandStatus",
            response(
                200,
                {
                    "resources": [
                        {
                            "stdout": "synthetic-secret",
                            "complete": True,
                            "sequence_id": 0,
                        }
                    ]
                },
            ),
        ),
    )
    with redaction_scope():
        register_secret("sensitive-path")
        result = run(transport, env, "cat sensitive-path")
    assert result.output == "[redacted]"
    journal = Path(env["FALCON_AXI_WRITE_LOG"]).read_text()
    assert "sensitive-path" not in journal
    assert "synthetic-secret" not in journal


@pytest.mark.parametrize("destination", ["journal", "lock"])
@pytest.mark.parametrize("mode", [0o770, 0o777])
@pytest.mark.parametrize("existing", [False, True])
def test_replaceable_ancestors_refuse_before_requests(env, transport, tmp_path, destination, mode, existing):
    ancestor = tmp_path / "shared"
    ancestor.mkdir()
    private = ancestor / "private"
    if existing:
        private.mkdir(mode=0o700)
    ancestor.chmod(mode)
    if destination == "journal":
        env["FALCON_AXI_WRITE_LOG"] = str(private / "writes.log")
    else:
        env["XDG_STATE_HOME"] = str(private / "state")
    with pytest.raises(CliError) as error:
        run(transport, env)
    assert error.value.code == "CONFIG_INSECURE"
    assert transport.requests == []
    assert not (private / "writes.log").exists()
    assert not (private / "state").exists()
    assert private.exists() is existing


@pytest.mark.parametrize("mode", [0o700, 0o755, 0o1777])
def test_trusted_ancestors_allow_journaling_and_host_locking(env, transport, tmp_path, mode):
    ancestor = tmp_path / "trusted"
    ancestor.mkdir()
    ancestor.chmod(mode)
    env["FALCON_AXI_WRITE_LOG"] = str(ancestor / "private" / "writes.log")
    env["XDG_STATE_HOME"] = str(ancestor / "private" / "state")
    result = run(transport, env)
    assert result.complete is True
    assert result.cleanup == "deleted"
    assert records(env)[-1]["cleanup"] == "deleted"
    assert (ancestor / "private" / "state" / "falcon-axi" / f"rtr-{HOST}.lock").read_bytes() == b""


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "directory", "fifo"])
def test_journal_refuses_unsafe_targets(tmp_path, kind):
    target = tmp_path / "journal"
    source = tmp_path / "source"
    source.touch(mode=0o600)
    if kind == "symlink":
        target.symlink_to(source)
    elif kind == "hardlink":
        target.hardlink_to(source)
    elif kind == "public":
        target.touch(mode=0o644)
    elif kind == "directory":
        target.mkdir()
    else:
        os.mkfifo(target)
    with pytest.raises(CliError, match="durably written"):
        Journal(str(target)).append({"phase": "intent"})
    assert source.read_text() == ""


@pytest.mark.parametrize("id", sorted(RTR_EXECUTION_IDS))
def test_every_execution_operation_refuses_unchecked_requests(id):
    with pytest.raises(CliError) as error:
        HttpTransport().request(id, RequestArgs(ORIGIN, TOKEN))
    assert error.value.code == "READ_ONLY_VIOLATION"


def test_sink_refuses_a_forged_prepared_request_even_with_a_transport_permit():
    prepared = PreparedOperation("RTR_ExecuteCommand", ORIGIN, TOKEN, body={"base_command": "ps", "command_string": "ps"})
    with pytest.raises(CliError) as error:
        send_permitted_request(prepared, mint_permit())
    assert error.value.code == "READ_ONLY_VIOLATION"


def test_sink_rechecks_body_against_signed_authority():
    authority = RunAuthority(HOST, "ps", COMMANDS, {}, _AUTHORITY, ORIGIN, TOKEN)
    proof = authority.grant("RTR_InitSession", ORIGIN, TOKEN, {"device_id": HOST, "queue_offline": False}, {})
    prepared = PreparedOperation("RTR_InitSession", ORIGIN, TOKEN, body={"device_id": "b" * 32}, rtr=proof)
    with pytest.raises(CliError) as error:
        send_permitted_request(prepared, mint_permit())
    assert error.value.code == "READ_ONLY_VIOLATION"


def test_init_authority_is_consumed_before_a_send_can_be_replayed():
    authority = RunAuthority(HOST, "ps", COMMANDS, {}, _AUTHORITY, ORIGIN, TOKEN)
    authority.grant("RTR_InitSession", ORIGIN, TOKEN, {"device_id": HOST, "queue_offline": False}, {})
    with pytest.raises(CliError):
        authority.grant("RTR_InitSession", ORIGIN, TOKEN, {"device_id": HOST, "queue_offline": False}, {})


@pytest.mark.parametrize(
    "field,value",
    [
        ("effect", "read"),
        ("method", "GET"),
        ("path", "/real-time-response/entities/sessions/v2"),
        ("scopes", ("Real time response:write",)),
        ("id", "RTR_PulseSession"),
    ],
)
def test_n3_registry_admits_only_the_exact_tuples(field, value):
    with pytest.raises(ValueError):
        _seal(dataclasses.replace(operation("RTR_InitSession"), **{field: value}))


def test_read_only_enabled_after_init_still_allows_owned_cleanup(env, transport):
    def initialize(args):
        env["FALCON_AXI_READ_ONLY"] = "1"
        return response(201, {"resources": [{"session_id": "synthetic-session"}]})

    transport.responders.insert(0, serve("RTR_InitSession", initialize))
    with pytest.raises(CliError):
        run(transport, env)
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1
    assert records(env)[-1]["cleanup"] == "deleted"


def test_known_session_journal_failure_still_deletes(env, transport, monkeypatch):
    original = Journal.append

    def append(journal, record):
        if record["phase"] == "execute":
            raise CliError("CONFIG_INSECURE", "synthetic known-session flush failure")
        original(journal, record)

    monkeypatch.setattr(Journal, "append", append)
    with pytest.raises(CliError, match="known-session flush"):
        run(transport, env)
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


def test_redaction_covers_a_secret_split_across_chunks(env, transport, monkeypatch):
    monkeypatch.setattr("falcon_axi.rtr_execute.time.sleep", lambda _: None)
    chunks = iter(
        [
            response(200, {"resources": [{"stdout": "synthetic-", "complete": False, "sequence_id": 0}]}),
            response(200, {"resources": [{"stdout": "secret", "complete": True, "sequence_id": 1}]}),
        ]
    )
    transport.responders.insert(0, serve("RTR_CheckCommandStatus", lambda _: next(chunks)))
    assert run(transport, env).output == "[redacted]"


def test_polling_carries_protocol_sequence_independently_of_attempt_count(env, transport, monkeypatch):
    monkeypatch.setattr("falcon_axi.rtr_execute.time.sleep", lambda _: None)
    chunks = iter(
        [
            response(200, {"resources": [{"stdout": "", "complete": False, "sequence_id": 0}]}),
            response(200, {"resources": [{"stdout": "first", "complete": False, "sequence_id": 71}]}),
            response(200, {"resources": [{"stdout": "second", "complete": True, "sequence_id": 72}]}),
        ]
    )
    transport.responders.insert(0, serve("RTR_CheckCommandStatus", lambda _: next(chunks)))
    result = run(transport, env)
    assert result.output == "firstsecond"
    assert result.complete is True
    assert [args.query["sequence_id"] for args in transport.operation_requests("RTR_CheckCommandStatus")] == [0, 0, 71]


@pytest.mark.parametrize("sequence", [None, True, -1, "1", 0])
def test_invalid_or_regressing_output_sequence_fails_and_deletes(env, transport, monkeypatch, sequence):
    monkeypatch.setattr("falcon_axi.rtr_execute.time.sleep", lambda _: None)
    chunks = iter(
        [
            response(200, {"resources": [{"stdout": "first", "complete": False, "sequence_id": 1}]}),
            response(200, {"resources": [{"stdout": "invalid", "complete": True, "sequence_id": sequence}]}),
        ]
    )
    transport.responders.insert(0, serve("RTR_CheckCommandStatus", lambda _: next(chunks)))
    with pytest.raises(CliError, match="invalid output sequence") as error:
        run(transport, env)
    assert error.value.details["output"] == "first"
    assert error.value.details["cleanup"] == "deleted"


def test_execution_tier_does_not_replay_a_rate_limited_send():
    authority = RunAuthority(HOST, "ps", COMMANDS, {}, _AUTHORITY, ORIGIN, TOKEN)
    with requests_mock.Mocker() as mock:
        mock.post(ORIGIN + "/real-time-response/entities/sessions/v1", status_code=429)
        answer = HttpTransport().request(
            "RTR_InitSession",
            RequestArgs(
                ORIGIN,
                TOKEN,
                body={"device_id": HOST, "queue_offline": False},
                rtr=authority,
            ),
        )
    assert answer.status == 429
    assert len(mock.request_history) == 1


def test_sink_caps_response_acquisition_before_json_parsing():
    authority = RunAuthority(HOST, "ps", COMMANDS, {}, _AUTHORITY, ORIGIN, TOKEN)
    with requests_mock.Mocker() as mock:
        mock.post(ORIGIN + "/real-time-response/entities/sessions/v1", content=b"x" * (RESPONSE_BYTES + 1))
        with pytest.raises(CliError, match="acquisition byte cap"):
            HttpTransport().request(
                "RTR_InitSession",
                RequestArgs(
                    ORIGIN,
                    TOKEN,
                    body={"device_id": HOST, "queue_offline": False},
                    rtr=authority,
                ),
            )
    assert len(mock.request_history) == 1


def test_bounded_worker_preserves_and_verifies_the_signed_execution_grant(monkeypatch):
    def worker(args, **kwargs):
        import subprocess

        return subprocess.CompletedProcess(args, 0, stdout=json.dumps(_worker_reply(json.loads(kwargs["input"]))))

    monkeypatch.setattr("falcon_axi.transport.harness.subprocess.run", worker)
    authority = RunAuthority(HOST, "ps", COMMANDS, {}, _AUTHORITY, ORIGIN, TOKEN)
    with requests_mock.Mocker() as mock, request_budget(time.monotonic() + 5):
        mock.post(ORIGIN + "/real-time-response/entities/sessions/v1", json={"resources": [{"session_id": "synthetic"}]})
        answer = HttpTransport().request(
            "RTR_InitSession",
            RequestArgs(
                ORIGIN,
                TOKEN,
                body={"device_id": HOST, "queue_offline": False},
                rtr=authority,
            ),
        )
    assert answer.body == {"resources": [{"session_id": "synthetic"}]}
    assert mock.request_history[0].json() == {"device_id": HOST, "queue_offline": False}
