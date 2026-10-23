"""Synthetic N3 lifecycle, refusals, ownership, and cleanup through the real core."""

import dataclasses
import json
import os
import time
from pathlib import Path

import pytest
import requests_mock

from falcon_axi.core import CliError
from falcon_axi.credentials import load_profiles
from falcon_axi.redaction import redaction_scope, register_secret
from falcon_axi.rtr_execute import execute_run
from falcon_axi.rtr_journal import Journal
from falcon_axi.rtr_policy import COMMANDS, OUTPUT_BYTES, OUTPUT_CHUNKS, RESPONSE_BYTES, parse_command
from falcon_axi.transport import HttpTransport
from falcon_axi.transport.budget import BudgetExpired, remaining_seconds, request_budget
from falcon_axi.transport.harness import _worker_reply, mint_permit, send_permitted_request
from falcon_axi.transport.operations import CANONICAL, RTR_EXECUTION_IDS, _seal
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
    }


@pytest.fixture
def transport():
    return RecordedTransport(
        [
            serve("RTR_InitSession", response(201, {"resources": [{"session_id": "synthetic-session"}]})),
            serve("RTR_ExecuteCommand", response(201, {"resources": [{"cloud_request_id": "synthetic-command"}]})),
            serve("RTR_CheckCommandStatus", response(200, {"resources": [{"stdout": "synthetic output", "complete": True}]})),
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


def test_success_deletes_the_owned_session_and_journals_without_output(env, transport):
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
        "cat `ps`",
        "cat x && ps",
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
    assert records(env)[-1]["cleanup"] == "failed"


def test_lost_init_is_unknown_owned_work_and_is_never_replayed(env, transport):
    transport.responders.insert(0, serve("RTR_InitSession", fail(BudgetExpired())))
    with pytest.raises(CliError, match="initialization outcome is unknown"):
        run(transport, env)
    assert len(transport.operation_requests("RTR_InitSession")) == 1
    assert transport.operation_requests("RTR_ExecuteCommand") == []
    assert transport.operation_requests("RTR_DeleteSession") == []
    assert records(env)[-1]["cleanup"] == "unknown"


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
    with pytest.raises(CliError, match="outcome flush"):
        run(transport, env)
    assert len(transport.operation_requests("RTR_DeleteSession")) == 1


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
    transport.responders.insert(0, serve("RTR_CheckCommandStatus", response(200, {"resources": [{"complete": False}]})))
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
        _seal(dataclasses.replace(CANONICAL[0], **{field: value}))


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
            response(200, {"resources": [{"stdout": "synthetic-", "complete": False}]}),
            response(200, {"resources": [{"stdout": "secret", "complete": True}]}),
        ]
    )
    transport.responders.insert(0, serve("RTR_CheckCommandStatus", lambda _: next(chunks)))
    assert run(transport, env).output == "[redacted]"


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
