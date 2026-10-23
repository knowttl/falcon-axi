"""N3 execute core with bounded execution and unconditional session cleanup."""

import os
import signal
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from falcon_axi.auth import authenticate
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential, read_only, resolve_credential, tool_directory, write_log_path
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.origin import assert_trusted_origin, resolve_base_url
from falcon_axi.redaction import redact_text, redaction_scope, register_secret
from falcon_axi.rtr_journal import Journal
from falcon_axi.rtr_policy import EXECUTION_SECONDS, OUTPUT_BYTES, OUTPUT_CHUNKS, parse_command, validate_host
from falcon_axi.transport.budget import BudgetExpired, remaining_seconds, request_budget, rtr_cleanup_budget
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.rtr import _AUTHORITY, RunAuthority
from falcon_axi.transport.types import RequestArgs, Transport


@dataclass(frozen=True)
class RunResult:
    run_id: str
    output: str
    complete: bool
    truncated: bool
    cleanup: str


@contextmanager
def _defer_interrupt() -> Iterator[None]:
    # On POSIX, defer further terminal interrupts until the deletion attempt is finished.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _resource(body: Any) -> dict[str, Any]:
    resources = body.get("resources") if isinstance(body, dict) else None
    if not isinstance(resources, list) or len(resources) != 1 or not isinstance(resources[0], dict):
        raise CliError("UPSTREAM_ERROR", "RTR response did not identify one resource")
    return resources[0]


def _identifier(resource: Mapping[str, Any], key: str) -> str:
    value = resource.get(key)
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(char) < 33 for char in value):
        raise CliError("UPSTREAM_ERROR", "RTR response omitted a valid lifecycle identifier")
    return value


@redaction_scope(inherit=True)
def execute_run(
    transport: Transport,
    env: Mapping[str, str],
    host: str,
    command: str,
    confirmation: str,
    *,
    profile: str | None = None,
    config: str | None = None,
    region: str | None = None,
    member_cid: str | None = None,
    no_member_cid: bool = False,
) -> RunResult:
    """Authorize before authentication, execute once, and clean up within a separate budget.

    The CLI emits its preview before calling this core.
    A lost init response leaves the session id unknown; recovery is manual in Falcon, never a replay.
    """
    if read_only(env) or read_only(os.environ):
        raise CliError("READ_ONLY_VIOLATION", "FALCON_AXI_READ_ONLY forbids RTR execution")
    validate_host(host)
    credential = resolve_credential(env, profile=profile, config=config)
    credential = replace(
        credential,
        region=assert_trusted_origin(resolve_base_url(region=region or credential.region), False),
        member_cid=None if no_member_cid else member_cid or credential.member_cid,
    )
    if not credential.rtr.enabled:
        raise CliError("READ_ONLY_VIOLATION", "RTR execution requires explicit profile opt-in")
    base = parse_command(command, credential.rtr.commands)
    if confirmation != f"{host}:{command}":
        raise CliError("VALIDATION_ERROR", "RTR confirmation must match the device id and complete command exactly")
    if credential.member_cid:
        register_secret(credential.member_cid)
    journal = Journal(write_log_path(env))
    lock = Journal(str(tool_directory("state", env) / f"rtr-{host.lower()}.lock"))
    with lock.lock():
        return _execute_locked(transport, env, host, command, base, credential, journal)


def _execute_locked(
    transport: Transport,
    env: Mapping[str, str],
    host: str,
    command: str,
    base: str,
    credential: Credential,
    journal: Journal,
) -> RunResult:
    run_id = uuid.uuid4().hex
    record: dict[str, Any] = {
        "run": run_id,
        "target": host,
        "command": command,
        "authorization": "allowed",
        "phase": "intent",
        "command_outcome": "not_started",
        "cleanup": "not_needed",
    }
    journal.append(record)
    authority = RunAuthority(host, command, credential.rtr.commands, env, _AUTHORITY)
    output = ""
    raw_output = ""
    truncated = False
    complete = False
    failure: BaseException | None = None

    def request(id: OperationId, body: Any = None, query: Mapping[str, Any] | None = None) -> Any:
        remaining_seconds()
        response = transport.request(id, RequestArgs(authority.origin, authority.token, body=body, query=query, rtr=authority))
        if not 200 <= response.status < 300:
            raise translate_falcon_error(response, id, "RTR lifecycle")
        return response.body

    try:
        with request_budget(time.monotonic() + EXECUTION_SECONDS):
            record["phase"] = "authentication"
            origin = resolve_base_url(region=credential.region)
            session = authenticate(transport, credential, origin, credential.member_cid)
            authority.origin, authority.token = session.base_url, session.token
            record.update(phase="init", cleanup="unknown")
            # A crash or lost response after this flush is an unknown session, never proof of no session.
            journal.append(record)
            initialized = _resource(request("RTR_InitSession", {"device_id": host, "queue_offline": False}))
            authority.session = _identifier(initialized, "session_id")
            record.update(phase="execute", session=authority.session, cleanup="pending")
            journal.append(record)
            executed = _resource(
                request(
                    "RTR_ExecuteCommand",
                    {
                        "base_command": base,
                        "command_string": command,
                        "session_id": authority.session,
                    },
                )
            )
            authority.request_id = _identifier(executed, "cloud_request_id")
            record.update(phase="status", command_outcome="unknown")
            sequence = 0
            for _ in range(OUTPUT_CHUNKS):
                chunk = _resource(
                    request(
                        "RTR_CheckCommandStatus",
                        query={
                            "cloud_request_id": authority.request_id,
                            "sequence_id": sequence,
                        },
                    )
                )
                stdout, stderr = chunk.get("stdout", ""), chunk.get("stderr", "")
                if not isinstance(stdout, str) or not isinstance(stderr, str) or type(chunk.get("complete")) is not bool:
                    raise CliError("UPSTREAM_ERROR", "RTR returned malformed command output")
                returned_sequence = chunk.get("sequence_id")
                # Falcon omits sequence_id from the final response of a completed command; no further request follows it.
                if returned_sequence is None and chunk["complete"]:
                    returned_sequence = sequence
                if type(returned_sequence) is not int or returned_sequence < sequence:
                    raise CliError("UPSTREAM_ERROR", "RTR returned an invalid output sequence")
                sequence = returned_sequence
                raw_output += stdout + stderr
                encoded = redact_text(raw_output).encode()
                output = encoded[:OUTPUT_BYTES].decode("utf-8", errors="ignore")
                if len(raw_output.encode()) > OUTPUT_BYTES or len(encoded) > OUTPUT_BYTES:
                    truncated = True
                    break
                if chunk["complete"]:
                    complete = True
                    break
                if len(output.encode()) >= OUTPUT_BYTES:
                    truncated = True
                    break
                remaining = remaining_seconds()
                time.sleep(min(0.1, remaining) if remaining is not None else 0.1)
            else:
                truncated = True
            record["command_outcome"] = "complete" if complete else "incomplete"
    except BaseException as error:
        failure = error
        record["command_outcome"] = "unknown" if authority.executed else "not_started"
    finally:
        if authority.session:
            try:
                with _defer_interrupt(), rtr_cleanup_budget():
                    record["phase"] = "delete"
                    request("RTR_DeleteSession", query={"session_id": authority.session})
                    record["cleanup"] = "deleted"
            except BaseException as error:
                if record["cleanup"] == "deleted":
                    failure = error
                else:
                    record["cleanup"] = "failed"
                    failure = CliError(
                        "UPSTREAM_ERROR",
                        "RTR session deletion could not be confirmed",
                        details={"cleanup": "failed", "run": run_id},
                    )
                    failure.__cause__ = error
        if record["cleanup"] == "unknown":
            if not isinstance(failure, CliError) or isinstance(failure, BudgetExpired):
                unknown = CliError("UPSTREAM_ERROR", "RTR initialization outcome is unknown")
                unknown.__cause__ = failure
                failure = unknown
            failure.help += (
                "Reconcile the host's sessions in Falcon before retrying; never replay initialization automatically",
            )
        record["phase"] = "outcome"
        try:
            journal.append(record)
        except CliError as error:
            if isinstance(failure, CliError):
                failure.details["journal_error"] = {"code": error.code, "message": error.message}
            else:
                error.details["journal_error"] = {"code": error.code, "message": error.message}
                error.__cause__ = failure
                failure = error
    if failure is not None:
        if isinstance(failure, CliError):
            failure.details.update(
                run=run_id,
                output=output,
                complete=complete,
                truncated=truncated,
                cleanup=record["cleanup"],
            )
        raise failure
    return RunResult(run_id, output, complete, truncated, str(record["cleanup"]))
