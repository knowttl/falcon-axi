"""N3 execute core with bounded execution and unconditional session cleanup."""

import os
import re
import shlex
import signal
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from falcon_axi.auth import authenticate
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential, read_only, resolve_credential, tool_directory, write_log_path
from falcon_axi.falcon_error import falcon_messages, translate_falcon_error
from falcon_axi.origin import assert_trusted_origin, resolve_base_url
from falcon_axi.redaction import redact_text, redaction_scope, register_secret
from falcon_axi.rtr_journal import Journal
from falcon_axi.rtr_policy import EXECUTION_SECONDS, OUTPUT_BYTES, OUTPUT_CHUNKS, cat_size_command, parse_command, validate_host
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
    size_unverified: bool = False


def _file_size(output: str, command: str) -> int | None:
    path = shlex.split(command, posix=False)[1].strip("\"'")
    names = {path, path.replace("\\", "/").rsplit("/", 1)[-1]}
    lines = [re.split(r"\s{2,}|\t", line.strip()) for line in output.splitlines() if line.strip()]
    if len(lines) != 2 or lines[0][:3] != ["Name", "Type", "Size (bytes)"]:
        return None
    row = lines[1]
    if len(row) < 3 or row[0] not in names or row[1].lower() != "file" or re.fullmatch(r"[0-9]+", row[2]) is None:
        return None
    return int(row[2])


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


def _command_chunks(
    request: Callable[[OperationId, Any, Mapping[str, Any] | None], Any], authority: RunAuthority,
) -> Iterator[tuple[str, str, bool]]:
    sequence = 0
    for _ in range(OUTPUT_CHUNKS - authority.status_requests):
        chunk = _resource(request("RTR_CheckCommandStatus", None, {
            "cloud_request_id": authority.request_id, "sequence_id": sequence,
        }))
        stdout, stderr = chunk.get("stdout", ""), chunk.get("stderr", "")
        if not isinstance(stdout, str) or not isinstance(stderr, str) or type(chunk.get("complete")) is not bool:
            raise CliError("UPSTREAM_ERROR", "RTR returned malformed command output")
        cursor = chunk.get("sequence_id")
        if cursor is None and chunk["complete"]:
            cursor = sequence
        if type(cursor) is not int or cursor < sequence:
            raise CliError("UPSTREAM_ERROR", "RTR returned an invalid output sequence")
        sequence = max(sequence + 1, cursor) if chunk["complete"] else cursor
        yield stdout, stderr, chunk["complete"]
        if chunk["complete"] and not stdout and not stderr:
            return
        if not chunk["complete"]:
            remaining = remaining_seconds()
            time.sleep(min(0.1, remaining) if remaining is not None else 0.1)


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
    size_unverified = base == "cat"
    stdout_bytes = 0
    has_stderr = False
    failure: BaseException | None = None

    def request(id: OperationId, body: Any = None, query: Mapping[str, Any] | None = None) -> Any:
        remaining_seconds()
        response = transport.request(id, RequestArgs(authority.origin, authority.token, body=body, query=query, rtr=authority))
        if not 200 <= response.status < 300:
            if (
                id == "RTR_ExecuteCommand"
                and response.status == 400
                and any("command not found" in message.lower() for message in falcon_messages(response))
            ):
                # Only the allowlisted base command is named; the full string may carry paths.
                raise CliError(
                    "UPSTREAM_ERROR",
                    f"Falcon does not accept the RTR command {base}",
                    [
                        "The command may not exist on this host's platform, or only in the interactive RTR console",
                        "Run `falcon-axi rtr run --help` for the commands and the platforms they were verified on",
                    ],
                )
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
            for stdout, stderr, ended in _command_chunks(request, authority):
                raw_output += stdout + stderr
                stdout_bytes += len(stdout.encode())
                has_stderr |= bool(stderr)
                encoded = redact_text(raw_output).encode()
                output = encoded[:OUTPUT_BYTES].decode("utf-8", errors="ignore")
                if len(raw_output.encode()) > OUTPUT_BYTES or len(encoded) > OUTPUT_BYTES:
                    truncated = True
                    break
                if ended and not stdout and not stderr:
                    complete = True
                    break
                if len(output.encode()) >= OUTPUT_BYTES:
                    truncated = True
                    break
            else:
                truncated = True
            if base == "cat":
                stream_complete = complete
                complete = False
                listing = cat_size_command(command, credential.rtr.commands)
                size = None
                if listing is not None and authority.status_requests < OUTPUT_CHUNKS:
                    try:
                        listed = _resource(request("RTR_ExecuteCommand", {
                            "base_command": "ls", "command_string": listing, "session_id": authority.session,
                        }))
                        authority.request_id = _identifier(listed, "cloud_request_id")
                        listing_output = ""
                        for text, stderr, ended in _command_chunks(request, authority):
                            if stderr:
                                break
                            listing_output += text
                            if len(listing_output.encode()) > OUTPUT_BYTES:
                                break
                            if ended and not text:
                                size = _file_size(listing_output, command)
                                break
                    except CliError:
                        pass
                size_unverified = size is None
                if size is not None:
                    returned_bytes = min(stdout_bytes, len(output.encode()))
                    truncated |= returned_bytes < size or size >= OUTPUT_BYTES
                    complete = (
                        stream_complete and not truncated and not has_stderr
                        and len(output.encode()) == size and stdout_bytes == size
                    )
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
            if base == "cat":
                failure.details["size_unverified"] = size_unverified
        raise failure
    return RunResult(run_id, output, complete, truncated, str(record["cleanup"]), size_unverified)
