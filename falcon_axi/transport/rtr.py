"""One-run RTR authority and independently checked, signed sink grants (N3)."""

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.credentials import read_only
from falcon_axi.rtr_policy import OUTPUT_CHUNKS, parse_command, validate_host
from falcon_axi.transport.operations import RTR_EXECUTION_IDS

_PROCESS_KEY = os.urandom(32)
_signing_key: ContextVar[bytes] = ContextVar("rtr_signing_key", default=_PROCESS_KEY)
_AUTHORITY = object()


def _deny() -> CliError:
    return CliError("READ_ONLY_VIOLATION", "RTR request does not match this run's execution authority")


@dataclass
class RunAuthority:
    host: str
    command: str
    allowed: frozenset[str]
    env: Mapping[str, str]
    receipt: object = field(repr=False)
    origin: str = ""
    token: str = field(default="", repr=False)
    session: str | None = None
    request_id: str | None = None
    initialized: bool = False
    executed: bool = False
    deleted: bool = False
    status_requests: int = 0

    def grant(self, id: str, origin: str, token: str, body: Any, query: Mapping[str, Any]) -> dict[str, Any]:
        if self.receipt is not _AUTHORITY or origin != self.origin or token != self.token:
            raise _deny()
        validate_host(self.host)
        base = parse_command(self.command, self.allowed)
        expected_body: Any
        expected_query: dict[str, Any]
        if id != "RTR_DeleteSession" and (read_only(self.env) or read_only(os.environ)):
            raise _deny()
        if id == "RTR_InitSession":
            if self.initialized:
                raise _deny()
            expected_body, expected_query = {"device_id": self.host, "queue_offline": False}, {}
        elif id == "RTR_ExecuteCommand":
            if not self.session or self.executed or self.deleted:
                raise _deny()
            expected_body = {"base_command": base, "command_string": self.command, "session_id": self.session}
            expected_query = {}
        elif id == "RTR_CheckCommandStatus":
            if not self.request_id or not self.executed or self.deleted or self.status_requests >= OUTPUT_CHUNKS:
                raise _deny()
            sequence = query.get("sequence_id")
            if type(sequence) is not int or sequence < 0:
                raise _deny()
            expected_body, expected_query = None, {"cloud_request_id": self.request_id, "sequence_id": sequence}
        elif id == "RTR_DeleteSession":
            if not self.session or self.deleted:
                raise _deny()
            expected_body, expected_query = None, {"session_id": self.session}
        else:
            raise _deny()
        if body != expected_body or dict(query) != expected_query:
            raise _deny()
        # Consume init/execute before the send. An error never restores replay authority.
        if id == "RTR_InitSession":
            self.initialized = True
        elif id == "RTR_ExecuteCommand":
            self.executed = True
        elif id == "RTR_DeleteSession":
            self.deleted = True
        elif id == "RTR_CheckCommandStatus":
            self.status_requests += 1
        claims = {
            "id": id,
            "origin": origin,
            "token": token,
            "host": self.host,
            "command": self.command,
            "allowed": sorted(self.allowed),
            "session": self.session,
            "request_id": self.request_id,
            "body": expected_body,
            "query": expected_query,
        }
        return {"claims": claims, "signature": _signature(claims)}


def _signature(claims: Mapping[str, Any]) -> str:
    data = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_signing_key.get(), data, hashlib.sha256).hexdigest()


def prepare_grant(id: str, args: Any) -> dict[str, Any] | None:
    if id not in RTR_EXECUTION_IDS:
        if args.rtr is not None:
            raise _deny()
        return None
    if not isinstance(args.rtr, RunAuthority):
        raise _deny()
    return args.rtr.grant(id, args.base_url, args.token, args.body, dict(args.query or {}))


def validate_grant(prepared: Any) -> None:
    if prepared.operation_id not in RTR_EXECUTION_IDS:
        if prepared.rtr is not None:
            raise _deny()
        return
    proof = prepared.rtr
    if not isinstance(proof, dict) or set(proof) != {"claims", "signature"}:
        raise _deny()
    claims = proof["claims"]
    if not isinstance(claims, dict) or not isinstance(proof["signature"], str):
        raise _deny()
    if not hmac.compare_digest(proof["signature"], _signature(claims)):
        raise _deny()
    if (
        claims["id"] != prepared.operation_id
        or claims["origin"] != prepared.origin
        or claims["token"] != prepared.token
        or claims["body"] != prepared.body
        or claims["query"] != dict(prepared.query)
        or (prepared.operation_id != "RTR_DeleteSession" and read_only(os.environ))
    ):
        raise _deny()
    validate_host(claims["host"])
    parse_command(claims["command"], frozenset(claims["allowed"]))
