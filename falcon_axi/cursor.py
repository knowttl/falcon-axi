"""An opaque continuation token (docs/design/v1.md §7.2).

It carries the operation, pagination model, and position, plus a non-reversible HMAC over the
invocation context. It never carries a credential value or the tenant CID, and a cursor whose
context changed is rejected before any request is made.

Two of Falcon's three pagination models reach the CLI: Alerts and Hosts advance an integer offset,
Spotlight carries an opaque `after` token (§7.1). Both travel in this one token shape, so the
agent-facing vocabulary is `--cursor` either way.
"""

import base64
import binascii
import hmac
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from falcon_axi.core import CliError
from falcon_axi.transport.operations import OperationId

Position = int | str


@dataclass(frozen=True)
class CursorContext:
    operation: OperationId
    client_id: str
    origin: str
    query: str | None = None
    sort: str | None = None
    member_cid: str | None = None
    model: Literal["offset", "token"] = "offset"


def _fingerprint(position: Position, context: CursorContext, client_secret: str) -> str:
    canonical = json.dumps(
        {
            "client_id": context.client_id,
            "member_cid": context.member_cid,
            "model": context.model,
            "operation": context.operation,
            "origin": context.origin,
            "position": position,
            "query": context.query,
            "sort": context.sort,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hmac.new(client_secret.encode("utf-8"), canonical.encode("utf-8"), sha256).hexdigest()


def encode_cursor(position: Position, context: CursorContext, client_secret: str) -> str:
    payload = json.dumps(
        {
            "operation": context.operation,
            "model": context.model,
            "position": position,
            "fingerprint": _fingerprint(position, context, client_secret),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _reject() -> CliError:
    return CliError(
        "VALIDATION_ERROR",
        "this cursor does not continue the current query",
        [
            "A cursor is bound to its operation, filter, sort, region, tenant selection, and credential",
            "Re-run the command without `--cursor` to start a fresh read",
        ],
    )


def _position_of(payload: object, model: str) -> Position:
    if not isinstance(payload, dict) or payload.get("model") != model:
        raise _reject()
    position = payload.get("position")
    if model == "offset":
        if not isinstance(position, int) or isinstance(position, bool) or position < 0:
            raise _reject()
        return position
    if not isinstance(position, str) or not position:
        raise _reject()
    return position


def decode_cursor(token: str, context: CursorContext, client_secret: str) -> Position:
    """Recomputes the fingerprint from the current invocation and returns the position it continues."""
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as error:
        raise _reject() from error
    position = _position_of(payload, context.model)
    if (
        not isinstance(payload, dict)
        or payload.get("operation") != context.operation
        or not isinstance(payload.get("fingerprint"), str)
    ):
        raise _reject()
    expected = _fingerprint(position, context, client_secret)
    if not hmac.compare_digest(expected, payload["fingerprint"]):
        raise _reject()
    return position


def decode_offset(token: str, context: CursorContext, client_secret: str) -> int:
    """The offset-model position, for the Alerts and Hosts walks (§7.1)."""
    position = decode_cursor(token, context, client_secret)
    if not isinstance(position, int):
        raise _reject()
    return position


def decode_after(token: str, context: CursorContext, client_secret: str) -> str:
    """The token-model position, for Spotlight's `after` pagination (§7.1)."""
    position = decode_cursor(token, context, client_secret)
    if not isinstance(position, str):
        raise _reject()
    return position
