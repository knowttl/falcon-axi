"""An opaque continuation token (docs/design/v1.md §7.2).

It carries the operation, pagination model, and position, plus a non-reversible HMAC over the
invocation context. It never carries a credential value or the tenant CID, and a cursor whose
context changed is rejected before any request is made.
"""

import base64
import binascii
import hmac
import json
from dataclasses import dataclass
from hashlib import sha256

from falcon_axi.core import CliError
from falcon_axi.transport.operations import OperationId


@dataclass(frozen=True)
class CursorContext:
    operation: OperationId
    client_id: str
    origin: str
    query: str | None = None
    sort: str | None = None
    member_cid: str | None = None


def _fingerprint(position: int, context: CursorContext, client_secret: str) -> str:
    canonical = json.dumps(
        {
            "client_id": context.client_id,
            "member_cid": context.member_cid,
            "model": "offset",
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


def encode_cursor(position: int, context: CursorContext, client_secret: str) -> str:
    payload = json.dumps(
        {
            "operation": context.operation,
            "model": "offset",
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


def decode_cursor(token: str, context: CursorContext, client_secret: str) -> int:
    """Recomputes the fingerprint from the current invocation and returns the position it continues."""
    try:
        padded = token + "=" * (-len(token) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as error:
        raise _reject() from error
    if (
        not isinstance(payload, dict)
        or payload.get("operation") != context.operation
        or payload.get("model") != "offset"
        or not isinstance(payload.get("position"), int)
        or isinstance(payload.get("position"), bool)
        or payload["position"] < 0
        or not isinstance(payload.get("fingerprint"), str)
    ):
        raise _reject()
    expected = _fingerprint(payload["position"], context, client_secret)
    if not hmac.compare_digest(expected, payload["fingerprint"]):
        raise _reject()
    position: int = payload["position"]
    return position
