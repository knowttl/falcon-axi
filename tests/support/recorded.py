"""The offline transport (docs/design/v1.md §14.2).

It preserves the sealed entry-point shape and serves fixtures without any network access.
It is never reachable from the shipped binary: no flag, environment variable, or config key
selects it, and it lives only in the test tree.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from falcon_axi.transport.types import FalconResponse, OAuthTokenArgs, RequestArgs

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

Responder = Callable[[str, RequestArgs], FalconResponse | None]


def fixture(relative_path: str) -> FalconResponse:
    """Loads a wholly synthetic fixture (§14.4)."""
    parsed = json.loads((FIXTURES / relative_path).read_text(encoding="utf-8"))
    return as_response(parsed["response"])


def as_response(payload: Mapping[str, Any]) -> FalconResponse:
    return FalconResponse(status=payload["status"], headers=dict(payload.get("headers") or {}), body=payload.get("body"))


def response(status: int, body: Any, headers: Mapping[str, str] | None = None) -> FalconResponse:
    return FalconResponse(status=status, headers=dict(headers or {}), body=body)


class RecordedTransport:
    def __init__(self, responders: Sequence[Responder], oauth: Sequence[FalconResponse] | None = None) -> None:
        self.responders = list(responders)
        self.oauth = list(oauth) if oauth is not None else [fixture("oauth2/token-success.json")]
        self.requests: list[tuple[str, Any]] = []

    def request(self, id: str, args: RequestArgs) -> FalconResponse:
        self.requests.append(("operation", (id, args)))
        for responder in self.responders:
            answer = responder(id, args)
            if answer is not None:
                return answer
        raise AssertionError(f"no recorded response for {id}")

    def request_oauth_token(self, args: OAuthTokenArgs) -> FalconResponse:
        self.requests.append(("oauth", args))
        next_response = self.oauth.pop(0) if len(self.oauth) > 1 else (self.oauth[0] if self.oauth else None)
        if next_response is None:
            raise AssertionError("no recorded token response")
        return next_response

    def operation_requests(self, id: str) -> list[RequestArgs]:
        return [entry[1] for kind, entry in self.requests if kind == "operation" and entry[0] == id]

    def oauth_requests(self) -> list[OAuthTokenArgs]:
        return [entry for kind, entry in self.requests if kind == "oauth"]


def serve(id: str, answer: FalconResponse | Callable[[RequestArgs], FalconResponse]) -> Responder:
    def responder(requested: str, args: RequestArgs) -> FalconResponse | None:
        if requested != id:
            return None
        return answer(args) if callable(answer) else answer

    return responder


CREDENTIAL_ENV: Mapping[str, str] = {
    "FALCON_CLIENT_ID": "synthetic-client-id",
    "FALCON_CLIENT_SECRET": "synthetic-client-secret",
    "FALCON_AXI_CREDENTIALS_FILE": "/nonexistent/falcon-axi/credentials",
}

NO_CREDENTIAL_ENV: Mapping[str, str] = {"FALCON_AXI_CREDENTIALS_FILE": "/nonexistent/falcon-axi/credentials"}
