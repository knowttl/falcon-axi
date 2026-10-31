"""The sole network sink (docs/design/v1.md §3.3 property 6, docs/design/v1-python.md §3.2).

This file is the only place allowed to import `falconpy` or `requests`, and `send_permitted_request`
is the only function in it allowed to touch the network. Both sealed entry points mint a permit
after their registry or OAuth checks pass; a prepared request without a valid permit is refused
before network access.

falconpy's `APIHarnessV2.command` accepts any Falcon operation id, including every mutating one,
so the closed registry is checked before this module is ever reached.
"""

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import Any

import requests
from falconpy import APIHarnessV2
from urllib3.util import Timeout

from falcon_axi.core import CliError
from falcon_axi.response_diagnostics import record_response
from falcon_axi.rtr_policy import RESPONSE_BYTES
from falcon_axi.transport.budget import TIMEOUT_SECONDS, BudgetExpired, deadline_after, remaining_seconds, request_budget
from falcon_axi.transport.graphql import is_registered_query
from falcon_axi.transport.malquery import validate_search_body
from falcon_axi.transport.operations import GRAPHQL_QUERY_IDS, operation
from falcon_axi.transport.rtr import _signing_key, validate_grant
from falcon_axi.transport.types import FalconResponse, PreparedOperation, PreparedToken
from falcon_axi.version import user_agent

OAUTH_PATH = "/oauth2/token"


@dataclass(frozen=True)
class Permit:
    """The module-private capability the sealed entry points mint after their checks pass.

    Only the instance below is accepted, so a forged permit cannot reach the network.
    """


_PERMIT = Permit()


def mint_permit() -> Permit:
    return _PERMIT


def _send_with_deadline(prepared: PreparedOperation | PreparedToken, permit: Permit) -> FalconResponse:
    if isinstance(prepared, PreparedOperation):
        validate_grant(prepared)
    remaining = remaining_seconds()
    if remaining is None or permit is not _PERMIT:
        return send_permitted_request(prepared, permit)
    values = {field.name: getattr(prepared, field.name) for field in fields(prepared)}
    payload = json.dumps(
        {
            "deadline": deadline_after(0),
            "rtr_key": _signing_key.get().hex(),
            "request": {key: dict(value) if isinstance(value, Mapping) else value for key, value in values.items()},
        }
    )
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-P", "-m", "falcon_axi.transport.harness"],
            input=payload,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=remaining_seconds(),
            check=True,
        )
    except subprocess.TimeoutExpired as error:
        raise BudgetExpired() from error
    except subprocess.CalledProcessError as error:
        raise CliError("UPSTREAM_ERROR", "the bounded Falcon request could not complete") from error
    answer = json.loads(result.stdout)
    if "error" in answer:
        failure = answer["error"]
        if failure["code"] == "WAIT_TIMEOUT":
            raise BudgetExpired()
        raise CliError(failure["code"], failure["message"], failure["help"], failure["details"])
    response = FalconResponse(**answer["response"])
    record_response(response.status, response.headers, response.body)
    return response


def _worker_reply(payload: dict[str, Any]) -> dict[str, Any]:
    values = payload["request"]
    prepared = PreparedToken(**values) if "form" in values else PreparedOperation(**values)
    key_token = _signing_key.set(bytes.fromhex(payload.get("rtr_key", _signing_key.get().hex())))
    try:
        return _bounded_worker_reply(prepared, payload["deadline"])
    finally:
        _signing_key.reset(key_token)


def _bounded_worker_reply(prepared: PreparedOperation | PreparedToken, deadline: float | None) -> dict[str, Any]:
    with request_budget(deadline):
        try:
            response = send_permitted_request(prepared, mint_permit())
        except CliError as error:
            return {"error": {"code": error.code, "message": error.message, "help": error.help, "details": error.details}}
        return {"response": {"status": response.status, "headers": dict(response.headers), "body": response.body}}


def _proxy() -> dict[str, str] | None:
    """The vendor-native name remains an alias for one minor release."""
    from falcon_axi.credentials import normalized_environment

    values = {key: os.environ[key] for key in ("FALCON_PROXY_URL", "FALCON_AXI_PROXY_URL") if key in os.environ}
    url = normalized_environment(values).get("FALCON_AXI_PROXY_URL")
    return {"https": url} if url else None


def _refuse_redirect() -> CliError:
    return CliError(
        "ORIGIN_NOT_ALLOWED",
        "the Falcon endpoint answered with a redirect and no credential was replayed",
        ["Supply a verified Falcon base URL with `--region <url>`"],
        {"invalid_component": "redirect"},
    )


def _causes(error: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: BaseException | None = error
    while seen is not None and not any(seen is entry for entry in chain):
        chain.append(seen)
        seen = seen.__cause__ or seen.__context__
    return chain


def _from_requests(error: BaseException) -> bool:
    return any(isinstance(cause, requests.exceptions.RequestException) for cause in _causes(error))


def _transport_failure(error: BaseException) -> CliError:
    if any(isinstance(cause, requests.exceptions.SSLError) for cause in _causes(error)):
        return CliError(
            "TLS_UNTRUSTED",
            "the Falcon endpoint presented a certificate that could not be verified",
            ["Check the system trust store and any TLS-intercepting proxy on this host"],
        )
    return CliError(
        "NETWORK_UNREACHABLE",
        "the Falcon endpoint could not be reached",
        [
            "Check network connectivity and any proxy settings for this host",
            "Run `falcon-axi auth status` once connectivity is restored",
        ],
    )


def _json_body(answer: requests.Response) -> Any:
    if not answer.content:
        return None
    try:
        return answer.json()
    except ValueError:
        # Preserve the received type for diagnostics, never its value in output.
        return ""


def _normalize(status: Any, headers: Any, body: Any, *, refuse_redirect: bool) -> FalconResponse:
    lowered = {str(key).lower(): str(value) for key, value in dict(headers or {}).items()}
    code = int(status) if isinstance(status, (int, str)) and str(status).isdigit() else 0
    if refuse_redirect and 300 <= code < 400:
        raise _refuse_redirect()
    record_response(code, lowered, body)
    return FalconResponse(status=code, headers=lowered, body=body)


class _RecordingSession(requests.Session):
    """Preserves the true transport failure, which falconpy otherwise folds into a synthetic 500.

    falconpy catches every `requests` exception and returns `{status_code: 500, ...}` with the
    exception text in the body, which would erase the TLS_UNTRUSTED and NETWORK_UNREACHABLE codes
    the error envelope owes the caller (§9.2).
    """

    def __init__(self, bounded: bool = False) -> None:
        super().__init__()
        self.failure: BaseException | None = None
        self.answer: requests.Response | None = None
        self.bounded = bounded

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        try:
            remaining_seconds()
            if self.bounded:
                kwargs["stream"] = True
            self.answer = super().request(*args, **kwargs)
            if self.bounded:
                data = bytearray()
                try:
                    for chunk in self.answer.iter_content(chunk_size=8192):
                        remaining_seconds()
                        if len(data) + len(chunk) > RESPONSE_BYTES:
                            raise CliError("UPSTREAM_ERROR", "RTR response exceeded its acquisition byte cap")
                        data.extend(chunk)
                    self.answer._content = bytes(data)
                finally:
                    self.answer.close()
        except Exception as error:
            self.failure = error
            raise
        return self.answer


def send_permitted_request(prepared: PreparedOperation | PreparedToken, permit: Permit) -> FalconResponse:
    if permit is not _PERMIT:
        raise CliError(
            "READ_ONLY_VIOLATION",
            "a request reached the network sink without a transport permit",
            ["falcon-axi sends only requests originated by its sealed transport; report this as a bug"],
        )
    try:
        remaining = remaining_seconds()
        # Requests accepts urllib3 Timeout objects, which its and falconpy's annotations omit.
        timeout = Timeout(total=min(TIMEOUT_SECONDS, remaining)) if remaining is not None else TIMEOUT_SECONDS
        if isinstance(prepared, PreparedToken):
            # D2 (docs/design/v1-python.md §3.3): falcon-axi mints the token itself, because
            # `requests` replays a POST body on a 307 or 308 and falconpy allows redirects on
            # the token path. A 3xx is returned, never followed, and Location is never read;
            # authenticate re-mints once against a verified region host (§6.4).
            token_answer = requests.post(
                f"{prepared.origin}{OAUTH_PATH}",
                data=dict(prepared.form),
                headers={
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "user-agent": user_agent(),
                },
                allow_redirects=False,
                timeout=timeout,  # type: ignore[arg-type]
            )
            return _normalize(
                token_answer.status_code,
                token_answer.headers,
                _json_body(token_answer),
                refuse_redirect=False,
            )

        descriptor = operation(prepared.operation_id)
        validate_grant(prepared)
        if descriptor.effect == "malquery-search":
            validate_search_body(prepared.body, prepared.query)
            if prepared.query or prepared.path_params:
                raise CliError("READ_ONLY_VIOLATION", "MalQuery search accepts only N4's bounded pattern body")
        if descriptor.id in GRAPHQL_QUERY_IDS and not is_registered_query(prepared.body):
            # The last check before the network: the GraphQL endpoint also accepts mutations (§4.4),
            # so nothing but a registered document may reach it, whatever built the prepared request.
            raise CliError(
                "READ_ONLY_VIOLATION",
                "a graphql request reached the network sink with a document that is not registered",
                ["falcon-axi sends only the query documents in its closed registry; report this as a bug"],
            )
        path_params = dict(prepared.path_params)
        if descriptor.id == "GetSearchStatusV1":
            # falconpy's uber path-variable map for this one operation lists `search_id` beside
            # `id` and reads every name it lists while interpolating, so both must be present.
            path_params["search_id"] = path_params["id"]
        session = _RecordingSession(bounded=prepared.rtr is not None)
        harness = APIHarnessV2(
            access_token=prepared.token,
            base_url=prepared.origin,
            user_agent=user_agent(),
            timeout=timeout,  # type: ignore[arg-type]
            proxy=_proxy(),
            debug=False,
            sanitize_log=True,
            session=session,
        )
        harness.command(
            descriptor.id,
            parameters=dict(prepared.query),
            body=prepared.body if prepared.body is not None else {},
            **path_params,
        )
        if session.failure is not None:
            if isinstance(session.failure, CliError):
                raise session.failure
            raise _transport_failure(session.failure) from session.failure
        answer = session.answer
    except CliError:
        raise
    except Exception as error:  # falconpy wraps a requests failure in its own SDK error
        if not _from_requests(error):
            raise
        raise _transport_failure(error) from error
    if answer is None:
        raise CliError(
            "UPSTREAM_ERROR",
            "Falcon returned a response falcon-axi could not read",
            ["Retry shortly", "Run `falcon-axi auth status` to re-check the credential"],
        )
    # The status, headers, and body are read from the response falconpy issued rather than from its
    # own container, so a redirect or an empty body is seen exactly as Falcon sent it.
    return _normalize(answer.status_code, answer.headers, _json_body(answer), refuse_redirect=True)


if __name__ == "__main__":
    json.dump(_worker_reply(json.load(sys.stdin)), sys.stdout)
