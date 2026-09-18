"""The sole network sink (docs/design/v1.md §3.3 property 6, docs/design/v1-python.md §3.2).

This file is the only place allowed to import `falconpy` or `requests`, and `send_permitted_request`
is the only function in it allowed to touch the network. Both sealed entry points mint a permit
after their registry or OAuth checks pass; a prepared request without a valid permit is refused
before network access.

falconpy's `APIHarnessV2.command` accepts any Falcon operation id, including every mutating one,
so the closed registry is checked before this module is ever reached.
"""

import os
from dataclasses import dataclass
from typing import Any

import requests
from falconpy import APIHarnessV2

from falcon_axi.core import CliError
from falcon_axi.transport.operations import operation
from falcon_axi.transport.types import FalconResponse, PreparedOperation, PreparedToken
from falcon_axi.version import user_agent

TIMEOUT_SECONDS = 30
OAUTH_PATH = "/oauth2/token"


@dataclass(frozen=True)
class Permit:
    """The module-private capability the sealed entry points mint after their checks pass.

    Only the instance below is accepted, so a forged permit cannot reach the network.
    """


_PERMIT = Permit()


def mint_permit() -> Permit:
    return _PERMIT


def _proxy() -> dict[str, str] | None:
    """FALCON_PROXY_URL is the variable name falcon-mcp uses, so one environment serves both."""
    url = os.environ.get("FALCON_PROXY_URL")
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
        return None


def _normalize(status: Any, headers: Any, body: Any) -> FalconResponse:
    lowered = {str(key).lower(): str(value) for key, value in dict(headers or {}).items()}
    code = int(status) if isinstance(status, (int, str)) and str(status).isdigit() else 0
    if 300 <= code < 400:
        raise _refuse_redirect()
    return FalconResponse(status=code, headers=lowered, body=body)


class _RecordingSession(requests.Session):
    """Preserves the true transport failure, which falconpy otherwise folds into a synthetic 500.

    falconpy catches every `requests` exception and returns `{status_code: 500, ...}` with the
    exception text in the body, which would erase the TLS_UNTRUSTED and NETWORK_UNREACHABLE codes
    the error envelope owes the caller (§9.2).
    """

    def __init__(self) -> None:
        super().__init__()
        self.failure: BaseException | None = None
        self.answer: requests.Response | None = None

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        try:
            self.answer = super().request(*args, **kwargs)
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
        if isinstance(prepared, PreparedToken):
            # D2 (docs/design/v1-python.md §3.3): falcon-axi mints the token itself, because
            # `requests` replays a POST body on a 307 or 308 and falconpy allows redirects on
            # the token path. No credential ever follows a redirect.
            token_answer = requests.post(
                f"{prepared.origin}{OAUTH_PATH}",
                data=dict(prepared.form),
                headers={
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "user-agent": user_agent(),
                },
                allow_redirects=False,
                timeout=TIMEOUT_SECONDS,
            )
            return _normalize(token_answer.status_code, token_answer.headers, _json_body(token_answer))

        descriptor = operation(prepared.operation_id)
        path_params = dict(prepared.path_params)
        if descriptor.id == "GetSearchStatusV1":
            # falconpy's uber path-variable map for this one operation lists `search_id` beside
            # `id` and reads every name it lists while interpolating, so both must be present.
            path_params["search_id"] = path_params["id"]
        session = _RecordingSession()
        harness = APIHarnessV2(
            access_token=prepared.token,
            base_url=prepared.origin,
            user_agent=user_agent(),
            timeout=TIMEOUT_SECONDS,
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
    return _normalize(answer.status_code, answer.headers, _json_body(answer))
