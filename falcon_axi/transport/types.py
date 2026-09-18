"""The sealed transport surface (docs/design/v1.md §3.3)."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from falcon_axi.transport.operations import OperationId


@dataclass(frozen=True)
class FalconResponse:
    status: int
    headers: Mapping[str, str]
    body: Any = None


@dataclass(frozen=True)
class RequestArgs:
    base_url: str
    token: str
    query: Mapping[str, str | int] | None = None
    body: Any = None
    #: Values interpolated into the route's `{name}` variables, validated before the request is sent.
    path_params: Mapping[str, str] | None = None
    allow_unknown_origin: bool = False


@dataclass(frozen=True)
class OAuthTokenArgs:
    base_url: str
    client_id: str
    client_secret: str
    member_cid: str | None = None
    allow_unknown_origin: bool = False


class Transport(Protocol):
    """It exposes no raw URL, method, path, prepared request, or network primitive, and the tenancy
    selection lives on the token mint alone because Falcon binds a member CID at that point (§6.5).
    """

    def request(self, id: OperationId, args: RequestArgs) -> FalconResponse: ...

    def request_oauth_token(self, args: OAuthTokenArgs) -> FalconResponse: ...


@dataclass(frozen=True)
class PreparedOperation:
    """One registered operation, resolved and validated, ready for the sink."""

    operation_id: OperationId
    origin: str
    token: str
    query: Mapping[str, str | int] = field(default_factory=lambda: MappingProxyType({}))
    body: Any = None
    path_params: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))


@dataclass(frozen=True)
class PreparedToken:
    """The separately sealed authentication request (§5.1)."""

    origin: str
    form: Mapping[str, str]
