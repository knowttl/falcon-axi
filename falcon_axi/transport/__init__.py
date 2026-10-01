"""The sealed transport (docs/design/v1.md §3.3).

The caller supplies an operation id, never a method, path, or URL; the descriptor is resolved from
the frozen registry, the destination is re-validated on every operation, and only then is a permit
minted for the single network sink.
"""

import time
from types import MappingProxyType

from falcon_axi.origin import assert_trusted_origin
from falcon_axi.transport.graphql import request_body
from falcon_axi.transport.operations import OperationId, operation, path_arguments
from falcon_axi.transport.retry import MAX_ATTEMPTS, retry_plan
from falcon_axi.transport.types import (
    FalconResponse,
    OAuthTokenArgs,
    PreparedOperation,
    PreparedToken,
    RequestArgs,
    Transport,
)

__all__ = [
    "FalconResponse",
    "OAuthTokenArgs",
    "OperationId",
    "RequestArgs",
    "Transport",
    "HttpTransport",
    "http_transport",
]


def _send(prepared: PreparedOperation | PreparedToken) -> FalconResponse:
    # falconpy loads with the sink, not with the package, so no command that never reaches the
    # network pays for it (AXI §10).
    from falcon_axi.transport.harness import mint_permit, send_permitted_request

    permit = mint_permit()
    attempt = 1
    while True:
        response = send_permitted_request(prepared, permit)
        plan = retry_plan(response.status, response.headers, attempt, time.time() * 1000) if attempt < MAX_ATTEMPTS else None
        if plan is None:
            return response
        time.sleep(plan.wait_ms / 1000)
        attempt += 1


class HttpTransport:
    """The only transport the shipped binary contains (§14.2)."""

    def request(self, id: OperationId, args: RequestArgs) -> FalconResponse:
        descriptor = operation(id)
        origin = assert_trusted_origin(args.base_url, args.allow_unknown_origin)
        return _send(
            PreparedOperation(
                operation_id=descriptor.id,
                origin=origin,
                token=args.token,
                query=MappingProxyType(dict(args.query or {})),
                body=request_body(descriptor, args.document, args.variables, args.body),
                path_params=MappingProxyType(path_arguments(descriptor, dict(args.path_params or {}))),
            )
        )

    def request_oauth_token(self, args: OAuthTokenArgs) -> FalconResponse:
        """The separately sealed authentication path (§3.3, §5.1).

        Its method and path are fixed, it cannot issue a scoped operation, and it does not pass
        through `request`, because authentication is not one of the registered read operations.
        """
        origin = assert_trusted_origin(args.base_url, args.allow_unknown_origin)
        form = {"client_id": args.client_id, "client_secret": args.client_secret}
        if args.member_cid:
            form["member_cid"] = args.member_cid
        return _send(PreparedToken(origin=origin, form=MappingProxyType(form)))


http_transport = HttpTransport()
