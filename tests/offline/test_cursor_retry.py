import base64
import json

import pytest

from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_cursor, encode_cursor
from falcon_axi.transport.retry import MAX_ATTEMPTS, RetryDecision, retry_plan

SECRET = "synthetic-client-secret"
CONTEXT = CursorContext(
    operation="GetQueriesAlertsV2",
    client_id="synthetic-client-id",
    query="severity_name:'High'",
    origin="https://api.crowdstrike.com",
    member_cid="synthetic-member-cid",
)


def _rejects(token: str, context: CursorContext, secret: str = SECRET) -> None:
    with pytest.raises(CliError) as error:
        decode_cursor(token, context, secret)
    assert error.value.code == "VALIDATION_ERROR"
    assert error.value.exit_code == 2


def _decoded(token: str) -> str:
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")


def test_a_cursor_round_trips_its_position() -> None:
    assert decode_cursor(encode_cursor(40, CONTEXT, SECRET), CONTEXT, SECRET) == 40


def test_a_cursor_carries_no_credential_or_tenant_value() -> None:
    decoded = _decoded(encode_cursor(40, CONTEXT, SECRET))
    assert SECRET not in decoded
    assert CONTEXT.client_id not in decoded
    assert "synthetic-member-cid" not in decoded
    assert "GetQueriesAlertsV2" in decoded


def test_any_changed_context_element_rejects_the_cursor_before_a_request() -> None:
    from dataclasses import replace

    token = encode_cursor(40, CONTEXT, SECRET)
    _rejects(token, replace(CONTEXT, query="severity_name:'Critical'"))
    _rejects(token, replace(CONTEXT, sort="created_timestamp|desc"))
    _rejects(token, replace(CONTEXT, origin="https://api.eu-1.crowdstrike.com"))
    _rejects(token, replace(CONTEXT, member_cid=None))
    _rejects(token, replace(CONTEXT, client_id="another-client"))
    _rejects(token, replace(CONTEXT, operation="combinedQueryVulnerabilities"))
    _rejects(token, CONTEXT, "rotated-secret")


def test_a_tampered_position_or_malformed_token_is_rejected() -> None:
    payload = json.loads(_decoded(encode_cursor(40, CONTEXT, SECRET)))
    payload["position"] = 0
    tampered = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    _rejects(tampered, CONTEXT)
    _rejects("not-a-cursor", CONTEXT)


def test_a_429_waits_until_a_future_x_ratelimit_retryafter() -> None:
    now = 1_000_000
    plan = retry_plan(429, {"x-ratelimit-retryafter": str((now + 5_000) / 1000)}, 1, now, 0)
    assert plan == RetryDecision(5_000, "retry_after")


def test_a_past_or_malformed_retry_after_falls_back_to_jittered_backoff() -> None:
    now = 1_000_000
    assert retry_plan(429, {"x-ratelimit-retryafter": "1"}, 1, now, 0) == RetryDecision(500, "backoff")
    assert retry_plan(429, {"x-ratelimit-retryafter": "soon"}, 2, now, 0) == RetryDecision(1_000, "backoff")
    assert retry_plan(429, {}, 1, now, 1) == RetryDecision(1_000, "backoff")


def test_a_503_ignores_the_retry_after_header_and_a_400_is_never_retried() -> None:
    now = 1_000_000
    assert retry_plan(503, {"x-ratelimit-retryafter": str((now + 60_000) / 1000)}, 1, now, 0) == RetryDecision(500, "backoff")
    assert retry_plan(400, {}, 1, now, 0) is None
    assert retry_plan(403, {}, 1, now, 0) is None


def test_retries_stop_after_the_last_attempt() -> None:
    assert retry_plan(429, {}, MAX_ATTEMPTS, 1_000_000, 0) is None
