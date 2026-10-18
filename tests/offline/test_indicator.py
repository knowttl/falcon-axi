"""Indicator reads use first-party Intel shapes and opaque marker continuation."""

import base64
import json
import shlex

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

LIST = "QueryIntelIndicatorEntities"
SHOW = "GetIntelIndicatorEntities"
FILTER = "type:'domain',type:'ip_address'"
CONTEXT = CursorContext(
    operation=LIST,
    client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
    origin="https://api.crowdstrike.com",
    query=FILTER,
    sort="_marker.asc",
    model="marker",
)
SECRET = CREDENTIAL_ENV["FALCON_CLIENT_SECRET"]


def test_next_page_suggestion_continues_the_same_filter_without_repeating_the_boundary() -> None:
    recorded = RecordedTransport([serve(LIST, fixture("intel/indicators-page.json"))])
    stdout, code = run(["indicator", "list", "--filter", FILTER, "--limit", "2"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    document = decode(stdout)
    assert [row["id"] for row in document["indicators"]] == ["synthetic-indicator-1", "synthetic-indicator-2"]
    assert recorded.operation_requests(LIST)[0].query == {"filter": FILTER, "limit": 2, "sort": "_marker.asc"}
    command = document["help"][-1].split("`", 2)[1]
    resumed = RecordedTransport(
        [
            serve(
                LIST,
                response(
                    200,
                    {
                        "meta": {"pagination": {"total": 1}},
                        "resources": [{"id": "synthetic-indicator-3", "indicator": "three.example", "type": "domain"}],
                    },
                ),
            )
        ]
    )
    next_stdout, next_code = run(shlex.split(command)[1:], resumed, dict(CREDENTIAL_ENV))
    assert next_code == 0
    assert resumed.operation_requests(LIST)[0].query == {
        "filter": f"({FILTER})+_marker:>'1700000000bbb'",
        "limit": 2,
        "sort": "_marker.asc",
    }
    assert "continuation_cursor" not in decode(next_stdout)
    assert decode(next_stdout)["indicators"][0]["id"] == "synthetic-indicator-3"


@pytest.mark.parametrize("change", ["position", "model", "query", "credential"])
def test_changed_cursor_or_context_is_rejected_before_an_indicator_read(change: str) -> None:
    token = encode_cursor("1700000000bbb", CONTEXT, SECRET)
    filter = FILTER
    env = dict(CREDENTIAL_ENV)
    if change in ("position", "model"):
        payload = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        payload[change] = "1700000000ccc" if change == "position" else "token"
        token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    elif change == "query":
        filter = "type:'domain'"
    else:
        env["FALCON_CLIENT_SECRET"] = "synthetic-rotated-secret"
    recorded = RecordedTransport([])
    stdout, code = run(["indicator", "list", "--filter", filter, "--cursor", token], recorded, env)
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert not recorded.operation_requests(LIST)


@pytest.mark.parametrize("cursor", [None, encode_cursor("1700000000bbb", CONTEXT, SECRET)])
def test_empty_page_is_definitive(cursor: str | None) -> None:
    recorded = RecordedTransport([serve(LIST, response(200, {"resources": []}))])
    argv = ["indicator", "list", "--filter", FILTER]
    if cursor:
        argv += ["--cursor", cursor]
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "no more indicators" in stdout if cursor else "0 indicators" in stdout
    assert "continuation_cursor" not in stdout


def test_detail_reads_by_id_and_preserves_labels() -> None:
    recorded = RecordedTransport([serve(SHOW, fixture("intel/indicator-detail.json"))])
    stdout, code = run(["indicator", "show", "synthetic-indicator-1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests(SHOW)[0].body == {"ids": ["synthetic-indicator-1"]}
    assert decode(stdout)["indicator"]["labels"][0]["name"] == "synthetic-label"
    assert "_marker" not in stdout


@pytest.mark.parametrize(
    "status,body,error",
    [
        (404, {}, "NOT_FOUND"),
        (200, {"resources": []}, "NOT_FOUND"),
        (200, {"resources": [{"id": "synthetic-other"}]}, "UPSTREAM_ERROR"),
        (403, {}, "SCOPE_DENIED"),
    ],
)
def test_detail_failures_are_structured(status: int, body: dict, error: str) -> None:
    recorded = RecordedTransport([serve(SHOW, response(status, body))])
    stdout, code = run(["indicator", "show", "synthetic-indicator-1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert error in stdout


def test_missing_continuation_marker_fails_loudly() -> None:
    recorded = RecordedTransport([serve(LIST, response(200, {"resources": [{"id": "synthetic-id"}]}))])
    stdout, code = run(["indicator", "list", "--limit", "1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout


def test_list_scope_denial_names_the_intel_scope() -> None:
    recorded = RecordedTransport([serve(LIST, response(403, {}))])
    stdout, code = run(["indicator", "list"], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert "Indicators (Falcon Intelligence):read" in stdout


@pytest.mark.parametrize(
    "argv,operation",
    [
        (["indicator", "list", "--filter", "invalid"], LIST),
        (["indicator", "list", "--filter", FILTER, "--cursor", encode_cursor("1700000000bbb", CONTEXT, SECRET)], LIST),
        (["indicator", "show", "synthetic-indicator-1"], SHOW),
    ],
)
def test_filter_rejection_teaches_indicator_fields(argv: list[str], operation: str) -> None:
    recorded = RecordedTransport([serve(operation, response(400, {"errors": [{"message": "Invalid FQL filter"}]}))])
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"] == [
        "FQL uses + for AND, `,` for OR, and values must be quoted",
        "Example: `--filter \"type:'domain'\"`",
        "Run `falcon-axi indicator list --help` for the filterable fields",
    ]
