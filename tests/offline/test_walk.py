"""Wholly synthetic paged responses exercise the public CLI and its recorded seam."""

import re

import pytest

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, response

DOMAINS = {
    "detection": ("GetQueriesAlertsV2", "PostEntitiesAlertsV2", "composite_id", "composite_ids"),
    "host": ("QueryDevicesByFilter", "PostDeviceDetailsV2", "device_id", "ids"),
    "account": ("query_accounts", "get_accounts", "id", "ids"),
    "vuln": ("combinedQueryVulnerabilities", None, "id", "ids"),
}


def inventory(domain: str, count: int, known_total: bool = True, deleted: bool = False) -> RecordedTransport:
    query_op, hydrate_op, id_key, ids_key = DOMAINS[domain]

    def responder(op: str, args: RequestArgs):
        if op == query_op:
            offset = int(args.query.get("offset", args.query.get("after", 0)))
            size = int(args.query["limit"])
            end = min(count, offset + size)
            ids = [f"synthetic-{index}" for index in range(offset, end)]
            pagination = {"total": count} if known_total else {}
            if domain == "vuln":
                if end < count:
                    pagination["after"] = str(end)
                resources = [{id_key: id} for id in ids]
            else:
                resources = ids
            return response(200, {"resources": resources, "meta": {"pagination": pagination}})
        if op == hydrate_op:
            ids = args.query[ids_key] if domain == "account" else args.body[ids_key]
            return response(200, {"resources": [] if deleted else [{id_key: id} for id in reversed(ids)]})
        return None

    return RecordedTransport([responder])


def argv(domain: str, *flags: str) -> list[str]:
    return [domain, "list", *(["--status", "open"] if domain == "vuln" else []), *flags]


@pytest.mark.parametrize(
    "domain,budget,retained,reason,cursor,pages,hydrates",
    [
        ("detection", 2, 2, "max_rows", True, [2], 1),
        ("detection", 10000, 10000, "max_rows", False, [10000], 10),
        ("detection", 25000, 10000, "pagination_limit", False, [10000], 10),
        ("host", 2, 2, "max_rows", True, [2], 1),
        ("host", 9999, 9999, "max_rows", False, [5000, 4999], 2),
        ("host", 10000, 9999, "pagination_limit", False, [5000, 4999], 2),
        ("account", 1000, 1000, "max_rows", True, [100] * 10, 10),
        ("vuln", 11000, 11000, "max_rows", True, [5000, 5000, 1000], 0),
    ],
)
def test_budget_wall_reachability_and_request_cost(domain, budget, retained, reason, cursor, pages, hydrates):
    recorded = inventory(domain, 41892)
    stdout, code = run(argv(domain, "--all", "--max-rows", str(budget)), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert f"count: {retained} of 41892 total\n" in stdout
    assert "partial: true\n" in stdout
    assert f"stop_reason: {reason}\n" in stdout
    assert ("continuation_cursor:" in stdout) is cursor
    query_op, hydrate_op, _, _ = DOMAINS[domain]
    queries = recorded.operation_requests(query_op)
    assert [q.query["limit"] for q in queries] == pages
    assert len(recorded.requests) == 1 + len(pages) + hydrates
    if domain == "host" and retained == 9999:
        assert [q.query["offset"] for q in queries] == [0, 5000]
        assert "Narrow the filter" in stdout
    if domain == "detection" and not cursor:
        assert "PostCombinedAlertsV1" in stdout
    if hydrate_op:
        chunks = recorded.operation_requests(hydrate_op)
        if domain == "detection":
            assert all(len(q.body["composite_ids"]) <= 1000 for q in chunks)


@pytest.mark.parametrize("domain,cost", [("detection", 3), ("host", 3), ("account", 21), ("vuln", 2)])
def test_default_budget_ignores_single_page_limit(domain, cost):
    recorded = inventory(domain, 1001)
    stdout, code = run(argv(domain, "--all", "--limit", "1"), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 1000 of 1001 total\n" in stdout
    assert len(recorded.requests) == cost


@pytest.mark.parametrize("domain", DOMAINS)
def test_partial_cursor_resumes_at_the_next_unseen_row(domain):
    recorded = inventory(domain, 5)
    stdout, code = run(argv(domain, "--all", "--max-rows", "2"), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    cursor = re.search(r"^continuation_cursor: (.+)$", stdout, re.MULTILINE)[1]
    stdout, code = run(argv(domain, "--all", "--max-rows", "3", "--cursor", cursor), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 3 of 5 total\n" in stdout
    assert "synthetic-2" in stdout and "synthetic-4" in stdout
    assert "synthetic-0" not in stdout and "synthetic-1" not in stdout
    assert "partial:" not in stdout and "continuation_cursor:" not in stdout


@pytest.mark.parametrize("domain", DOMAINS)
@pytest.mark.parametrize("known_total", [True, False])
def test_short_final_page_retains_earlier_pages_without_partial_marker(domain, known_total):
    recorded = inventory(domain, 101, known_total)
    stdout, code = run(argv(domain, "--all"), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert f"count: 101 of {101 if known_total else 'unknown'} total\n" in stdout
    assert "partial:" not in stdout and "continuation_cursor:" not in stdout


@pytest.mark.parametrize("domain,wall", [("detection", 10000), ("host", 9999)])
def test_starting_at_wall_fails_without_data_requests(domain, wall):
    context = CursorContext(DOMAINS[domain][0], CREDENTIAL_ENV["FALCON_CLIENT_ID"], "https://api.crowdstrike.com")
    cursor = encode_cursor(wall, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    recorded = inventory(domain, 41892)
    stdout, code = run(argv(domain, "--all", "--cursor", cursor), recorded, dict(CREDENTIAL_ENV))
    assert code == 1 and "PAGINATION_LIMIT" in stdout
    assert len(recorded.requests) == 1


def test_discover_offsets_have_no_ten_thousand_wall():
    context = CursorContext("query_accounts", CREDENTIAL_ENV["FALCON_CLIENT_ID"], "https://api.crowdstrike.com")
    cursor = encode_cursor(10000, context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])
    recorded = inventory("account", 10101)
    stdout, code = run(argv("account", "--all", "--cursor", cursor), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 101 of 10101 total\n" in stdout
    assert "partial:" not in stdout


@pytest.mark.parametrize(
    "domain,flags",
    [
        ("detection", ("--max-rows", "2")),
        ("detection", ("--all", "--max-rows", "0")),
        ("detection", ("--all", "--max-rows", "-1")),
        ("detection", ("--all", "--max-rows", "abc")),
        ("host", ("--all", "--max-rows", "0")),
        ("account", ("--all", "--max-rows", "0")),
        ("vuln", ("--all", "--max-rows", "0")),
    ],
)
def test_invalid_budget_fails_before_authentication(domain, flags):
    recorded = inventory(domain, 5)
    stdout, code = run(argv(domain, *flags), recorded, dict(CREDENTIAL_ENV))
    assert code == 2 and "VALIDATION_ERROR" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize("domain,budget", [("detection", 10000), ("host", 9999)])
def test_wall_with_all_hydrated_rows_gone_is_an_error(domain, budget):
    recorded = inventory(domain, 41892, deleted=True)
    stdout, code = run(argv(domain, "--all", "--max-rows", str(budget)), recorded, dict(CREDENTIAL_ENV))
    assert code == 1 and "PAGINATION_LIMIT" in stdout
    assert "Narrow the filter" in stdout


def test_deleted_entities_count_only_retained_rows_and_preserve_query_cursor():
    recorded = inventory("account", 101, deleted=True)
    stdout, code = run(argv("account", "--all", "--max-rows", "100"), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 0 of 101 total\n" in stdout
    assert "partial: true\n" in stdout and "continuation_cursor:" in stdout
    assert len(recorded.requests) == 3


def test_empty_terminal_page_retains_earlier_rows_when_total_is_unknown():
    recorded = inventory("account", 100, known_total=False)
    stdout, code = run(argv("account", "--all"), recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "count: 100 of unknown total\n" in stdout
    assert "partial:" not in stdout and "continuation_cursor:" not in stdout
    assert len(recorded.operation_requests("query_accounts")) == 2
    assert len(recorded.operation_requests("get_accounts")) == 1
