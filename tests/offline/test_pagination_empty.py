import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


@pytest.mark.parametrize(
    ("noun", "collection", "operation", "query_fixture", "entity_operation", "entity_fixture", "filter"),
    [
        (
            "account",
            "accounts",
            "query_accounts",
            "discover/accounts-query-page.json",
            "get_accounts",
            "discover/accounts-details-page.json",
            "username:'synthetic-user'",
        ),
        (
            "detection",
            "detections",
            "GetQueriesAlertsV2",
            "alerts/query-page.json",
            "PostEntitiesAlertsV2",
            "alerts/hydrate-page.json",
            "severity_name:'High'",
        ),
        (
            "host",
            "hosts",
            "QueryDevicesByFilter",
            "hosts/query-page.json",
            "PostDeviceDetailsV2",
            "hosts/details-page.json",
            "hostname:'WIN-*'",
        ),
        (
            "vuln",
            "vulnerabilities",
            "combinedQueryVulnerabilities",
            "spotlight/combined-page.json",
            None,
            None,
            "status:'open'",
        ),
    ],
)
@pytest.mark.parametrize("filtered", [False, True])
@pytest.mark.parametrize("total", [None, 3])
def test_empty_continuations_report_exhaustion_without_claiming_an_empty_inventory(
    noun: str,
    collection: str,
    operation: str,
    query_fixture: str,
    entity_operation: str | None,
    entity_fixture: str | None,
    filter: str,
    filtered: bool,
    total: int | None,
) -> None:
    pagination: dict[str, int | str] = {} if total is None else {"total": total}
    if noun == "vuln":
        pagination["after"] = "synthetic-next-page"
    responders = [
        serve(
            operation,
            response(200, {"resources": fixture(query_fixture).body["resources"], "meta": {"pagination": pagination}}),
        ),
    ]
    if entity_operation is not None and entity_fixture is not None:
        responders.append(serve(entity_operation, fixture(entity_fixture)))
    flags = ["--filter", filter] if filtered else (["--status", "open"] if noun == "vuln" else [])
    argv = [noun, "list", "--limit", "2", *flags]
    stdout, exit_code = run(argv, RecordedTransport(responders), dict(CREDENTIAL_ENV))
    page = decode(stdout)
    assert exit_code == 0
    assert len(page[collection]) == 2
    assert page["count"] == f"2 of {total if total is not None else 'unknown'} total"

    exhausted = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, exit_code = run([*argv, "--cursor", page["continuation_cursor"]], exhausted, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    assert decode(stdout) == {collection: f"no more {collection}"}
    (request,) = exhausted.operation_requests(operation)
    position = "synthetic-next-page" if noun == "vuln" else 2
    assert request.query["after" if noun == "vuln" else "offset"] == position
    assert len(exhausted.requests) == 2

    initial = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, exit_code = run(argv, initial, dict(CREDENTIAL_ENV))
    assert exit_code == 0
    if filtered:
        expected = f"0 {collection} matching the supplied filter"
    elif noun == "vuln":
        expected = "0 vulnerabilities matching status open"
    else:
        expected = f"0 {collection} in this tenant"
    assert decode(stdout)[collection] == expected
    assert len(initial.requests) == 2
