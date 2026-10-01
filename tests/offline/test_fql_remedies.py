import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve


@pytest.mark.parametrize(
    ("noun", "query_operation", "detail_operation", "query_fixture", "example"),
    [
        ("account", "query_accounts", "get_accounts", "discover/accounts-query-page.json", "username:'synthetic-user'"),
        (
            "detection",
            "GetQueriesAlertsV2",
            "PostEntitiesAlertsV2",
            "alerts/query-page.json",
            "severity_name:'High'+status:'new'",
        ),
        ("host", "QueryDevicesByFilter", "PostDeviceDetailsV2", "hosts/query-page.json", "hostname:'WIN-*'"),
    ],
)
def test_query_and_entity_filter_rejections_teach_the_failed_domains_fields(
    noun: str,
    query_operation: str,
    detail_operation: str,
    query_fixture: str,
    example: str,
) -> None:
    rejected = fixture("errors/400-fql.json")
    for argv, responders in (
        ([noun, "list"], [serve(query_operation, rejected)]),
        ([noun, "list"], [serve(query_operation, fixture(query_fixture)), serve(detail_operation, rejected)]),
        ([noun, "show", "synthetic-id"], [serve(detail_operation, rejected)]),
    ):
        stdout, exit_code = run(argv, RecordedTransport(responders), dict(CREDENTIAL_ENV))
        document = decode(stdout)
        assert exit_code == 2
        assert document["code"] == "FQL_INVALID"
        assert document["help"] == [
            "FQL uses + for AND, `,` for OR, and values must be quoted",
            f'Example: `--filter "{example}"`',
            f"Run `falcon-axi {noun} list --help` for the filterable fields",
        ]


@pytest.mark.parametrize(
    ("argv", "operation", "noun", "example"),
    [
        (["host", "logins", "synthetic-id"], "QueryDeviceLoginHistoryV2", "host", "hostname:'WIN-*'"),
        (["vuln", "list", "--status", "open"], "combinedQueryVulnerabilities", "vuln", "status:'open'"),
    ],
)
def test_combined_reads_use_their_own_fql_remedy(argv: list[str], operation: str, noun: str, example: str) -> None:
    recorded = RecordedTransport([serve(operation, fixture("errors/400-fql.json"))])
    stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert exit_code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"][1:] == [
        f'Example: `--filter "{example}"`',
        f"Run `falcon-axi {noun} list --help` for the filterable fields",
    ]
