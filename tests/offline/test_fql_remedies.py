import pytest
from toon_format import decode

from falcon_axi.cli import run
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve


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
        (
            "cloud-asset",
            "cloud_security_assets_queries",
            "cloud_security_assets_entities_get",
            "cloud/assets-query.json",
            "cloud_provider:'aws'",
        ),
        (
            "iom",
            "cspm_evaluations_iom_queries",
            "cspm_evaluations_iom_entities",
            "cloud/iom-query.json",
            "severity:'critical'+status:'non-compliant'",
        ),
        (
            "identity sensor",
            "QuerySensorsByFilter",
            "GetSensorDetails",
            "identity/sensors-query.json",
            "hostname:'SYNTH-DC-01'+status:'healthy'",
        ),
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
        ([*noun.split(), "list"], [serve(query_operation, rejected)]),
        ([*noun.split(), "list"], [serve(query_operation, fixture(query_fixture)), serve(detail_operation, rejected)]),
        ([*noun.split(), "show", "synthetic-id"], [serve(detail_operation, rejected)]),
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
        (["cloud-risk", "list"], "combined_cloud_risks", "cloud-risk", "severity:'Critical'+status:'Open'"),
        (["malware", "list"], "QueryMalwareEntities", "malware", "slug:'synthetic-family'"),
        (["malware", "show", "synthetic-family"], "GetMalwareEntities", "malware", "slug:'synthetic-family'"),
        (["iot", "list"], "query_iot_hostsV2", "iot", "device_type:'Printer'"),
        (["host-group", "list", "--filter", "bad"], "queryCombinedHostGroups", "host-group", "group_type:'dynamic'"),
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


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["cve", "list", "--filter", "bad"], "QueryVulnerabilities"),
        (["cve", "list"], "GetVulnerabilities"),
        (["cve", "show", "CVE-2099-0001"], "GetVulnerabilities"),
    ],
)
def test_cve_filter_errors_name_intelligence_fields(argv: list[str], operation: str) -> None:
    recorded = RecordedTransport(
        [
            serve(operation, fixture("errors/400-fql.json")),
            serve("QueryVulnerabilities", fixture("intel/query-page.json")),
        ]
    )
    stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert exit_code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"][1:] == [
        "Example: `--filter \"severity:'CRITICAL'\"`",
        "Run `falcon-axi cve list --help` for the filterable fields",
    ]


def test_host_group_members_filter_errors_name_host_attributes() -> None:
    recorded = RecordedTransport([serve("queryCombinedGroupMembers", fixture("errors/400-fql.json"))])
    stdout, exit_code = run(["host-group", "members", "synthetic-group", "--filter", "bad"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert exit_code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"][1:] == [
        "Example: `--filter \"platform_name:'Windows'\"`",
        "Run `falcon-axi host-group members --help` for the filterable fields",
    ]


@pytest.mark.parametrize(
    ("argv", "operation"),
    [
        (["identity", "sensor", "list"], "QuerySensorsByFilter"),
        (["identity", "sensor", "list"], "GetSensorDetails"),
        (["identity", "sensor", "show", "synthetic-id"], "GetSensorDetails"),
    ],
)
def test_sensor_not_found_errors_point_to_sensor_identifiers(argv: list[str], operation: str) -> None:
    recorded = RecordedTransport(
        [
            serve(operation, response(404, {"resources": []})),
            serve("QuerySensorsByFilter", fixture("identity/sensors-query.json")),
        ]
    )
    stdout, exit_code = run(argv, recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert exit_code == 1
    assert document["code"] == "NOT_FOUND"
    assert document["help"] == ["Run `falcon-axi identity sensor list` to see current identifiers"]


def test_iot_entity_filter_rejection_teaches_iot_fields() -> None:
    recorded = RecordedTransport(
        [
            serve("query_iot_hostsV2", fixture("discover/iot-query.json")),
            serve("get_iot_hosts", fixture("errors/400-fql.json")),
        ]
    )
    stdout, exit_code = run(["iot", "list"], recorded, dict(CREDENTIAL_ENV))
    document = decode(stdout)
    assert exit_code == 2
    assert document["code"] == "FQL_INVALID"
    assert document["help"][1:] == [
        "Example: `--filter \"device_type:'Printer'\"`",
        "Run `falcon-axi iot list --help` for the filterable fields",
    ]
