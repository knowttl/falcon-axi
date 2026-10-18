"""Cloud reads match falcon-mcp modules/cloud cloud_assets, cloud_iom and cloud_risks.

IOM fields follow cloud_iom.py's documented evaluation/cloud/resource nesting, rather than
the simplified root-level severity in some falcon-mcp test doubles.
"""

import re

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.transport.types import RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

DOMAINS = [
    ("cloud-asset", "cloud_security_assets_queries", "cloud_security_assets_entities_get", "assets"),
    ("iom", "cspm_evaluations_iom_queries", "cspm_evaluations_iom_entities", "iom"),
]


@pytest.mark.parametrize(("noun", "query_op", "entity_op", "prefix"), DOMAINS)
def test_two_step_reads_preserve_query_order_and_pagination(noun, query_op, entity_op, prefix):
    recorded = RecordedTransport(
        [
            serve(query_op, fixture(f"cloud/{prefix}-query.json")),
            serve(entity_op, fixture(f"cloud/{prefix}-entities.json")),
        ]
    )
    stdout, code = run([noun, "list", "--limit", "2", "--sort", "cloud_provider.asc"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert stdout.index(f"synthetic-{noun}-01,") < stdout.index(f"synthetic-{noun}-02,")
    query = recorded.operation_requests(query_op)[0].query
    assert query == (
        {"limit": 2, "sort": "cloud_provider.asc"}
        if noun == "cloud-asset"
        else {
            "limit": 2,
            "offset": 0,
            "sort": "cloud_provider.asc",
        }
    )
    assert recorded.operation_requests(entity_op)[0].query == {
        "ids": (
            f"synthetic-{noun}-01",
            f"synthetic-{noun}-02",
        )
    }
    assert "synthetic-cloud-cid" not in stdout
    assert "synthetic-omitted-configuration" not in stdout
    assert f"falcon-axi {noun} show <id>" in stdout
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE).group(1)
    followed = RecordedTransport([serve(query_op, response(200, {"resources": []}))])
    stdout, code = run([noun, "list", "--sort", "cloud_provider.asc", "--cursor", cursor], followed, CREDENTIAL_ENV)
    assert code == 0
    assert "continuation_cursor" not in stdout
    assert followed.operation_requests(query_op)[0].query == (
        {"limit": 20, "after": "synthetic-cloud-next", "sort": "cloud_provider.asc"}
        if noun == "cloud-asset"
        else {
            "limit": 20,
            "offset": 2,
            "sort": "cloud_provider.asc",
        }
    )


@pytest.mark.parametrize(("noun", "query_op", "entity_op", "prefix"), DOMAINS)
def test_hydration_batches_at_100_and_reorders_across_batches(noun, query_op, entity_op, prefix):
    ids = [f"synthetic-{index}" for index in range(201)]

    def hydrate(args: RequestArgs):
        return response(200, {"resources": [{"id": id} for id in reversed(args.query["ids"])]})

    recorded = RecordedTransport(
        [
            serve(query_op, response(200, {"resources": ids})),
            serve(entity_op, hydrate),
        ]
    )
    stdout, code = run([noun, "list", "--limit", "201"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert [len(args.query["ids"]) for args in recorded.operation_requests(entity_op)] == [100, 100, 1]
    assert re.findall(r"^  (synthetic-\d+),", stdout, re.MULTILINE) == ids


@pytest.mark.parametrize(("noun", "query_op", "entity_op", "prefix"), DOMAINS)
def test_show_uses_entity_read_and_keeps_finding_id_separate_from_resource_id(noun, query_op, entity_op, prefix):
    recorded = RecordedTransport([serve(entity_op, fixture(f"cloud/{prefix}-entities.json"))])
    stdout, code = run([noun, "show", f"synthetic-{noun}-01"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert f"id: synthetic-{noun}-01" in stdout
    assert "synthetic-bucket-id" in stdout
    assert "synthetic-cloud-cid" not in stdout
    assert "synthetic-omitted-configuration" not in stdout
    assert recorded.operation_requests(query_op) == []


@pytest.mark.parametrize(("noun", "query_op", "entity_op", "prefix"), DOMAINS)
def test_show_not_found_on_empty_entity_response(noun, query_op, entity_op, prefix):
    recorded = RecordedTransport([serve(entity_op, response(200, {"resources": []}))])
    stdout, code = run([noun, "show", "synthetic-missing"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "NOT_FOUND" in stdout


@pytest.mark.parametrize(
    ("argv", "operation", "before"),
    [
        (["cloud-asset", "list"], "cloud_security_assets_queries", []),
        (["iom", "list"], "cspm_evaluations_iom_queries", []),
        (["cloud-risk", "list"], "combined_cloud_risks", []),
        (
            ["cloud-asset", "list"],
            "cloud_security_assets_entities_get",
            [serve("cloud_security_assets_queries", fixture("cloud/assets-query.json"))],
        ),
        (
            ["iom", "list"],
            "cspm_evaluations_iom_entities",
            [serve("cspm_evaluations_iom_queries", fixture("cloud/iom-query.json"))],
        ),
        (["cloud-asset", "show", "synthetic-missing"], "cloud_security_assets_entities_get", []),
        (["iom", "show", "synthetic-missing"], "cspm_evaluations_iom_entities", []),
    ],
)
def test_upstream_not_found_suggests_the_corresponding_cloud_list(argv, operation, before):
    recorded = RecordedTransport([*before, serve(operation, response(404, {}))])
    stdout, code = run(argv, recorded, CREDENTIAL_ENV)
    document = decode(stdout)
    assert code == 1
    assert document["code"] == "NOT_FOUND"
    assert document["help"] == [f"Run `falcon-axi {argv[0]} list` to see current identifiers"]


@pytest.mark.parametrize(
    ("noun", "operation", "scope"),
    [
        ("cloud-asset", "cloud_security_assets_queries", "Assets"),
        ("iom", "cspm_evaluations_iom_queries", "Detections"),
        ("cloud-risk", "combined_cloud_risks", "Risks"),
    ],
)
def test_scope_denied_names_the_required_cloud_scope(noun, operation, scope):
    recorded = RecordedTransport([serve(operation, fixture("errors/403-scope.json"))])
    stdout, code = run([noun, "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "SCOPE_DENIED" in stdout
    assert f"Cloud Security API {scope}:read" in stdout


@pytest.mark.parametrize(("noun", "query_op", "entity_op", "prefix"), DOMAINS)
def test_entity_failure_fails_the_list_instead_of_claiming_an_empty_result(noun, query_op, entity_op, prefix):
    recorded = RecordedTransport(
        [
            serve(query_op, fixture(f"cloud/{prefix}-query.json")),
            serve(entity_op, fixture("errors/500-internal.json")),
        ]
    )
    stdout, code = run([noun, "list"], recorded, CREDENTIAL_ENV)
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout


def test_iom_reads_nested_evaluation_fields():
    recorded = RecordedTransport(
        [
            serve("cspm_evaluations_iom_queries", fixture("cloud/iom-query.json")),
            serve("cspm_evaluations_iom_entities", fixture("cloud/iom-entities.json")),
        ]
    )
    stdout, code = run(["iom", "list"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "ioms[2]{id,evaluation_severity,evaluation_status,resource_id}" in stdout
    assert "synthetic-iom-01,critical,non-compliant,synthetic-bucket-id" in stdout


def test_risks_use_combined_read_and_continue_by_offset():
    recorded = RecordedTransport([serve("combined_cloud_risks", fixture("cloud/risks.json"))])
    stdout, code = run(["cloud-risk", "list", "--limit", "2"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "count: 2 of 3 total" in stdout
    assert "synthetic-risk-01,Synthetic public bucket,Critical,Open" in stdout
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE).group(1)
    followed = RecordedTransport([serve("combined_cloud_risks", response(200, {"resources": []}))])
    _, code = run(["cloud-risk", "list", "--cursor", cursor], followed, CREDENTIAL_ENV)
    assert code == 0
    assert followed.operation_requests("combined_cloud_risks")[0].query["offset"] == 2


@pytest.mark.parametrize(
    "noun,operation",
    [
        ("cloud-asset", "cloud_security_assets_queries"),
        ("iom", "cspm_evaluations_iom_queries"),
        ("cloud-risk", "combined_cloud_risks"),
    ],
)
def test_empty_list_is_definitive_and_never_hydrates(noun, operation):
    recorded = RecordedTransport([serve(operation, response(200, {"resources": []}))])
    stdout, code = run([noun, "list", "--filter", "cloud_provider:'gcp'"], recorded, CREDENTIAL_ENV)
    assert code == 0
    assert "matching the supplied filter" in stdout
    assert "continuation_cursor" not in stdout
    assert len([kind for kind, _ in recorded.requests if kind == "operation"]) == 1


@pytest.mark.parametrize(
    "flags",
    [
        ["--filter", "cloud_provider:'gcp'"],
        ["--sort", "first_seen.desc"],
    ],
)
def test_changed_query_context_refuses_cursor_before_an_operation(flags):
    recorded = RecordedTransport([serve("combined_cloud_risks", fixture("cloud/risks.json"))])
    stdout, _ = run(["cloud-risk", "list", "--limit", "2"], recorded, CREDENTIAL_ENV)
    cursor = re.search(r"^continuation_cursor: (\S+)$", stdout, re.MULTILINE).group(1)
    refused = RecordedTransport([])
    stdout, code = run(["cloud-risk", "list", "--cursor", cursor, *flags], refused, CREDENTIAL_ENV)
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert [kind for kind, _ in refused.requests if kind == "operation"] == []


@pytest.mark.parametrize(
    "argv",
    [
        ["cloud-risk", "show", "synthetic-risk-01"],
        ["cloud-asset", "register"],
        ["iom", "remediate"],
        ["cloud-risk", "list", "--limit", "1001"],
    ],
)
def test_unsupported_cloud_input_fails_before_any_network(argv):
    recorded = RecordedTransport([])
    _, code = run(argv, recorded, CREDENTIAL_ENV)
    assert code == 2
    assert recorded.requests == []
