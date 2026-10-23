"""ThreatGraph process trees through the CLI and its recorded transport seam."""

import re
import shlex

import pytest

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.transport.operations import operation, path_arguments
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, response, serve

ROOT = "pid:synthetic-device:3"


def tree_transport(children=None):
    records = fixture("threatgraph/process-tree.json").body["resources"]
    return RecordedTransport(
        [
            serve(
                "combined_summary_get",
                lambda args: response(200, {"resources": [r for r in records if r["id"] in args.query["ids"]]}),
            ),
            serve("combined_edges_get", children or fixture("threatgraph/children.json")),
        ]
    )


def test_three_generations_render_process_then_ancestors_then_children():
    recorded = tree_transport()
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert (
        stdout.index("synthetic-child.exe")
        < stdout.index("synthetic-parent.exe")
        < stdout.index("synthetic-root.exe")
        < stdout.index("synthetic-descendant.exe")
    )
    assert "synthetic-child.exe --inspect" in stdout
    assert "synthetic-sha256" in stdout
    assert "2026-01-01T00:02:00Z" in stdout
    assert "no further parent recorded" in stdout
    summaries = recorded.operation_requests("combined_summary_get")
    assert [r.query for r in summaries] == [
        {"ids": (ROOT,)},
        {"ids": ("pid:synthetic-device:2",)},
        {"ids": ("pid:synthetic-device:1",)},
    ]
    assert all(r.path_params == {"vertex_type": "processes"} for r in summaries)
    assert recorded.operation_requests("combined_edges_get")[0].query == {
        "ids": ROOT,
        "edge_type": "child_process",
        "limit": 100,
    }


def test_vertex_without_parent_stops_after_one_summary():
    recorded = tree_transport(response(200, {"resources": []}))
    stdout, code = run(["process", "tree", "pid:synthetic-device:1"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "0 child processes" in stdout
    assert "no further parent recorded" in stdout
    assert len(recorded.operation_requests("combined_summary_get")) == 1


def test_depth_bound_stops_at_five_ancestors():
    def summary(args):
        identifier = args.query["ids"][0]
        number = int(identifier.rsplit(":", 1)[1])
        return response(
            200, {"resources": [{"id": identifier, "edges": {"parent_process": [{"id": f"pid:synthetic:{number + 1}"}]}}]}
        )

    recorded = RecordedTransport(
        [serve("combined_summary_get", summary), serve("combined_edges_get", response(200, {"resources": []}))]
    )
    stdout, code = run(["process", "tree", "pid:synthetic:0"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "ancestor_5" in stdout
    assert "ancestor_6" not in stdout
    assert "depth limit reached" in stdout
    assert len(recorded.operation_requests("combined_summary_get")) == 6


def test_child_cursor_resumes_offset_and_binds_process():
    recorded = tree_transport()
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    cursor = re.search(r"continuation_cursor: (\S+)", stdout)[1]
    recorded.responders[-1] = serve("combined_edges_get", response(200, {"resources": []}))
    stdout, code = run(["process", "tree", ROOT, "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert recorded.operation_requests("combined_edges_get")[-1].query["offset"] == "synthetic-next-child"
    assert "no more child processes" in stdout
    assert "continuation_cursor" not in stdout
    before = len(recorded.operation_requests("combined_summary_get"))
    stdout, code = run(["process", "tree", "pid:synthetic:other", "--cursor", cursor], recorded, dict(CREDENTIAL_ENV))
    assert code == 2
    assert "VALIDATION_ERROR" in stdout
    assert len(recorded.operation_requests("combined_summary_get")) == before


@pytest.mark.parametrize("op", ["combined_summary_get", "combined_edges_get"])
def test_permission_denial_names_scope_and_subscription(op):
    recorded = tree_transport()
    recorded.responders.insert(0, serve(op, response(403, {})))
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "not permitted" in stdout
    assert "Threatgraph:read" in stdout
    assert "subscription with ThreatGraph API access" in stdout


def test_summary_path_requires_fixed_process_vertex_type():
    descriptor = operation("combined_summary_get")
    assert path_arguments(descriptor, {"vertex_type": "processes"}) == {"vertex_type": "processes"}
    with pytest.raises(CliError, match="restricted to processes"):
        path_arguments(descriptor, {"vertex_type": "devices"})


def test_cycle_stops_without_refetching_the_process():
    recorded = RecordedTransport(
        [
            serve(
                "combined_summary_get",
                response(200, {"resources": [{"id": ROOT, "edges": {"parent_process": [{"id": ROOT}]}}]}),
            ),
            serve("combined_edges_get", response(200, {"resources": []})),
        ]
    )
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "cycle detected" in stdout
    assert len(recorded.operation_requests("combined_summary_get")) == 1


def test_long_command_preview_expands_and_full_continuation_preserves_full():
    command = "synthetic-command " + "x" * 900
    recorded = tree_transport()
    recorded.responders.insert(
        0, serve("combined_summary_get", response(200, {"resources": [{"id": ROOT, "properties": {"CommandLine": command}}]}))
    )
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert "truncated, 918 chars total" in stdout
    assert command not in stdout
    stdout, code = run(["process", "tree", ROOT, "--full"], recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert command in stdout
    suggestion = re.search(r"Run `(.*?)` for the next child page", stdout)[1]
    argv = shlex.split(suggestion)[1:]
    assert "--full" in argv
    recorded.responders[-1] = serve("combined_edges_get", response(200, {"resources": []}))
    stdout, code = run(argv, recorded, dict(CREDENTIAL_ENV))
    assert code == 0
    assert command in stdout


def test_help_discloses_sdk_sample_shape_source_without_authentication():
    recorded = RecordedTransport([])
    stdout, code = run(["process", "tree", "--help"], recorded, {})
    assert code == 0
    assert "SDK sample" in stdout
    assert "not a resource schema in the API spec" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize("body", [{}, {"resources": [{}]}, {"resources": [], "errors": [{"code": 500}]}])
def test_invalid_summary_fails_instead_of_inventing_an_empty_tree(body):
    recorded = RecordedTransport([serve("combined_summary_get", response(200, body))])
    stdout, code = run(["process", "tree", ROOT], recorded, dict(CREDENTIAL_ENV))
    assert code == 1
    assert "UPSTREAM_ERROR" in stdout
