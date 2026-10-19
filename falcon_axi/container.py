"""Read-only Kubernetes container inventory."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.domain import CommandOutput
from falcon_axi.inventory import read_page


def _list(ctx: Invocation) -> CommandOutput:
    return read_page(ctx, "containers", ("container_id", "container_name", "namespace", "running_status"), "container_name.asc")


COMMAND_SPECS = (
    CommandSpec(
        name="container list",
        summary="  container list            list Kubernetes containers",
        help="\n".join(
            [
                "falcon-axi container list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists Kubernetes containers in fixed container_name.asc order.",
                "--filter     FQL fields include container_id, cluster_name, namespace, running_status",
                "--limit      rows per call (default 20, ceiling 200)",
                "--cursor     opaque continuation token; keep the same filter and credential",
                "Falcon exposes at most 10000 records per query; narrow --filter at that boundary.",
                "Examples:",
                "  falcon-axi container list --filter \"namespace:'production'\"",
                "  falcon-axi container list --limit 100",
                "",
                "Read-only; requires Falcon Container Image:read and the corresponding license.",
            ]
        ),
        handler=_list,
        operations=("ReadContainerCombined",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(200, "Kubernetes container query"),
    ),
)
