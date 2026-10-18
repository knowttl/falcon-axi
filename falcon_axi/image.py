"""Read-only container image assessments and vulnerabilities."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.domain import CommandOutput
from falcon_axi.inventory import read_page


def _list(ctx: Invocation) -> CommandOutput:
    return read_page(ctx, "images", ("image_id", "repository", "tag", "highest_vulnerability_severity"), "image_id.asc")


def _vulnerabilities(ctx: Invocation) -> CommandOutput:
    return read_page(ctx, "vulnerabilities", ("cve_id", "severity", "cvss_score", "images_impacted"), "cve_id.asc")


COMMAND_SPECS = (
    CommandSpec(
        name="image list",
        summary="  image list                list container image assessments",
        help="\n".join(
            [
                "falcon-axi image list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists container image assessments in fixed image_id.asc order.",
                "--filter     FQL fields include image_id, image_digest, registry, repository, tag",
                "--limit      rows per call (default 20, ceiling 100)",
                "--cursor     opaque continuation token; keep the same filter and credential",
                "Falcon exposes at most 10000 records per query; narrow --filter at that boundary.",
                "Examples:",
                "  falcon-axi image list --filter \"repository:'example/service'\"",
                "  falcon-axi image list --limit 100",
                "",
                "Read-only; requires Falcon Container Image:read and the corresponding license.",
            ]
        ),
        handler=_list,
        operations=("GetCombinedImages",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "container image query"),
    ),
    CommandSpec(
        name="image vulnerabilities",
        summary="  image vulnerabilities     list container image vulnerabilities",
        help="\n".join(
            [
                "falcon-axi image vulnerabilities [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "Lists vulnerabilities across container images in fixed cve_id.asc order.",
                "--filter     FQL fields include cve_id, cvss_score, image_id, repository, severity",
                "--limit      rows per call (default 20, ceiling 100)",
                "--cursor     opaque continuation token; keep the same filter and credential",
                "Falcon exposes at most 10000 records per query; narrow --filter at that boundary.",
                "Examples:",
                '  falcon-axi image vulnerabilities --filter "cvss_score:>7"',
                "  falcon-axi image vulnerabilities --filter \"image_id:'synthetic-image'\"",
                "",
                "Read-only; requires Falcon Container Image:read and the corresponding license.",
            ]
        ),
        handler=_vulnerabilities,
        operations=("ReadCombinedVulnerabilities",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "container vulnerability query"),
    ),
)
