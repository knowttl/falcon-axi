"""Aggregated cloud risk reads, with no unsupported risk-detail command."""

from falcon_axi.cloud import CloudDomain, commands

COMMAND_SPECS = commands(
    CloudDomain(
        noun="cloud-risk",
        plural="cloud_risks",
        description="list aggregated cloud risks",
        query="combined_cloud_risks",
        entity=None,
        scope="Cloud Security API Risks:read",
        columns=("id", "rule_name", "severity", "status"),
        filter_example="severity:'Critical'+status:'Open'",
        note="Risk detail is not offered: the official API has no risk-detail endpoint or risk-id filter.",
    )
)
