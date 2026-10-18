"""Indicators of Misconfiguration: individual rule-against-resource findings."""

from falcon_axi.cloud import CloudDomain, commands

COMMAND_SPECS = commands(
    CloudDomain(
        noun="iom",
        plural="ioms",
        description="list cloud Indicators of Misconfiguration",
        query="cspm_evaluations_iom_queries",
        entity="cspm_evaluations_iom_entities",
        scope="Cloud Security API Detections:read",
        columns=("id", "evaluation.severity", "evaluation.status", "resource.id"),
        detail=(
            "cloud.provider",
            "cloud.account_id",
            "cloud.region",
            "resource.service",
            "evaluation.first_detected",
            "evaluation.last_detected",
        ),
        filter_example="severity:'critical'+status:'non-compliant'",
    )
)
