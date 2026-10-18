"""CSPM cloud resource inventory, separate from Discover endpoint assets."""

from falcon_axi.cloud import CloudDomain, commands

COMMAND_SPECS = commands(
    CloudDomain(
        noun="cloud-asset",
        plural="cloud_assets",
        description="list CSPM cloud assets",
        query="cloud_security_assets_queries",
        entity="cloud_security_assets_entities_get",
        scope="Cloud Security API Assets:read",
        model="token",
        columns=("id", "resource_name", "resource_type", "cloud_provider"),
        detail=(
            "resource_id",
            "account_id",
            "account_name",
            "region",
            "service",
            "active",
            "first_seen",
            "updated_at",
            "cloud_context.publicly_exposed",
            "cloud_context.detections.highest_severity",
        ),
    )
)
