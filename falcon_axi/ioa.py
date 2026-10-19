"""Custom IOA group reads matching falcon-mcp modules/custom_ioa.py."""

from falcon_axi.collection import Collection

GROUPS = Collection(
    "ioa group",
    "ioa_groups",
    "query_rule_groups_full",
    ("id", "name", "enabled", "platform"),
    500,
)
COMMAND_SPECS = GROUPS.commands()
