"""Correlation rule reads matching falcon-mcp modules/correlation_rules.py."""

from falcon_axi.collection import Collection

RULES = Collection(
    "correlation-rule",
    "correlation_rules",
    "combined_rules_get_v2",
    ("rule_id", "name", "status", "severity"),
    500,
)
COMMAND_SPECS = RULES.commands()
