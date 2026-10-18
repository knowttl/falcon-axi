"""Firewall reads matching falcon-mcp modules/firewall.py search tools."""

from falcon_axi.collection import Collection

RULES = Collection(
    "firewall rule",
    "firewall_rules",
    "query_rules",
    ("id", "name", "enabled", "action"),
    5000,
    "get_rules",
    "token",
)
GROUPS = Collection(
    "firewall group",
    "firewall_groups",
    "query_rule_groups",
    ("id", "name", "enabled", "platform"),
    5000,
    "get_rule_groups",
    "token",
)
COMMAND_SPECS = (*RULES.commands(show=True), *GROUPS.commands())
