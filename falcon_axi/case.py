"""Case reads matching falcon-mcp modules/cases.py search_cases and get_cases."""

from falcon_axi.collection import Collection

CASES = Collection(
    "case",
    "cases",
    "queries_cases_get_v1",
    ("id", "name", "status", "severity"),
    500,
    "entities_cases_post_v2",
)
COMMAND_SPECS = CASES.commands(show=True)
