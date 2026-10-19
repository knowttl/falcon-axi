"""Read the four exclusion inventories using the official falcon-mcp operation mapping."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput
from falcon_axi.inventory import list_records, show_record
from falcon_axi.transport.operations import OperationId

# falcon_mcp/modules/exclusions.py: _OPERATIONS, _LIMIT_CAP, _search_by_type.
TYPES: dict[str, tuple[OperationId, OperationId]] = {
    "ml": ("exclusions_search_v2", "exclusions_get_v2"),
    "ioa": ("ss_ioa_exclusions_search_v2", "ss_ioa_exclusions_get_v2"),
    "sensor-visibility": ("querySensorVisibilityExclusionsV1", "getSensorVisibilityExclusionsV1"),
    "certificate": ("cb_exclusions_query_v1", "cb_exclusions_get_v1"),
}


def validate_type(type: str | None, limit: int = 20) -> None:
    if type not in TYPES:
        raise CliError("VALIDATION_ERROR", "--type must be one of ml, ioa, sensor-visibility, certificate")
    if type == "certificate" and limit > 100:
        raise CliError("VALIDATION_ERROR", "--limit must be an integer from 1 to 100 for certificate exclusions")


def _list(ctx: Invocation) -> CommandOutput:
    query, entity = TYPES[ctx.text("type") or ""]
    fields = {
        "ioa": ("id", "name", "pattern_id"),
        "certificate": ("id", "name", "status"),
    }.get(ctx.text("type") or "", ("id", "value", "applied_globally"))
    return list_records(ctx, query, entity, fields)


def _show(ctx: Invocation) -> CommandOutput:
    return show_record(ctx, TYPES[ctx.text("type") or ""][1])


COMMAND_SPECS = (
    CommandSpec(
        name="exclusion list",
        help="\n".join(
            [
                "falcon-axi exclusion list --type ml|ioa|sensor-visibility|certificate"
                " [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--type       required exclusion inventory",
                "--filter     raw FQL; applied_globally and created_on work for all four types",
                "             ml/sensor-visibility: value; ioa: pattern_id; certificate: name, modified_on",
                "             value/name use : for exact matches and :* for substring globs",
                "             unsupported fields may return zero matches without an error",
                "--limit      rows in this call (default 20, ceiling 500; certificate ceiling 100)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Read-only. Requires IOA Exclusions:read, Sensor Visibility Exclusions:read, or",
                "Machine Learning Exclusions:read for ml and certificate.",
                "Examples:",
                "  falcon-axi exclusion list --type ml",
                "  falcon-axi exclusion list --type ioa --filter \"pattern_id:'569'\"",
            ]
        ),
        summary="  exclusion list            list ML, IOA, sensor-visibility, or certificate exclusions",
        handler=_list,
        operations=tuple(op for pair in TYPES.values() for op in pair),
        flags=("type", "filter", "limit", "cursor"),
        value_flags=("type", "filter", "limit", "cursor"),
        limit_ceiling=(500, "exclusion query"),
    ),
    CommandSpec(
        name="exclusion show",
        help="\n".join(
            [
                "falcon-axi exclusion show <id> --type ml|ioa|sensor-visibility|certificate",
                "",
                "--type       required; use the same type as the list that returned the id",
                "Reads the full exclusion record with the same read scope as exclusion list.",
                "Examples:",
                "  falcon-axi exclusion show synthetic-exclusion-01 --type ml",
                "  falcon-axi exclusion show synthetic-exclusion-02 --type certificate",
            ]
        ),
        summary="  exclusion show <id>       the full exclusion record for a required --type",
        handler=_show,
        operations=tuple(pair[1] for pair in TYPES.values()),
        flags=("type",),
        value_flags=("type",),
        positional=("exclusion identifier", "Run `falcon-axi exclusion list --type ml` to see exclusion identifiers"),
    ),
)
