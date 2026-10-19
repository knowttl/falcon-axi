"""Read-only Data Protection classifications."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.data_protection import list_entities, show_entity
from falcon_axi.domain import CommandOutput


def _list(ctx: Invocation) -> CommandOutput:
    return list_entities(ctx, "classifications")


def _show(ctx: Invocation) -> CommandOutput:
    return show_entity(ctx, "classification")


COMMAND_SPECS = (
    CommandSpec(
        name="classification list",
        summary="  classification list       list Data Protection classifications",
        help="\n".join(
            [
                "falcon-axi classification list [--filter <FQL>] [--sort <field.direction>] [--limit N] [--cursor <token>]",
                "",
                "--filter  raw FQL; fields include name, created_at, modified_at, properties.protection_mode",
                "--sort    name, created_at or modified_at with .asc or .desc",
                "--limit   rows in this call (default 20, ceiling 500)",
                "--cursor  opaque continuation token from a previous call; maximum offset 10000",
                "",
                "Examples:",
                "  falcon-axi classification list --filter \"name:'Confidential*'\"",
                "  falcon-axi classification list --sort name.asc --limit 100",
                "",
                "Read-only. Requires Data Protection:read (license-gated).",
            ]
        ),
        handler=_list,
        operations=("queries_classification_get_v2", "entities_classification_get_v2"),
        flags=("filter", "sort", "limit", "cursor"),
        value_flags=("filter", "sort", "limit", "cursor"),
        limit_ceiling=(500, "Data Protection query"),
    ),
    CommandSpec(
        name="classification show",
        summary="  classification show <id>  full Data Protection classification",
        help="\n".join(
            [
                "falcon-axi classification show <id>",
                "",
                "Shows the classification record, including classification_properties and its rules.",
                "Example: falcon-axi classification show <id>",
                "Read-only. Requires Data Protection:read (license-gated).",
            ]
        ),
        handler=_show,
        operations=("entities_classification_get_v2",),
        positional=("classification identifier", "Run `falcon-axi classification list` to find identifiers"),
    ),
)
