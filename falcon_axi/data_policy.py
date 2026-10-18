"""Read-only Data Protection policies, distinct from endpoint policy families."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.data_protection import list_entities, show_entity
from falcon_axi.domain import CommandOutput


def _list(ctx: Invocation) -> CommandOutput:
    platform = ctx.text("platform")
    assert platform in ("win", "mac")
    return list_entities(ctx, "policies", platform)


def _show(ctx: Invocation) -> CommandOutput:
    return show_entity(ctx, "policy")


COMMAND_SPECS = (
    CommandSpec(
        name="data-policy list",
        summary="  data-policy list          list Data Protection policies",
        help="\n".join(
            [
                "falcon-axi data-policy list --platform win|mac [--filter <FQL>] [--sort <field.direction>]",
                "                            [--limit N] [--cursor <token>]",
                "",
                "--platform  required: win or mac; sent as the API's platform_name",
                "--filter    raw FQL; fields include name, is_enabled, precedence, created_at, modified_at",
                "--sort      name, precedence, created_at or modified_at with .asc or .desc",
                "--limit     rows in this call (default 20, ceiling 500)",
                "--cursor    opaque continuation token from a previous call; maximum offset 10000",
                "",
                "Examples:",
                '  falcon-axi data-policy list --platform win --filter "is_enabled:true"',
                "  falcon-axi data-policy list --platform mac --sort precedence.asc",
                "",
                "Read-only. Requires Data Protection:read (license-gated).",
            ]
        ),
        handler=_list,
        operations=("queries_policy_get_v2", "entities_policy_get_v2"),
        flags=("platform", "filter", "sort", "limit", "cursor"),
        value_flags=("platform", "filter", "sort", "limit", "cursor"),
        limit_ceiling=(500, "Data Protection query"),
    ),
    CommandSpec(
        name="data-policy show",
        summary="  data-policy show <id>     full Data Protection policy",
        help="\n".join(
            [
                "falcon-axi data-policy show <id>",
                "",
                "Shows the policy record, including policy_properties and classification references.",
                "The get endpoint needs only the id, without a platform selector.",
                "Example: falcon-axi data-policy show <id>",
                "Read-only. Requires Data Protection:read (license-gated).",
            ]
        ),
        handler=_show,
        operations=("entities_policy_get_v2",),
        positional=("policy identifier", "Run `falcon-axi data-policy list --platform win` to find identifiers"),
    ),
)
