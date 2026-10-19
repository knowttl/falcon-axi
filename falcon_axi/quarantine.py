"""Read quarantined file metadata without issuing quarantine actions."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.domain import CommandOutput
from falcon_axi.inventory import list_records, show_record


def _list(ctx: Invocation) -> CommandOutput:
    return list_records(ctx, "QueryQuarantineFiles", "GetQuarantineFiles", ("id", "hostname", "sha256", "state"))


def _show(ctx: Invocation) -> CommandOutput:
    return show_record(ctx, "GetQuarantineFiles")


COMMAND_SPECS = (
    CommandSpec(
        name="quarantine list",
        help="\n".join(
            [
                "falcon-axi quarantine list [--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                "--filter     raw FQL (hostname, sha256, state, paths.path, paths.state)",
                "--limit      rows in this call (default 20, ceiling 500)",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Reads file metadata only. Requires Quarantined Files:read.",
                "Examples:",
                "  falcon-axi quarantine list",
                "  falcon-axi quarantine list --filter \"hostname:'SYNTHETIC-*'\"",
            ]
        ),
        summary="  quarantine list           list quarantined file metadata",
        handler=_list,
        operations=("QueryQuarantineFiles", "GetQuarantineFiles"),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(500, "quarantine query"),
    ),
    CommandSpec(
        name="quarantine show",
        help="\n".join(
            [
                "falcon-axi quarantine show <id>",
                "",
                "Reads the full file metadata, including paths and associated alert/detection ids.",
                "Requires Quarantined Files:read. No release, delete, or other action is performed.",
                "Example: falcon-axi quarantine show synthetic-quarantine-01",
            ]
        ),
        summary="  quarantine show <id>      the full quarantined file record",
        handler=_show,
        operations=("GetQuarantineFiles",),
        positional=("quarantine identifier", "Run `falcon-axi quarantine list` to see quarantine identifiers"),
    ),
)
