"""Weekly sensor billing and usage reports, without entity ids or pagination."""

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput
from falcon_axi.recon import read, records
from falcon_axi.render import raw


def list_usage(ctx: Invocation) -> CommandOutput:
    filter = ctx.text("filter")
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    rows = records(read(ctx, "GetSensorUsageWeekly", {"filter": filter} if filter else {}))
    return CommandOutput(
        value={"count": len(rows), "usage": rows if rows else raw("0 weekly sensor usage reports")},
        help=(),
    )


COMMAND_SPECS = (
    CommandSpec(
        name="sensor-usage list",
        help="\n".join(
            [
                "falcon-axi sensor-usage list [--filter <FQL>]",
                "",
                "Read weekly sensor usage reports. Requires Sensor Usage:read.",
                "--filter     raw FQL; supported fields include event_date and period",
                "Returns all weekly reports supplied by Falcon; no limit, cursor or entity detail endpoint.",
                "Reports retain all metric categories so numeric zero values remain visible.",
                "Examples:",
                "  falcon-axi sensor-usage list --filter \"period:'30'\"",
                "  falcon-axi sensor-usage list --filter \"event_date:'2026-10-11'\"",
            ]
        ),
        summary="  sensor-usage list         weekly sensor usage reports",
        handler=list_usage,
        operations=("GetSensorUsageWeekly",),
        flags=("filter",),
        value_flags=("filter",),
    ),
)
