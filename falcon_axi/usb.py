"""Fixed host USB activity search inside captain exception N1."""

import re

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput
from falcon_axi.search import DEFAULT_REPOSITORY, DEFAULT_SINCE, start_search


def usb_query(device_id: str) -> str:
    if re.fullmatch(r"[a-fA-F0-9]{32}", device_id) is None:
        raise CliError(
            "VALIDATION_ERROR",
            "host usb requires a 32-character hexadecimal device id (AID)",
            ["Run `falcon-axi host list` to see current device identifiers"],
        )
    return (
        "#event_simpleName=/^(DcUsbDeviceConnected|DcUsbDeviceDisconnected|DcUsbDevicePolicyViolation)$/ "
        f"aid={device_id.lower()} "
        "| table([@timestamp, ComputerName, DeviceManufacturer, DeviceProduct, DevicePropertyDeviceDescription, "
        "DeviceUsbClass, DcPolicyAction, event_platform], limit=200, sortby=@timestamp, order=desc)"
    )


def _host_usb(ctx: Invocation) -> CommandOutput:
    return start_search(
        ctx.transport,
        ctx.session,
        usb_query(ctx.positionals[0]),
        DEFAULT_REPOSITORY,
        ctx.text("since") or DEFAULT_SINCE,
    )


COMMAND_SPECS = (
    CommandSpec(
        name="host usb",
        help="\n".join(
            [
                "falcon-axi host usb <device id> [--since <window>]",
                "",
                "The device id is the 32-character hexadecimal AID printed by `falcon-axi host list`.",
                f"--since      relative window such as 24h or 7d (default {DEFAULT_SINCE})",
                "",
                "Starts a fixed NG-SIEM search in search-all for USB connections, disconnections, and policy",
                "violations on one host, newest first, bounded to 200 events. Poll with `search status`.",
                "An empty result can mean no USB events or no Device Control licence.",
                "Event and field names come from CrowdStrike's community-content dashboard; not live-verified.",
                "",
                "Examples:",
                "  falcon-axi host usb 00000000000000000000000000000001",
                "  falcon-axi host usb 00000000000000000000000000000001 --since 7d",
                "",
                "This command starts a job on the tenant and requires NGSIEM:write (captain exception N1).",
                "It changes no host, device, or policy. Polling requires NGSIEM:read.",
            ]
        ),
        summary="  host usb <device id>      start a search for one host's USB activity",
        handler=_host_usb,
        operations=("StartSearchV1",),
        flags=("since",),
        value_flags=("since",),
        positional=("device identifier", "Run `falcon-axi host list` to see current device identifiers"),
    ),
)
