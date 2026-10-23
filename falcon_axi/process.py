"""Process detail reads from the IOCs collection, without graph traversal."""

import re
from collections.abc import Mapping

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import redact, truncate
from falcon_axi.transport.types import RequestArgs

PROCESS_ID = re.compile(r"pid:[a-fA-F0-9]{32}:[0-9]+")
_FIELDS = (
    "command_line",
    "device_id",
    "file_name",
    "process_id",
    "process_id_local",
    "start_timestamp",
    "start_timestamp_raw",
    "stop_timestamp",
    "stop_timestamp_raw",
)
_FIND_PROCESSES = "Run `falcon-axi ioc processes <type:value> --host <device_id>` to find process identifiers"


def validate_process_id(value: str) -> None:
    if PROCESS_ID.fullmatch(value) is None:
        raise CliError("VALIDATION_ERROR", "process identifier must be pid:<32 hex device ID>:<decimal ID>", [_FIND_PROCESSES])


def _show(ctx: Invocation) -> CommandOutput:
    id = ctx.positionals[0]
    validate_process_id(id)
    response = ctx.transport.request(
        "entities_processes",
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"ids": (id,)},
        ),
    )
    if response.status == 404 or (response.status == 200 and response.body == []):
        raise CliError("NOT_FOUND", "no process matched that identifier", [_FIND_PROCESSES])
    if response.status != 200:
        raise translate_falcon_error(response, "entities_processes", "process details")
    if not isinstance(response.body, list) or any(not isinstance(entry, Mapping) for entry in response.body):
        raise CliError("UPSTREAM_ERROR", "Falcon returned malformed process details")
    record = next((entry for entry in response.body if entry.get("process_id") == id), None)
    if record is None:
        raise CliError("UPSTREAM_ERROR", "Falcon returned process details without the requested identifier")
    value = {field: record.get(field) if record.get(field) is not None else "unknown" for field in _FIELDS}
    value["command_line"] = redact(value["command_line"])
    shortened = False
    if not ctx.flags.get("full") and isinstance(value["command_line"], str):
        value["command_line"], shortened = truncate(value["command_line"])
    help = (f"Run `falcon-axi process show {id} --full` to see the complete command line",) if shortened else ()
    return CommandOutput({"process": value}, help)


COMMAND_SPECS = (
    CommandSpec(
        name="process show",
        handler=_show,
        operations=("entities_processes",),
        summary="  process show <pid-id>     read one observed process",
        positional=("process identifier", _FIND_PROCESSES),
        flags=("full",),
        help="\n".join(
            [
                "falcon-axi process show <pid-id> [--full]",
                "",
                "ID shape: pid:<32 hex device ID>:<decimal ID>; use ioc processes to find it.",
                "Returns command_line, device_id, file_name, process_id, process_id_local,",
                "start_timestamp, start_timestamp_raw, stop_timestamp, and stop_timestamp_raw.",
                "--full  expand the command line beyond its 800-character preview",
                "",
                "Examples:",
                "  falcon-axi process show pid:00000000000000000000000000000001:1234",
                "  falcon-axi process show pid:00000000000000000000000000000001:1234 --full",
                "",
                "Read-only; requires IOCs (Indicators of Compromise):read.",
                "Availability depends on the tenant's subscription and API client permissions.",
            ]
        ),
    ),
)
