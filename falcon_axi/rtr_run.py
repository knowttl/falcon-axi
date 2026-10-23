"""Local RTR preview and the single-invocation N3 execution surface."""

import os
import signal
from dataclasses import asdict
from types import FrameType

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.credentials import read_only, resolve_credential, write_log_path
from falcon_axi.domain import CommandOutput
from falcon_axi.origin import assert_trusted_origin, resolve_base_url
from falcon_axi.redaction import register_secret
from falcon_axi.rtr_execute import execute_run
from falcon_axi.rtr_policy import CLEANUP_SECONDS, EXECUTION_SECONDS, OUTPUT_BYTES, OUTPUT_CHUNKS, parse_command, validate_host


def preview(ctx: Invocation) -> CommandOutput:
    host = ctx.positionals[0]
    command = ctx.text("command")
    if command is None:
        raise CliError("VALIDATION_ERROR", "rtr run requires --command '<complete command>'")
    validate_host(host)
    executing = bool(ctx.flags.get("execute"))
    if executing and (read_only(ctx.env) or read_only(os.environ)):
        raise CliError("READ_ONLY_VIOLATION", "FALCON_AXI_READ_ONLY forbids RTR execution")
    if ctx.text("confirm") is not None and not executing:
        raise CliError("VALIDATION_ERROR", "--confirm requires --execute")
    if executing and ctx.text("confirm") != f"{host}:{command}":
        raise CliError("VALIDATION_ERROR", "--confirm must match '<device_id>:<complete command>' exactly")
    credential = resolve_credential(ctx.env, profile=ctx.text("profile"), config=ctx.text("config"))
    member = None if ctx.flags.get("no-member-cid") else ctx.text("member-cid") or credential.member_cid
    if member:
        register_secret(member)
    origin = assert_trusted_origin(resolve_base_url(region=ctx.text("region") or credential.region), False)
    parse_command(command, credential.rtr.commands)
    if executing and not credential.rtr.enabled:
        raise CliError("READ_ONLY_VIOLATION", "RTR execution requires explicit profile opt-in")
    return CommandOutput(
        value={
            "preview": {
                "host": host,
                "command": command,
                "profile": credential.profile,
                "origin": origin,
                "enabled": credential.rtr.enabled,
                "allowed_commands": sorted(credential.rtr.commands),
                "execution_seconds": EXECUTION_SECONDS,
                "cleanup_seconds": CLEANUP_SECONDS,
                "output_bytes": OUTPUT_BYTES,
                "output_chunks": OUTPUT_CHUNKS,
                "journal": write_log_path(ctx.env),
                "session_deletion": "mandatory",
            }
        },
        help=()
        if executing
        else (
            "Execution requires profile rtr.enabled=true and both --execute and "
            "--confirm '<device_id>:<complete command>'; FALCON_AXI_READ_ONLY always wins",
        ),
    )


def execute(ctx: Invocation) -> CommandOutput:
    def interrupted(signum: int, frame: FrameType | None) -> None:
        raise CliError("UPSTREAM_ERROR", "RTR execution interrupted")

    # Turn catchable terminal signals into core failures so its finally block owns deletion.
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, interrupted)
        result = execute_run(
            ctx.transport,
            ctx.env,
            ctx.positionals[0],
            ctx.text("command") or "",
            ctx.text("confirm") or "",
            profile=ctx.text("profile"),
            config=ctx.text("config"),
            region=ctx.text("region"),
            member_cid=ctx.text("member-cid"),
            no_member_cid=bool(ctx.flags.get("no-member-cid")),
        )
        return CommandOutput(value={"result": asdict(result)}, help=())
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


COMMAND_SPECS = (
    CommandSpec(
        name="rtr run",
        summary="  rtr run                   preview or execute one read-only RTR command on one host",
        help="\n".join(
            [
                "falcon-axi rtr run <device_id> --command '<complete command>' "
                "[--execute --confirm '<device_id>:<complete command>']",
                "",
                "Default: local preview, no network request. Requires one 32-hex device id.",
                "Execution requires profile rtr.enabled=true and exact host:command confirmation.",
                "FALCON_AXI_READ_ONLY always forbids execution; previews remain available.",
                "50-second execution budget; separate 10-second mandatory session deletion budget.",
                "Output caps: 64 KiB and 64 status requests; incomplete/truncated output is explicit.",
                "A durable private redacted journal is mandatory; no offline queue, pulse, or replay.",
                "Commands: cat, cd, clear, csrutil, env, eventlog view/list, filehash, getsid,",
                "history, ifconfig, ipconfig, ls, mount, netstat, ps, reg query, users.",
                "No shell syntax; eventlog backup/export, scripts, and file transfers are excluded.",
                "Examples:",
                "  falcon-axi rtr run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --command ps --profile triage",
                "  falcon-axi rtr run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --command ps --profile triage "
                "--execute --confirm 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ps'",
            ]
        ),
        handler=preview,
        operations=("RTR_InitSession", "RTR_ExecuteCommand", "RTR_CheckCommandStatus", "RTR_DeleteSession"),
        flags=("command", "execute", "confirm"),
        value_flags=("command", "confirm"),
        positional=("device id", "Use `falcon-axi rtr run <device_id> --command '<complete command>'"),
        authentication="none",
    ),
)
