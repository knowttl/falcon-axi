"""Read-only policy inventory and host membership over combined policy operations."""

import json
from collections.abc import Mapping
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, rate_limit_note, resources, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import RequestArgs

# Matches falcon-mcp modules/policies.py _OPERATIONS; CLI type names use hyphens.
POLICY_OPERATIONS: Mapping[str, tuple[OperationId, OperationId]] = {
    "prevention": ("queryCombinedPreventionPolicies", "queryCombinedPreventionPolicyMembers"),
    "sensor-update": ("queryCombinedSensorUpdatePoliciesV2", "queryCombinedSensorUpdatePolicyMembers"),
    "firewall": ("queryCombinedFirewallPolicies", "queryCombinedFirewallPolicyMembers"),
    "device-control": ("queryCombinedDeviceControlPolicies", "queryCombinedDeviceControlPolicyMembers"),
    "response": ("queryCombinedRTResponsePolicies", "queryCombinedRTResponsePolicyMembers"),
    "content-update": ("queryCombinedContentUpdatePolicies", "queryCombinedContentUpdatePolicyMembers"),
}
TYPE_CHOICES = "|".join(POLICY_OPERATIONS)
QUERY_CEILING = 5000


def validate_policy_type(value: str | None) -> str:
    if value not in POLICY_OPERATIONS:
        raise CliError(
            "VALIDATION_ERROR",
            "--type requires one of: " + ", ".join(POLICY_OPERATIONS),
            ["Run `falcon-axi policy list --type prevention` to list prevention policies"],
        )
    assert value is not None
    return value


def _list(ctx: Invocation) -> CommandOutput:
    policy_type = validate_policy_type(ctx.text("type"))
    members = ctx.spec.name == "policy members"
    policy_id = ctx.positionals[0] if members else None
    operation = POLICY_OPERATIONS[policy_type][1 if members else 0]
    filter = ctx.text("filter")
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        member_cid=ctx.session.member_cid,
        query=json.dumps([filter, policy_id], separators=(",", ":")),
    )
    cursor = ctx.text("cursor")
    offset = 0 if cursor is None else decode_offset(cursor, context, ctx.credential.client_secret)
    query: dict[str, str | int] = {"limit": ctx.limit, "offset": offset}
    if filter:
        query["filter"] = filter
    if policy_id is not None:
        query["id"] = policy_id
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(
            response,
            operation,
            "policy members" if members else "policies",
            filter_help=(
                f"{ctx.spec.name} --type {policy_type}",
                "hostname:'WIN-*'" if members else "enabled:true",
            ),
            not_found_command=f"policy list --type {policy_type}",
        )
    entries = resources(response)
    key = "members" if members else "policies"
    subject = f"{policy_type} policy members" if members else f"{policy_type} policies"
    help = (
        "Run `falcon-axi host show <device_id>` for a member's host details"
        if members
        else f"Run `falcon-axi policy members <id> --type {policy_type}` for assigned hosts"
    )
    if not entries:
        return CommandOutput(
            value={key: raw(f"no more {subject}" if offset else f"0 {subject} matching this query")},
            help=() if offset else (help,),
        )
    fields = ("device_id", "hostname", "platform_name", "status") if members else ("id", "name", "platform_name", "enabled")
    rows = [{field: entry.get(field, "unknown") for field in fields} for entry in entries if isinstance(entry, Mapping)]
    count = total(response)
    position = offset + len(entries)
    more = len(entries) >= ctx.limit if count is None else position < count
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    hints = [help]
    if more:
        continuation = encode_cursor(position, context, ctx.credential.client_secret)
        value["continuation_cursor"] = continuation
        hints.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
    value[key] = rows
    note = rate_limit_note(ctx.session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(hints))


COMMAND_SPECS = tuple(
    CommandSpec(
        name=f"policy {verb}",
        help="\n".join(
            [
                f"falcon-axi policy {verb}{' <id>' if verb == 'members' else ''} --type <type> "
                "[--filter <FQL>] [--limit N] [--cursor <token>]",
                "",
                f"--type       required: {TYPE_CHOICES}",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "",
                "Reads policy inventory or assigned host details, without changing policies or precedence.",
                "Requires the selected policy type's read scope; run `falcon-axi scopes` for the matrix.",
                "Device-control inventory uses the combined v1 schema, without v2 settings.",
                "Examples:",
                '  falcon-axi policy list --type prevention --filter "enabled:true"',
                "  falcon-axi policy members <id> --type sensor-update",
            ]
        ),
        summary=(
            "  policy list               list policies of one required type"
            if verb == "list"
            else "  policy members <id>       list hosts assigned to a policy"
        ),
        handler=_list,
        operations=tuple(pair[index] for pair in POLICY_OPERATIONS.values()),
        flags=("type", "filter", "limit", "cursor"),
        value_flags=("type", "filter", "limit", "cursor"),
        limit_ceiling=(QUERY_CEILING, "combined policy query"),
        positional=("policy identifier", "Run `falcon-axi policy list --type prevention` to find policy ids")
        if verb == "members"
        else None,
    )
    for index, verb in enumerate(("list", "members"))
)
