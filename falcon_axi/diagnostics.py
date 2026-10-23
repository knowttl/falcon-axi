"""Local configuration views and authentication diagnostics."""

from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.credentials import config_path, load_profiles, write_log_path
from falcon_axi.domain import CommandOutput
from falcon_axi.render import mask_cid, raw


def tenant_line(active: Any) -> str:
    region = active.region or "an unlisted Falcon cloud"
    retarget = f" (re-targeted from {active.retargeted_from})" if active.retargeted_from else ""
    if active.member_cid:
        return f"{region}{retarget} member CID {mask_cid(active.member_cid)}"
    return f"{region}{retarget} (own CID unavailable)"


def _auth_status(ctx: Invocation) -> CommandOutput:
    limit = ctx.session.rate_limit.limit
    remaining = ctx.session.rate_limit.remaining
    value: dict[str, Any] = {"credential_resolved": True, "credential_channel": ctx.credential.channel}
    value["profile"] = ctx.credential.profile
    value["endpoint"] = ctx.session.base_url
    value["client_secret_source"] = ctx.credential.secret_source
    if ctx.credential.path:
        value["credential_path"] = ctx.credential.path
    value["tenant"] = raw(tenant_line(ctx.session))
    value["scopes"] = raw(
        "read scopes, plus NGSIEM:write for `search start`, `search stop`, and `identity activity`, "
        "Identity Protection GraphQL:write for the fixed Identity Protection query commands, "
        "and MalQuery:write for bounded exact/fuzzy searches (N4)"
    )
    if limit is not None and remaining is not None:
        value["rate_limit"] = raw(f"{remaining} of {limit} requests remaining")
    return CommandOutput(value, ("Run `falcon-axi detection list` to read detections with this credential",))


def _config_path(ctx: Invocation) -> CommandOutput:
    return CommandOutput({"config": config_path(ctx.env, ctx.text("config")), "write_log": write_log_path(ctx.env)}, ())


def _profile_list(ctx: Invocation) -> CommandOutput:
    document = load_profiles(ctx.env, ctx.text("config"))
    return CommandOutput({"profiles": list(document["profiles"]), "default_profile": document.get("defaultProfile")}, ())


COMMAND_SPECS = (
    CommandSpec(
        name="auth status",
        help="\n".join(
            [
                "falcon-axi auth status",
                "",
                "Reports whether a credential resolved, from which channel, and which region it resolved to.",
                "No credential value, bearer token, or tenant CID is ever printed.",
            ]
        ),
        summary="  auth status               whether a credential resolved, and where to",
        handler=_auth_status,
        operations=(),
        authentication="diagnostic",
    ),
    CommandSpec(
        name="profile list",
        help="falcon-axi profile list [--config <path>]\nLists profile names without resolving secrets.\n"
        "Example: falcon-axi profile list",
        summary="  profile list              configured profile names, without reading secrets",
        handler=_profile_list,
        operations=(),
        authentication="none",
    ),
    CommandSpec(
        name="config path",
        help="falcon-axi config path [--config <path>]\nReports config and write-journal paths.\n"
        "Example: falcon-axi config path",
        summary="  config path               config and write-journal paths",
        handler=_config_path,
        operations=(),
        authentication="none",
    ),
)
