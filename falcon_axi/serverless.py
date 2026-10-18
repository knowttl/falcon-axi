"""Read-only serverless vulnerabilities in their SARIF representation."""

from collections.abc import Mapping

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_offset, encode_cursor
from falcon_axi.domain import CommandOutput, body_of
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs


def _list(ctx: Invocation) -> CommandOutput:
    filter = ctx.text("filter")
    assert filter is not None
    operation = ctx.spec.operations[0]
    context = CursorContext(
        operation=operation,
        client_id=ctx.credential.client_id,
        origin=ctx.session.base_url,
        query=filter,
        sort="cve_id",
        member_cid=ctx.session.member_cid,
    )
    cursor = ctx.text("cursor")
    offset = decode_offset(cursor, context, ctx.credential.client_secret) if cursor else 0
    response = ctx.transport.request(
        operation,
        RequestArgs(
            base_url=ctx.session.base_url,
            token=ctx.session.token,
            allow_unknown_origin=ctx.session.allow_unknown_origin,
            query={"filter": filter, "limit": ctx.limit, "offset": offset, "sort": "cve_id"},
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, operation, "serverless vulnerabilities")
    body = body_of(response)
    # falcon-mcp reads body.runs; the generated API schema also permits a resources SARIF object.
    sarif = body.get("resources", body)
    runs = sarif.get("runs") if isinstance(sarif, Mapping) else None
    if not isinstance(runs, list) or any(not isinstance(run, Mapping) for run in runs):
        raise CliError("UPSTREAM_ERROR", "Falcon returned an invalid serverless SARIF document")
    if not runs:
        return CommandOutput(value={"runs": raw("0 serverless SARIF runs matching the supplied query")}, help=())
    # A SARIF run can aggregate many vulnerabilities. Neither its count nor its rule count
    # proves how many source records Falcon consumed; advance by the requested record budget.
    continuation = encode_cursor(offset + ctx.limit, context, ctx.credential.client_secret)
    return CommandOutput(
        value={
            "count": raw(f"{len(runs)} SARIF runs; vulnerability total unknown"),
            "runs": runs,
            "continuation_cursor": continuation,
        },
        help=(
            "SARIF runs are not vulnerability rows; the next page may be empty",
            f"Run `{ctx.suggestion} --cursor {continuation}` for the next page",
        ),
    )


COMMAND_SPECS = (
    CommandSpec(
        name="serverless list",
        summary="  serverless list           read serverless vulnerability SARIF",
        help="\n".join(
            [
                "falcon-axi serverless list --filter <FQL> [--limit N] [--cursor <token>]",
                "",
                "Reads serverless function vulnerabilities as SARIF runs in fixed cve_id order.",
                "--filter     required FQL; fields include cloud_provider, cve_id, runtime, severity",
                "--limit      source records per call (default 20, CLI cap 100)",
                "--cursor     opaque continuation token; keep the same filter and credential",
                "SARIF runs aggregate source records; run counts are not vulnerability totals.",
                "Every nonempty page offers continuation; the next page may be empty.",
                "Examples:",
                "  falcon-axi serverless list --filter \"cloud_provider:'aws'\"",
                "  falcon-axi serverless list --filter \"severity:'HIGH'\" --limit 100",
                "",
                "Read-only; requires Falcon Container Image:read and the corresponding license.",
            ]
        ),
        handler=_list,
        operations=("GetCombinedVulnerabilitiesSARIF",),
        flags=("filter", "limit", "cursor"),
        value_flags=("filter", "limit", "cursor"),
        limit_ceiling=(100, "falcon-axi serverless page"),
    ),
)
