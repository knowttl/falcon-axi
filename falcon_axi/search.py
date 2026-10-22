"""The NG-SIEM search domain: the three lifecycle operations captain exception N1 admits.

NG-SIEM search is a job, not a query: `StartSearchV1` creates one, `GetSearchStatusV1` polls it and
carries the events once it is done, and `StopSearchV1` cancels it (docs/design/v1.md §4.3).
By default each command is one request; start and status can poll with a bounded `--wait` of 1-50 seconds.

The job has no `meta.pagination`, so there is no cursor and no `--limit`: the CQL query itself
bounds the result set, with `| head(N)` or an aggregate (§7.1).
"""

import time
from collections.abc import Mapping
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput, body_of, rate_limit_note, text
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.fql import since_seconds
from falcon_axi.render import raw
from falcon_axi.transport.budget import BudgetExpired, deadline_after, remaining_seconds, request_budget
from falcon_axi.transport.operations import OperationId
from falcon_axi.transport.types import FalconResponse, RequestArgs, Transport

#: The view that spans every repository, and the default falcon-mcp also uses.
DEFAULT_REPOSITORY = "search-all"
#: A search with no window would scan everything, so one is always sent.
DEFAULT_SINCE = "24h"


def _metadata(response: FalconResponse) -> Mapping[str, Any]:
    meta = body_of(response).get("metaData")
    return meta if isinstance(meta, Mapping) else {}


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _request(
    transport: Transport,
    session: Session,
    id: OperationId,
    subject: str,
    path_params: Mapping[str, str],
    body: Any = None,
    accepted: tuple[int, ...] = (200,),
    overrides: Mapping[int, CliError] | None = None,
    deadline: float | None = None,
) -> FalconResponse:
    with request_budget(deadline):
        remaining_seconds()
        response = transport.request(
            id,
            RequestArgs(
                base_url=session.base_url,
                token=session.token,
                allow_unknown_origin=session.allow_unknown_origin,
                path_params=path_params,
                body=body,
            ),
        )
    if response.status not in accepted:
        override = (overrides or {}).get(response.status)
        raise override if override is not None else translate_falcon_error(response, id, subject)
    return response


def _unknown_job() -> CliError:
    return CliError(
        "NOT_FOUND",
        "no NG-SIEM search job matched that identifier",
        [
            "A job id comes from `falcon-axi search start`, and a completed or cancelled job expires",
            "Pass the same `--repository` the job was started against",
        ],
    )


def _rejected_query() -> CliError:
    """NG-SIEM speaks CQL, not FQL, so a rejected search must not be given FQL advice (§9.4)."""
    return CliError(
        "VALIDATION_ERROR",
        "NG-SIEM rejected this search",
        [
            "CQL is pipe-based and is neither FQL nor SQL: `#event_simpleName=ProcessRollup2 | head(5)`",
            "Check the repository name and the query, then run `falcon-axi search start --help`",
        ],
    )


def _rate_limit(session: Session, value: dict[str, Any]) -> dict[str, Any]:
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return value


def _job_command(verb: str, id: str, repository: str) -> str:
    """A follow-up command replaying the repository, because a job id is only valid within one (§7.2)."""
    suffix = "" if repository == DEFAULT_REPOSITORY else f" --repository {repository}"
    return f"falcon-axi search {verb} {id}{suffix}"


def start_search(
    transport: Transport,
    session: Session,
    query: str,
    repository: str,
    since: str,
    wait: int = 0,
) -> CommandOutput:
    """`search start`: create one CQL search job and return its identifier (§4.3).

    This is one of the two operations captain exception N1 admits, and it requires `NGSIEM:write`.
    """
    deadline = deadline_after(wait)
    if not query.strip():
        raise CliError(
            "VALIDATION_ERROR",
            "search start requires a CQL query",
            [
                "CQL is pipe-based: a filter, then commands, for example `#event_simpleName=ProcessRollup2 | head(5)`",
                "Run `falcon-axi search start --help` for the query shape",
            ],
        )
    window_end = int(time.time() * 1000)
    response = _request(
        transport,
        session,
        "StartSearchV1",
        "NG-SIEM searches",
        {"repository": repository},
        body={"queryString": query, "start": window_end - since_seconds(since) * 1000, "end": window_end},
        overrides={400: _rejected_query(), 404: _rejected_query()},
        deadline=deadline,
    )
    id = text(body_of(response).get("id"))
    if not id:
        raise CliError(
            "UPSTREAM_ERROR",
            "the NG-SIEM search started but returned no job identifier",
            ["Retry shortly", "Run `falcon-axi auth status` to re-check the credential"],
        )
    if wait:
        return search_status(transport, session, id, repository, wait, deadline=deadline)
    value: dict[str, Any] = {"search_id": id, "repository": repository, "query": query, "window": f"the last {since}"}
    return CommandOutput(
        value=_rate_limit(session, value),
        help=(
            f"Run `{_job_command('status', id, repository)}` to poll this job and read its events",
            f"Run `{_job_command('stop', id, repository)}` to cancel it",
            "A job keeps running until it completes or is stopped, so stop one you no longer need",
        ),
    )


def search_status(
    transport: Transport,
    session: Session,
    id: str,
    repository: str,
    wait: int = 0,
    *,
    deadline: float | None = None,
) -> CommandOutput:
    """`search status <search id>`: poll one job and render its events once it is done (§10.2)."""
    deadline = deadline if deadline is not None else deadline_after(wait)
    response = FalconResponse(200, {}, {})
    with request_budget(deadline):
        while True:
            try:
                response = _request(
                    transport,
                    session,
                    "GetSearchStatusV1",
                    "NG-SIEM search status",
                    {"repository": repository, "id": id},
                    overrides={404: _unknown_job()},
                )
            except BudgetExpired:
                break
            except CliError as error:
                raise CliError(
                    error.code,
                    error.message,
                    (
                        *error.help,
                        f"Run `{_job_command('status', id, repository)}` to resume polling this job",
                        f"Run `{_job_command('stop', id, repository)}` to cancel it",
                    ),
                    {**error.details, "search_id": id, "repository": repository},
                ) from error
            body = body_of(response)
            remaining = deadline - time.monotonic() if deadline is not None else 0
            if body.get("done") or body.get("cancelled") or remaining <= 0:
                break
            time.sleep(min(1, remaining))
    body = body_of(response)
    if body.get("cancelled"):
        return CommandOutput(
            value=_rate_limit(session, {"state": "cancelled", "search_id": id}),
            help=("Run `falcon-axi search start --query '<cql>'` to run the search again",),
        )
    meta = _metadata(response)
    scanned = _count(meta.get("processedEvents"))
    if not body.get("done"):
        running: dict[str, Any] = {"state": "running", "search_id": id}
        if scanned is not None:
            running["events_scanned"] = scanned
        return CommandOutput(
            value=_rate_limit(session, running),
            help=(
                f"Run `{_job_command('status', id, repository)}{' --wait 30' if wait else ''}` "
                "again in a few seconds; the job is still running",
                f"Run `{_job_command('stop', id, repository)}` to cancel it",
            ),
        )

    events = [entry for entry in (body.get("events") or []) if isinstance(entry, Mapping)]
    matched = _count(meta.get("eventCount"))
    filter_query = meta.get("filterQuery")
    done: dict[str, Any] = {
        "state": "done",
        "count": raw(f"{len(events)} of {matched if matched is not None else 'unknown'} matching events"),
    }
    if scanned is not None:
        done["events_scanned"] = scanned
    parsed = text(filter_query.get("queryString")) if isinstance(filter_query, Mapping) else None
    if parsed:
        done["parsed_query"] = parsed
    done["events"] = events if events else raw("0 events matched this search")
    return CommandOutput(
        value=_rate_limit(session, done),
        help=(
            "Compare parsed_query with the query you sent: NG-SIEM turns an unrecognised word into a "
            "free-text stage rather than an error",
            "Bound a large result set in the query itself, with `| head(N)` or an aggregate such as "
            "`groupBy([...], function=count())`",
        ),
    )


def stop_search(
    transport: Transport,
    session: Session,
    id: str,
    repository: str,
) -> CommandOutput:
    """`search stop <search id>`: cancel one job (§4.3).

    The second operation captain exception N1 admits, and the reason a started job is never
    abandoned. It answers 200 with no body, so there is nothing to render but the confirmation.
    """
    _request(
        transport,
        session,
        "StopSearchV1",
        "NG-SIEM searches",
        {"repository": repository, "id": id},
        accepted=(200, 204),
        overrides={404: _unknown_job()},
    )
    return CommandOutput(
        value=_rate_limit(session, {"stopped": id, "repository": repository}),
        help=(
            f"Run `{_job_command('status', id, repository)}` to confirm the job reports cancelled",
            "Run `falcon-axi search start --query '<cql>'` to run a narrower search",
        ),
    )


def _search_start(ctx: Invocation) -> CommandOutput:
    return start_search(
        ctx.transport,
        ctx.session,
        query=ctx.text("query") or "",
        repository=ctx.text("repository") or DEFAULT_REPOSITORY,
        since=ctx.text("since") or DEFAULT_SINCE,
        wait=int(ctx.text("wait") or "0"),
    )


def _search_status(ctx: Invocation) -> CommandOutput:
    return search_status(
        ctx.transport,
        ctx.session,
        ctx.positionals[0],
        repository=ctx.text("repository") or DEFAULT_REPOSITORY,
        wait=int(ctx.text("wait") or "0"),
    )


def _search_stop(ctx: Invocation) -> CommandOutput:
    return stop_search(
        ctx.transport,
        ctx.session,
        ctx.positionals[0],
        repository=ctx.text("repository") or DEFAULT_REPOSITORY,
    )


COMMAND_SPECS = (
    CommandSpec(
        name="search start",
        help="\n".join(
            [
                "falcon-axi search start --query <CQL> [--repository <name>] [--since <window>] [--wait <seconds>]",
                "",
                "--query      the CQL search to run; required",
                f"--repository repository or view to search (default {DEFAULT_REPOSITORY})",
                f"--since      window to search, such as 24h or 7d (default {DEFAULT_SINCE})",
                "--wait       poll for completion for 1-50 seconds (default: return the job id immediately)",
                "",
                "CQL is pipe-based and is neither FQL nor SQL: a filter, then commands.",
                "Start from a tag or field filter and pipe into commands, and bound the result set in the",
                "query itself with `| head(N)` or an aggregate; there is no --limit and no --cursor.",
                "Examples:",
                "  falcon-axi search start --query '#event_simpleName=ProcessRollup2 | head(5)' --wait 30",
                "  falcon-axi search start --query '#event_simpleName=ProcessRollup2 "
                "| groupBy([ComputerName], function=count())' --since 7d",
                "",
                "This command starts a job on the tenant and requires NGSIEM:write.",
                "Using --wait also requires NGSIEM:read to poll status.",
                "Poll it with `falcon-axi search status <id> --wait 30`; a timeout leaves the job running.",
                "For readable epoch-millisecond @timestamp values, append this CQL stage:",
                '| formatTime("%Y-%m-%dT%H:%M:%SZ", field=@timestamp, as=time, timezone="UTC")',
            ]
        ),
        summary="  search start              start an NG-SIEM CQL search job",
        handler=_search_start,
        operations=("StartSearchV1", "GetSearchStatusV1"),
        flags=("query", "repository", "since", "wait"),
        value_flags=("query", "repository", "since", "wait"),
    ),
    CommandSpec(
        name="search status",
        help="\n".join(
            [
                "falcon-axi search status <search id> [--repository <name>] [--wait <seconds>]",
                "",
                f"--repository the repository the job was started against (default {DEFAULT_REPOSITORY})",
                "--wait       poll for completion for 1-50 seconds (default: one poll)",
                "",
                "Start a job with search start, then use status; --wait bounds polling without cancelling it.",
                "It reports running, cancelled, or done, and carries the events once",
                "the job is done. Compare parsed_query with the query you sent, because NG-SIEM turns an",
                "unrecognised word into a free-text stage rather than an error.",
                "",
                "Example: falcon-axi search status abc123 --wait 30",
                "Bound results with | head(N) in the original query; format epoch-millisecond @timestamp with:",
                '| formatTime("%Y-%m-%dT%H:%M:%SZ", field=@timestamp, as=time, timezone="UTC")',
                "",
                "This command is read-only and requires only NGSIEM:read.",
            ]
        ),
        summary="  search status <id>        poll one search job and read its events",
        handler=_search_status,
        operations=("GetSearchStatusV1",),
        flags=("repository", "wait"),
        value_flags=("repository", "wait"),
        positional=("search identifier", "A search identifier comes from `falcon-axi search start --query '<cql>'`"),
    ),
    CommandSpec(
        name="search stop",
        help="\n".join(
            [
                "falcon-axi search stop <search id> [--repository <name>]",
                "",
                f"--repository the repository the job was started against (default {DEFAULT_REPOSITORY})",
                "",
                "Cancels one search job falcon-axi started. It changes no tenant data, no host, and no",
                "detection: the only thing it stops is the job.",
                "",
                "Example: falcon-axi search stop abc123",
                "",
                "This command requires NGSIEM:write.",
            ]
        ),
        summary="  search stop <id>          cancel one search job",
        handler=_search_stop,
        operations=("StopSearchV1",),
        flags=("repository",),
        value_flags=("repository",),
        positional=("search identifier", "A search identifier comes from `falcon-axi search start --query '<cql>'`"),
    ),
)
