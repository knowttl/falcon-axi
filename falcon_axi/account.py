"""The Discover accounts domain: the endpoint-observed account inventory (docs/design/v1.md §2.3, §10.2).

`account list` is the documented two-step read: `query_accounts` returns account ids by offset and
`get_accounts` hydrates them, with the query-step order reapplied afterwards. `account show` is the
hydrate step alone. Both need `Assets:read`, a license-gated scope (§5.7).
"""

from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.credentials import Credential
from falcon_axi.cursor import CursorContext, Position, decode_offset, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs, Transport
from falcon_axi.walk import Page, max_rows_of, offset_page, walk

#: Documented Discover limits: query "min: 1, max: 100", hydrate "max: 100" ids.
QUERY_CEILING = 100
HYDRATE_CHUNK = 100

Account = Mapping[str, Any]


def _scalar(value: Any) -> str:
    """Account fields are strings in the documented filter tables; a bool or number is rendered, never dropped."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return text(value) or "unknown"


def _id_of(account: Account) -> str:
    return text(account.get("id")) or ""


def _query_account_ids(
    transport: Transport, session: Session, filter: str | None, limit: int, offset: int
) -> tuple[list[str], int | None]:
    query: dict[str, str | int] = {"limit": limit, "offset": offset}
    if filter:
        query["filter"] = filter
    response = transport.request(
        "query_accounts",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            query=query,
        ),
    )
    if response.status != 200:
        raise translate_falcon_error(response, "query_accounts", "accounts")
    return [id for id in resources(response) if isinstance(id, str)], total(response)


def _hydrate_accounts(transport: Transport, session: Session, ids: Sequence[str]) -> list[Account]:
    by_id: dict[str, Account] = {}
    for index in range(0, len(ids), HYDRATE_CHUNK):
        response = transport.request(
            "get_accounts",
            RequestArgs(
                base_url=session.base_url,
                token=session.token,
                allow_unknown_origin=session.allow_unknown_origin,
                query={"ids": tuple(ids[index : index + HYDRATE_CHUNK])},
            ),
        )
        if response.status == 404:
            continue
        if response.status != 200:
            raise translate_falcon_error(response, "get_accounts", "accounts")
        for entry in resources(response):
            if isinstance(entry, Mapping) and _id_of(entry):
                by_id[_id_of(entry)] = entry
    return [by_id[id] for id in ids if id in by_id]


def list_accounts(
    transport: Transport,
    session: Session,
    filter: str | None,
    limit: int,
    credential: Credential,
    suggestion: str,
    cursor: str | None = None,
    max_rows: int | None = None,
) -> CommandOutput:
    """`account list`: query ids, hydrate them, and render the six-field schema (§10.2)."""
    if filter is not None and not filter.strip():
        raise CliError("VALIDATION_ERROR", "--filter requires a value")
    context = CursorContext(
        operation="query_accounts",
        client_id=credential.client_id,
        query=filter,
        origin=session.base_url,
        member_cid=session.member_cid,
        model="offset",
    )
    offset = 0 if cursor is None else decode_offset(cursor, context, credential.client_secret)

    def fetch(size: int, position: Position | None) -> Page[Account]:
        assert isinstance(position, int)
        ids, count = _query_account_ids(transport, session, filter, size, position)
        return offset_page(_hydrate_accounts(transport, session, ids), count, position, len(ids), size)

    result = walk(fetch, offset, limit, QUERY_CEILING, max_rows)
    accounts, count = result.items, result.total

    if not result.consumed:
        if offset > 0:
            return CommandOutput(value={"accounts": raw("no more accounts")}, help=())
        return CommandOutput(
            value={"accounts": raw("0 accounts matching the supplied filter" if filter else "0 accounts in this tenant")},
            help=("Run `falcon-axi account list` without a filter to see every observed account",),
        )

    rows = [
        {
            "id": _id_of(account),
            "username": _scalar(account.get("username")),
            "account_type": _scalar(account.get("account_type")),
            "login_domain": _scalar(account.get("login_domain")),
            "admin_privileges": _scalar(account.get("admin_privileges")),
            "last_login": _scalar(account.get("last_successful_login_timestamp")),
        }
        for account in accounts
    ]

    help = ["Run `falcon-axi account show <id>` for the full account record"]
    value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
    result.partial(value, help, result.next_position is not None)
    if result.next_position is not None:
        continuation = encode_cursor(result.next_position, context, credential.client_secret)
        value["continuation_cursor"] = continuation
        help.append(f"Run `{suggestion} --cursor {continuation}` for the next page")
    value["accounts"] = rows
    note = rate_limit_note(session)
    if note:
        value["rate_limit"] = raw(note)
    return CommandOutput(value=value, help=tuple(help))


def show_account(transport: Transport, session: Session, id: str) -> CommandOutput:
    """`account show <id>`: hydrate one account id into the detail view (§10.2)."""
    accounts = _hydrate_accounts(transport, session, [id])
    if not accounts:
        raise CliError(
            "NOT_FOUND",
            "no account matched that identifier",
            ["Run `falcon-axi account list` to see current account identifiers"],
        )
    account = accounts[0]
    detail: dict[str, Any] = {
        "id": _id_of(account),
        "username": _scalar(account.get("username")),
        "account_name": _scalar(account.get("account_name")),
        "account_type": _scalar(account.get("account_type")),
        "login_domain": _scalar(account.get("login_domain")),
        "user_sid": _scalar(account.get("user_sid")),
        "admin_privileges": _scalar(account.get("admin_privileges")),
        "local_admin_privileges": _scalar(account.get("local_admin_privileges")),
        "password_last_set": _scalar(account.get("password_last_set_timestamp")),
        "first_seen": _scalar(account.get("first_seen_timestamp")),
        "last_login": _scalar(account.get("last_successful_login_timestamp")),
        "last_login_hostname": _scalar(account.get("last_successful_login_hostname")),
        "last_login_type": _scalar(account.get("last_successful_login_type")),
        "last_failed_login": _scalar(account.get("last_failed_login_timestamp")),
        "last_failed_login_hostname": _scalar(account.get("last_failed_login_hostname")),
    }
    help = ["Run `falcon-axi account list` to see more accounts"]
    aid = text(account.get("last_successful_login_aid"))
    if aid:
        help.insert(0, f"Run `falcon-axi host logins {aid}` for recent interactive logins on its last login host")
    return CommandOutput(value={"account": detail}, help=tuple(help))


def _account_list(ctx: Invocation) -> CommandOutput:
    return list_accounts(
        ctx.transport,
        ctx.session,
        filter=ctx.text("filter"),
        limit=ctx.limit,
        cursor=ctx.text("cursor"),
        credential=ctx.credential,
        suggestion=ctx.suggestion,
        max_rows=max_rows_of(ctx.flags),
    )


def _account_show(ctx: Invocation) -> CommandOutput:
    return show_account(ctx.transport, ctx.session, ctx.positionals[0])


COMMAND_SPECS = (
    CommandSpec(
        name="account list",
        help="\n".join(
            [
                "falcon-axi account list [--filter <FQL>] [--limit N] [--cursor <token>] [--all] [--max-rows N]",
                "",
                "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted",
                f"--limit      rows in this call (default {DEFAULT_LIMIT}, ceiling {QUERY_CEILING})",
                "--cursor     opaque continuation token from a previous call",
                "--all        walk pages; page size is independent of --limit",
                "--max-rows   row budget (default 1000; requires --all)",
                "",
                "Lists the accounts Falcon Discover has observed logging in on endpoints, which is an",
                "endpoint-observed inventory and not an identity directory.",
                "Filterable fields include username, account_name, account_type, login_domain, user_sid,",
                "admin_privileges, local_admin_privileges, first_seen_timestamp, password_last_set_timestamp,",
                "last_successful_login_timestamp, and last_failed_login_timestamp.",
                "Examples:",
                "  falcon-axi account list --filter \"admin_privileges:'Yes'\"",
                "  falcon-axi account list --filter \"username:'svc-*'\"",
                "",
                "This command is read-only and requires only Assets:read, which is license-gated to Falcon",
                "Discover or Exposure Management.",
            ]
        ),
        summary="  account list              list Discover accounts observed on endpoints",
        handler=_account_list,
        operations=("query_accounts", "get_accounts"),
        flags=("filter", "limit", "cursor", "all", "max-rows"),
        value_flags=("filter", "limit", "cursor", "max-rows"),
        limit_ceiling=(QUERY_CEILING, "Discover accounts query"),
    ),
    CommandSpec(
        name="account show",
        help="\n".join(
            [
                "falcon-axi account show <account id>",
                "",
                "The account id is the identifier printed by `falcon-axi account list`.",
                "",
                "Example: falcon-axi account show abc123",
                "",
                "This command is read-only and requires only Assets:read, which is license-gated to Falcon",
                "Discover or Exposure Management.",
            ]
        ),
        summary="  account show <id>         the full detail for one account",
        handler=_account_show,
        operations=("get_accounts",),
        positional=("account identifier", "Run `falcon-axi account list` to see current account identifiers"),
    ),
)
