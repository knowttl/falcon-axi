"""Read collections with query-bound cursors and ordered, chunked hydration."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.cursor import CursorContext, decode_cursor, encode_cursor
from falcon_axi.domain import DEFAULT_LIMIT, CommandOutput, body_of, rate_limit_note, resources, text, total
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw, truncate
from falcon_axi.transport.operations import OperationId, operation
from falcon_axi.transport.types import FalconResponse, RequestArgs


@dataclass(frozen=True)
class Collection:
    noun: str
    key: str
    query: OperationId
    columns: tuple[str, ...]
    ceiling: int
    hydrate: OperationId | None = None
    model: Literal["offset", "token"] = "offset"
    chunk: int = 100

    def _request(
        self, ctx: Invocation, id: OperationId, query: Mapping[str, Any] | None = None, body: Any = None
    ) -> FalconResponse:
        response = ctx.transport.request(
            id,
            RequestArgs(
                base_url=ctx.session.base_url,
                token=ctx.session.token,
                allow_unknown_origin=ctx.session.allow_unknown_origin,
                query=query,
                body=body,
            ),
        )
        if response.status != 200:
            raise translate_falcon_error(response, id, self.key)
        return response

    def _details(self, ctx: Invocation, ids: list[str]) -> list[Mapping[str, Any]]:
        assert self.hydrate is not None
        by_id: dict[str, Mapping[str, Any]] = {}
        for start in range(0, len(ids), self.chunk):
            batch = ids[start : start + self.chunk]
            if operation(self.hydrate).method == "POST":
                response = self._request(ctx, self.hydrate, body={"ids": batch})
            else:
                response = self._request(ctx, self.hydrate, query={"ids": tuple(batch)})
            for record in resources(response):
                if isinstance(record, Mapping) and text(record.get("id")):
                    by_id[record["id"]] = record
        return [by_id[id] for id in ids if id in by_id]

    def list(self, ctx: Invocation) -> CommandOutput:
        context = CursorContext(
            operation=self.query,
            client_id=ctx.credential.client_id,
            origin=ctx.session.base_url,
            query=ctx.text("filter"),
            member_cid=ctx.session.member_cid,
            model=self.model,
        )
        cursor = ctx.text("cursor")
        position = decode_cursor(cursor, context, ctx.credential.client_secret) if cursor else None
        query: dict[str, Any] = {"limit": ctx.limit}
        if self.model == "offset":
            query["offset"] = position or 0
        elif position is not None:
            query["after"] = position
        if ctx.text("filter"):
            query["filter"] = ctx.text("filter")
        response = self._request(ctx, self.query, query=query)
        listed = resources(response)
        if not listed:
            return CommandOutput(
                {self.key: raw(f"0 {self.key} matching this query" if not cursor else f"no more {self.key}")}, ()
            )
        if self.hydrate:
            records = self._details(ctx, [id for id in listed if isinstance(id, str)])
        else:
            records = [record for record in listed if isinstance(record, Mapping)]
        rows = [{field: record.get(field, "unknown") for field in self.columns} for record in records]
        count = total(response)
        value: dict[str, Any] = {"count": raw(f"{len(rows)} of {count if count is not None else 'unknown'} total")}
        next_position: int | str | None = None
        if self.model == "offset":
            next_offset = int(position or 0) + len(listed)
            if (count is not None and next_offset < count) or (count is None and len(listed) >= ctx.limit):
                next_position = next_offset
        else:
            meta = body_of(response).get("meta", {})
            pagination = meta.get("pagination", {}) if isinstance(meta, Mapping) else {}
            if isinstance(pagination, Mapping):
                next_position = text(pagination.get("next")) or text(pagination.get("after"))
        help = []
        if self.hydrate and self.noun != "firewall group":
            help.append(f"Run `falcon-axi {self.noun} show <id>` for the full record")
        if next_position is not None:
            continuation = encode_cursor(next_position, context, ctx.credential.client_secret)
            value["continuation_cursor"] = continuation
            help.append(f"Run `{ctx.suggestion} --cursor {continuation}` for the next page")
        value[self.key] = rows
        note = rate_limit_note(ctx.session)
        if note:
            value["rate_limit"] = raw(note)
        return CommandOutput(value, tuple(help))

    def show(self, ctx: Invocation) -> CommandOutput:
        records = self._details(ctx, [ctx.positionals[0]])
        if not records:
            raise CliError("NOT_FOUND", "no record matched that identifier", [f"Run `falcon-axi {self.noun} list`"])
        truncated = False

        def detail(value: Any) -> Any:
            nonlocal truncated
            if isinstance(value, str) and not ctx.flags.get("full"):
                rendered = truncate(value)
                truncated |= rendered.truncated
                return rendered.text
            if isinstance(value, Mapping):
                return {key: detail(item) for key, item in value.items()}
            if isinstance(value, list):
                return [detail(item) for item in value]
            return value

        value = {self.noun.replace(" ", "_"): detail(records[0])}
        help = (f"Run `{ctx.suggestion} --full` for untruncated detail",) if truncated else ()
        return CommandOutput(value, help)

    def commands(self, *, show: bool = False) -> tuple[CommandSpec, ...]:
        scopes = ", ".join(operation(self.query).scopes)
        name = f"{self.noun} list"
        listed = CommandSpec(
            name=name,
            help="\n".join(
                (
                    f"falcon-axi {name} [--filter <FQL>] [--limit N] [--cursor <token>]",
                    "",
                    "--filter  raw FQL; + is AND, comma is OR, values are single-quoted",
                    f"--limit   rows in this call (default {DEFAULT_LIMIT}, ceiling {self.ceiling})",
                    "--cursor  opaque continuation token from the previous call",
                    f"Read-only. Requires {scopes}.",
                    "Examples:",
                    f"  falcon-axi {name}",
                    f"  falcon-axi {name} --limit 2",
                )
            ),
            summary=f"  {name:<26} read {self.key}",
            handler=self.list,
            operations=(self.query, self.hydrate) if self.hydrate else (self.query,),
            flags=("filter", "limit", "cursor"),
            value_flags=("filter", "limit", "cursor"),
            limit_ceiling=(self.ceiling, self.noun),
        )
        if not show:
            return (listed,)
        assert self.hydrate is not None
        shown = CommandSpec(
            name=f"{self.noun} show",
            help="\n".join(
                (
                    f"falcon-axi {self.noun} show <id> [--full]",
                    "",
                    "Use the opaque id from list output. Long text is truncated to 800 characters.",
                    "--full  return untruncated text",
                    f"Read-only. Requires {scopes}.",
                    f"Example: falcon-axi {self.noun} show <id> --full",
                )
            ),
            summary=f"  {self.noun + ' show <id>':<26} read one record",
            handler=self.show,
            operations=(self.hydrate,),
            flags=("full",),
            positional=("identifier", f"Run `falcon-axi {name}` to see current identifiers"),
        )
        return listed, shown
