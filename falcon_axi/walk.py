"""Bounded pagination shared by offset and token list commands (§7.2)."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from falcon_axi.core import CliError
from falcon_axi.cursor import Position

T = TypeVar("T")


def max_rows_of(flags: Mapping[str, str | bool]) -> int | None:
    if "max-rows" in flags and not flags.get("all"):
        raise CliError("VALIDATION_ERROR", "--max-rows requires --all")
    if not flags.get("all"):
        return None
    try:
        budget = int(str(flags.get("max-rows", "1000")), 10)
    except ValueError:
        budget = 0
    if budget < 1:
        raise CliError("VALIDATION_ERROR", "--max-rows must be a positive integer")
    return budget


@dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    total: int | None
    next_position: Position | None
    consumed: int


@dataclass(frozen=True)
class Walk(Generic[T]):
    items: list[T]
    total: int | None
    next_position: Position | None
    stop_reason: str | None
    more_remain: bool = False
    consumed: int = 0

    def partial(self, value: dict[str, Any], help: list[str], reachable: bool) -> None:
        if self.stop_reason is None:
            return
        value.update(partial=True, stop_reason=self.stop_reason)
        if self.stop_reason == "max_rows":
            if reachable:
                help.append("Raise --max-rows, or follow continuation_cursor to resume from this position")
            else:
                help.append("The row budget was spent at the pagination boundary, so raising --max-rows reaches no further")


def walk(
    fetch: Callable[[int, Position | None], Page[T]],
    position: Position | None,
    limit: int,
    ceiling: int,
    max_rows: int | None,
    wall: int | None = None,
    wall_help: tuple[str, ...] = (),
) -> Walk[T]:
    """Fetch whole pages, shrinking the last request to the budget and reachable headroom.

    Consumed query rows advance the budget even when hydration loses deleted records.
    An empty page always terminates, including when an upstream total is stale.
    """
    items: list[T] = []
    remaining = limit if max_rows is None else max_rows
    consumed = 0
    count = None
    while True:
        headroom = wall - position if wall is not None and isinstance(position, int) else remaining
        if headroom <= 0:
            if not items:
                raise CliError("PAGINATION_LIMIT", "this read reached the endpoint pagination boundary", wall_help)
            return Walk(items, count, None, "pagination_limit" if max_rows is not None else None, True)
        size = min(limit if max_rows is None else ceiling, remaining, headroom)
        page = fetch(size, position)
        items.extend(page.items)
        count = page.total
        remaining -= page.consumed
        consumed += page.consumed
        position = page.next_position
        if position is None or page.consumed == 0:
            return Walk(items, count, None, None, consumed=consumed)
        at_wall = wall is not None and isinstance(position, int) and position >= wall
        if at_wall and not items:
            raise CliError("PAGINATION_LIMIT", "this read reached the endpoint pagination boundary", wall_help)
        if max_rows is None:
            return Walk(items, count, None if at_wall else position, None, True, consumed)
        if remaining <= 0:
            return Walk(items, count, None if at_wall else position, "max_rows", True, consumed)
        if at_wall:
            return Walk(items, count, None, "pagination_limit", True, consumed)


def offset_page(items: list[T], count: int | None, offset: int, consumed: int, limit: int) -> Page[T]:
    next_position = offset + consumed
    more = consumed >= limit if count is None else next_position < count
    return Page(items, count, next_position if more and consumed else None, consumed)
