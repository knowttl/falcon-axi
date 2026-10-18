"""Falcon Recon monitoring rule reads."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.recon import commands


def row(record: Mapping[str, Any]) -> dict[str, Any]:
    return {field: record.get(field) for field in ("id", "name", "status", "priority")}


COMMAND_SPECS = commands(
    "recon-rule",
    "list Recon monitoring rules",
    ("QueryRulesV1", "GetRulesV1"),
    row,
    "status:'active'",
)
