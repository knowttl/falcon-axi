"""Falcon Recon notification reads."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.recon import commands


def row(record: Mapping[str, Any]) -> dict[str, Any]:
    notification = record.get("notification")
    fields = notification if isinstance(notification, Mapping) else {}
    return {"id": record.get("id"), **{field: fields.get(field) for field in ("status", "rule_name", "created_date")}}


COMMAND_SPECS = commands(
    "recon-notification",
    "list Recon notifications",
    ("QueryNotificationsV1", "GetNotificationsDetailedV1"),
    row,
    "status:'new'",
)
