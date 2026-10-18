"""Falcon Recon exposed-data record reads."""

from collections.abc import Mapping
from typing import Any

from falcon_axi.recon import commands


def row(record: Mapping[str, Any]) -> dict[str, Any]:
    return {field: record.get(field) for field in ("id", "domain", "credential_status", "notification_id")}


COMMAND_SPECS = commands(
    "recon-record",
    "list Recon exposed-data records",
    ("QueryNotificationsExposedDataRecordsV1", "GetNotificationsExposedDataRecordsV1"),
    row,
    "domain:'example.com'",
)
