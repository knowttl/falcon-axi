"""CVE intelligence detail: one GetVulnerabilities read (docs/design/v1.md §2.1, §2.2)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from falcon_axi.auth import Session
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput, resources, text
from falcon_axi.falcon_error import translate_falcon_error
from falcon_axi.render import raw
from falcon_axi.transport.types import RequestArgs, Transport

#: MITRE's CVE id shape. Rejecting anything else also keeps the value out of a later FQL filter.
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate_cve_id(value: str) -> str:
    if CVE_ID.fullmatch(value):
        return value
    raise CliError(
        "VALIDATION_ERROR",
        "cve show requires a CVE identifier such as CVE-2021-44228",
        ["A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228"],
    )


def _count(value: Any) -> int:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return len(value)
    return 0


def _score(record: Mapping[str, Any]) -> int | float | str:
    base = record.get("cvss_v3_base")
    score: Any = base.get("score") if isinstance(base, Mapping) else base
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        score = base.get("base_score") if isinstance(base, Mapping) else None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return "unknown"
    return int(score) if float(score).is_integer() else float(score)


def _cve_of(record: Mapping[str, Any], requested: str) -> str:
    value = record.get("cve")
    if isinstance(value, str) and value:
        return value
    if isinstance(value, Mapping):
        for key in ("id", "cve_id", "cve"):
            found = text(value.get(key))
            if found:
                return found
    return requested


def _plain(value: Any) -> str:
    found = text(value)
    if found:
        return found
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "unknown"
    return str(value)


def _matching(response_resources: list[Any]) -> list[Mapping[str, Any]]:
    return [entry for entry in response_resources if isinstance(entry, Mapping)]


def _empty(cve_id: str) -> CommandOutput:
    return CommandOutput(
        value={"vulnerabilities": raw(f"0 vulnerabilities matching {cve_id}")},
        help=(
            "CrowdStrike Intelligence has no entry for that CVE, which is not the same as no host exposure",
            f"Run `falcon-axi vuln list --filter \"cve.id:'{cve_id}'\"` for tenant exposure",
        ),
    )


def show_cve(transport: Transport, session: Session, cve_id: str) -> CommandOutput:
    """`cve show <CVE-ID>`: one GetVulnerabilities read, shaped to the default fields."""
    requested = validate_cve_id(cve_id)
    response = transport.request(
        "GetVulnerabilities",
        RequestArgs(
            base_url=session.base_url,
            token=session.token,
            allow_unknown_origin=session.allow_unknown_origin,
            body={"ids": [requested]},
        ),
    )
    matched = _matching(resources(response))
    if response.status in (200, 404) and not matched:
        return _empty(requested)
    if response.status != 200:
        raise translate_falcon_error(response, "GetVulnerabilities", "CVE intelligence")
    record = matched[0]
    shown = _cve_of(record, requested)
    return CommandOutput(
        value={
            "cve": {
                "cve": shown,
                "severity": _plain(record.get("severity")),
                "cvss_v3_score": _score(record),
                "exploit_status": _plain(record.get("exploit_status")),
                "publish_date": _plain(record.get("publish_date")),
                "updated": _plain(record.get("updated_timestamp") or record.get("updated")),
                "description": _plain(record.get("description")),
                "affected_products": _count(record.get("affected_products")),
                "related_actors": _count(record.get("related_actors")),
                "related_reports": _count(record.get("related_reports")),
                "related_threats": _count(record.get("related_threats")),
            }
        },
        help=(
            "Related actor, report, threat, and affected-product lists are counts; this command does not expand them",
            f"Run `falcon-axi vuln list --filter \"cve.id:'{shown}'\"` for tenant exposure",
        ),
    )
