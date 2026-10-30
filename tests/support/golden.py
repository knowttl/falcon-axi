"""Replays committed golden scenarios through the Python CLI.

docs/design/v1-python.md §5 owns scenario provenance, template reconstruction, and the parity contract.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from falcon_axi.cli import run
from falcon_axi.cursor import CursorContext, encode_cursor
from falcon_axi.response_diagnostics import record_response
from falcon_axi.transport.graphql import request_body
from falcon_axi.transport.operations import operation, path_arguments
from falcon_axi.transport.types import FalconResponse, RequestArgs
from tests.support.recorded import CREDENTIAL_ENV, NO_CREDENTIAL_ENV, Responder, as_response, fixture

GOLDEN = Path(__file__).resolve().parent.parent / "golden"


def scenarios() -> list[dict[str, Any]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((GOLDEN / "scenarios").glob("*.json"))]


def command_references() -> list[dict[str, Any]]:
    references = [json.loads(path.read_text(encoding="utf-8")) for path in (GOLDEN / "commands").glob("*.json")]
    return sorted(references, key=lambda entry: entry["order"])


def _scope_table(references: list[dict[str, Any]]) -> str:
    commands: dict[tuple[str, str], list[str]] = {}
    requirements: dict[tuple[str, str], set[str]] = {}
    for entry in references:
        for scope in entry["scopes"]:
            key = (scope["scope"], scope["access"])
            commands.setdefault(key, []).append(entry["name"])
            requirements.setdefault(key, set()).add(scope.get("required", "yes"))
    lines = [f"scopes[{len(commands)}]{{scope,access,commands,required}}:"]
    for (scope, access), names in commands.items():
        required = "selected --type" if requirements[(scope, access)] == {"selected --type"} else "yes"
        named = json.dumps(", ".join(names)) if len(names) > 1 else names[0]
        lines.append(f"  {json.dumps(scope)},{access},{named},{required}")
    return "\n".join(lines)


def expected_stdout(name: str) -> str:
    references = command_references()
    fragments = {
        "command_summaries": "\n".join(entry["summary"] for entry in references),
        "command_names": ", ".join(entry["name"] for entry in references),
        "scope_table": _scope_table(references),
        "description": (GOLDEN / "description.txt").read_text(encoding="utf-8").rstrip("\n"),
    }
    expected = (GOLDEN / f"{name}.txt").read_text(encoding="utf-8")
    for key, value in fragments.items():
        expected = expected.replace("{{" + key + "}}", value)
    return expected


def _generated(spec: Mapping[str, Any], args: RequestArgs) -> FalconResponse:
    if spec["kind"] == "host-ids":
        offset = int(args.query["offset"])
        end = min(spec["total"], offset + int(args.query["limit"]))
        return FalconResponse(
            status=200,
            headers={},
            body={
                "resources": [f"synthetic-device-{index}" for index in range(offset, end)],
                "meta": {"pagination": {"total": spec["total"]}},
            },
        )
    if spec["kind"] == "host-hydrate":
        return FalconResponse(
            status=200,
            headers={},
            body={
                "resources": [
                    {"device_id": id, "hostname": "synthetic-host", "platform_name": "Windows", "last_seen": "unknown"}
                    for id in reversed(args.body["ids"])
                ],
            },
        )
    if spec["kind"] == "ids":
        resources = [f"ldt:synthetic-agent-{index}:{index}" for index in range(spec["count"])]
        total = spec.get("total")
        meta = {} if total is None else {"meta": {"pagination": {"total": total}}}
        return FalconResponse(status=200, headers={}, body={**meta, "resources": resources})
    ids = list(args.body["composite_ids"])
    taken = ids if spec.get("take") is None else ids[: spec["take"]]
    ordered = list(reversed(taken)) if spec.get("reverse") else taken
    return FalconResponse(
        status=200,
        headers={},
        body={
            "resources": [
                {
                    "composite_id": id,
                    "severity_name": spec["severity_name"],
                    "tactic": spec["tactic"],
                    "device": {"hostname": spec["hostname"]},
                }
                for id in ordered
            ]
        },
    )


def _responder_for(entry: Mapping[str, Any]) -> Responder:
    answer = None
    if entry.get("fixture"):
        answer = fixture(entry["fixture"])
    elif entry.get("response"):
        answer = as_response(entry["response"])

    def responder(id: str, args: RequestArgs) -> FalconResponse | None:
        if id != entry["op"]:
            return None
        return _generated(entry["generate"], args) if entry.get("generate") else answer

    return responder


class _GoldenTransport:
    def __init__(self, responders: list[Responder], oauth: list[FalconResponse]) -> None:
        self.responders = responders
        self.oauth = oauth

    def request(self, id: str, args: RequestArgs) -> FalconResponse:
        descriptor = operation(id)
        path_arguments(descriptor, dict(args.path_params or {}))
        request_body(descriptor, args.document, args.variables, args.body, args.query)
        for responder in self.responders:
            answer = responder(id, args)
            if answer is not None:
                record_response(answer.status, answer.headers, answer.body)
                return answer
        raise AssertionError(f"no recorded response for {id}")

    def request_oauth_token(self, args: Any) -> FalconResponse:
        answer = self.oauth.pop(0) if len(self.oauth) > 1 else self.oauth[0]
        record_response(answer.status, answer.headers, answer.body)
        return answer


def replay(scenario: Mapping[str, Any]) -> tuple[str, int]:
    env = {**(NO_CREDENTIAL_ENV if scenario.get("env") == "none" else CREDENTIAL_ENV), **scenario.get("envExtra", {})}
    responders = [_responder_for(entry) for entry in scenario.get("responders", [])]
    oauth = (
        [fixture(entry["fixture"]) if entry.get("fixture") else as_response(entry["response"]) for entry in scenario["oauth"]]
        if scenario.get("oauth")
        else [fixture("oauth2/token-success.json")]
    )
    argv = list(scenario["argv"])
    if scenario.get("cursor"):
        context = CursorContext(
            operation="GetQueriesAlertsV2",
            client_id=CREDENTIAL_ENV["FALCON_CLIENT_ID"],
            origin="https://api.crowdstrike.com",
        )
        argv += ["--cursor", encode_cursor(scenario["cursor"]["position"], context, CREDENTIAL_ENV["FALCON_CLIENT_SECRET"])]
    # The home view prints argv[0]; both runners pin it so the golden text is portable.
    return run(argv, _GoldenTransport(responders, oauth), env, bin="falcon-axi")
