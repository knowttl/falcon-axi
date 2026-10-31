"""Opt-in installed-artifact checks; see docs/catalog-verification.md for setup."""

import json
import os
import shlex
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
from toon_format import decode

from falcon_axi.commands import COMMAND_SPECS, SUBCOMMANDS
from falcon_axi.version import VERSION
from tests.support.recorded import fixture

REPO = Path(__file__).resolve().parents[2]
BASE = "https://api.crowdstrike.com"
TOKEN = "/oauth2/token"
QUERY = "/alerts/queries/alerts/v2"
ENTITIES = "/alerts/entities/alerts/v2"


@pytest.fixture
def binary():
    value = os.environ.get("CATALOG_TEST_BIN")
    assert value, "set CATALOG_TEST_BIN to the clean artifact installation's absolute executable path"
    path = Path(value)
    assert path.is_absolute() and path.is_file()
    assert not path.resolve().is_relative_to(REPO)
    return path


@pytest.fixture
def invoke(binary, tmp_path):
    env = {**os.environ, "FALCON_AXI_CONFIG": str(tmp_path / "absent.json")}
    env.update(FALCON_AXI_CLIENT_ID="synthetic-client", FALCON_AXI_CLIENT_SECRET="synthetic-secret", FALCON_AXI_REGION="us-1")

    def call(argv, routes=(), *, configured=True, executable=binary):
        history = tmp_path / "requests.json"
        selected = dict(env)
        if not configured:
            selected.pop("FALCON_AXI_CLIENT_ID")
            selected.pop("FALCON_AXI_CLIENT_SECRET")
        python = binary.parent / "python"
        result = subprocess.run(  # noqa: S603
            [str(python), "-I", str(REPO / "tests/support/package_worker.py"), str(executable)],
            input=json.dumps({"argv": argv, "routes": routes, "history": str(history)}),
            env=selected,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert not result.stderr, result.stderr
        assert "synthetic-secret" not in result.stdout
        assert "synthetic-client" not in result.stdout
        return result.returncode, result.stdout, json.loads(history.read_text())

    return call


def route(method, path, *, name=None, body=None, status=200):
    answer = fixture(name) if name else None
    return {
        "method": method,
        "url": BASE + path,
        "status_code": answer.status if answer else status,
        "json": answer.body if answer else body,
        "headers": {"Content-Type": "application/json"},
    }


def token():
    return route("POST", TOKEN, name="oauth2/token-success.json")


@pytest.mark.parametrize("flag", ["-v", "-V", "--version"])
def test_installed_version(binary, tmp_path, flag):
    result = subprocess.run([str(binary), flag], cwd=tmp_path, capture_output=True, text=True, timeout=30)  # noqa: S603
    assert (result.returncode, result.stdout, result.stderr) == (0, VERSION + "\n", "")


@pytest.mark.parametrize("name", COMMAND_SPECS)
def test_installed_subcommand_help(invoke, name):
    code, output, calls = invoke([*name.split(), "--help"])
    assert code == 0
    assert output == (
        "\n".join(spec.summary for spec in COMMAND_SPECS.values() if spec.name.startswith(name + " ")) + "\n"
        if name in SUBCOMMANDS
        else COMMAND_SPECS[name].help + "\n"
    )
    assert calls == []


@pytest.mark.parametrize("name", COMMAND_SPECS)
@pytest.mark.parametrize("invalid", ["--catalog-unknown", "unexpected-positional"])
def test_installed_input_rejected_before_authentication(invoke, name, invalid):
    spec = COMMAND_SPECS[name]
    argv = [*name.split()]
    if spec.positional:
        argv.append("synthetic-id")
    if name.startswith("exclusion "):
        argv.extend(["--type", "ml"])
    code, output, calls = invoke([*argv, invalid])
    document = decode(output)
    assert code == 2
    assert document["code"] == "VALIDATION_ERROR"
    assert document["error"] and document["help"]
    assert (
        "catalog-unknown" in document["error"]
        if invalid.startswith("--")
        else ("positional" in document["error"] or "exactly one" in document["error"])
    )
    assert calls == []


def test_configured_home_is_bounded_content_with_identity_and_next_steps(invoke, binary):
    resources = [{"composite_id": f"ldt:synthetic-agent:{index}", "severity_name": "High"} for index in range(5)]
    code, output, calls = invoke(
        [],
        [
            token(),
            route(
                "GET",
                QUERY,
                body={"resources": [row["composite_id"] for row in resources], "meta": {"pagination": {"total": 384}}},
            ),
            route("POST", ENTITIES, body={"resources": resources}),
        ],
    )
    document = decode(output)
    assert code == 0
    assert document["bin"] == str(binary).replace(str(Path.home()), "~", 1)
    assert "Read CrowdStrike Falcon" in document["description"]
    assert len(document["detections"]) == 5
    assert document["count"] == "5 of 384 total"
    assert any("detection show <id>" in hint for hint in document["help"])
    assert any("detection list" in hint for hint in document["help"])
    assert [(call["method"], call["path"]) for call in calls] == [("POST", TOKEN), ("GET", QUERY), ("POST", ENTITIES)]
    assert calls[1]["query"]["limit"] == ["5"]


@pytest.mark.parametrize(
    "configured,routes,expected",
    [
        (False, [], "PROFILE_REQUIRED"),
        (
            True,
            [route("POST", TOKEN, status=401, body={"errors": [{"code": 401, "message": "invalid client"}]})],
            "AUTH_FAILED",
        ),
        (
            True,
            [
                token(),
                route(
                    "GET", QUERY, status=403, body={"errors": [{"code": 403, "message": "access denied, scope not permitted"}]}
                ),
            ],
            "SCOPE_DENIED",
        ),
    ],
)
def test_missing_credentials_auth_failure_and_denied_home_are_not_zero(invoke, configured, routes, expected):
    code, output, calls = invoke([], routes, configured=configured)
    document = decode(output)
    assert code == 1
    assert document["code"] == expected
    assert "count" not in document and "detections" not in document
    assert len(calls) == len(routes)


def test_installed_empty_list_is_successful_and_explicit(invoke):
    code, output, calls = invoke(["detection", "list"], [token(), route("GET", QUERY, name="alerts/query-empty.json")])
    assert code == 0
    assert decode(output)["detections"] == "0 detections in this tenant"
    assert len(calls) == 2


@pytest.mark.parametrize("retained", [0, 1])
def test_installed_partial_hydration_retains_total_and_cursor(invoke, retained):
    page = fixture("alerts/hydrate-page.json").body
    partial = {**page, "resources": page["resources"][:retained]}
    code, output, _ = invoke(
        ["detection", "list", "--limit", "2"],
        [token(), route("GET", QUERY, name="alerts/query-page.json"), route("POST", ENTITIES, body=partial)],
    )
    document = decode(output)
    assert code == 0
    assert len(document["detections"]) == retained
    assert "384 total" in document["count"]
    assert document["continuation_cursor"]
    code, output, calls = invoke(
        ["detection", "list", "--limit", "2", "--cursor", document["continuation_cursor"]],
        [token(), route("GET", QUERY, name="alerts/query-empty.json")],
    )
    assert code == 0
    assert calls[1]["query"]["offset"] == ["2"]


def test_installed_detail_truncation_can_be_recovered_with_full(invoke):
    detail = fixture("alerts/hydrate-detail.json").body
    routes = [token(), route("POST", ENTITIES, body=detail)]
    argv = ["detection", "show", detail["resources"][0]["composite_id"]]
    code, preview, _ = invoke(argv, routes)
    assert code == 0
    assert "truncated" in preview and "--full" in preview
    code, full, _ = invoke([*argv, "--full"], routes)
    assert code == 0
    assert decode(full)["detection"]["cmdline"] == detail["resources"][0]["cmdline"]
    assert "truncated" not in full


def test_installed_setup_is_opt_in_repeatable_and_repairs_relocation(invoke, binary, tmp_path):
    home = Path(os.environ["HOME"])
    code, output, calls = invoke(["setup"])
    assert code == 0 and calls == []
    assert "npx skills add knowttl/falcon-axi --skill falcon-axi" in output
    assert list(home.rglob("*")) == []
    code, output, calls = invoke(["setup", "hooks"])
    assert code == 0 and calls == []
    assert decode(output)["hooks"]["status"] == "installed"
    files = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in home.rglob("*") if path.is_file()}
    assert len(files) == 4
    assert tomllib.loads((home / ".codex/config.toml").read_text())["features"]["hooks"] is True
    for relative in (".claude/settings.json", ".codex/hooks.json"):
        entry = json.loads((home / relative).read_text())["hooks"]["SessionStart"][0]["hooks"][0]
        command = shlex.split(entry["command"], comments=True)
        result = subprocess.run(command, cwd=home, capture_output=True, text=True, timeout=10)  # noqa: S603
        assert result.returncode == 0 and not result.stderr
        assert len(result.stdout.splitlines()) == 1
        assert "profile unresolved" in result.stdout
    assert invoke(["setup", "hooks"])[0] == 0
    assert files == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in files}
    moved = tmp_path / "moved"
    moved.mkdir()
    for name in ("falcon-axi", "falcon-axi-hook"):
        shutil.copy2(binary.with_name(name), moved / name)
    code, output, calls = invoke(["setup", "hooks"], executable=moved / "falcon-axi")
    assert code == 0 and calls == []
    for relative in (".claude/settings.json", ".codex/hooks.json"):
        entry = json.loads((home / relative).read_text())["hooks"]["SessionStart"][0]["hooks"][0]
        assert shlex.split(entry["command"])[0] == str(moved / "falcon-axi-hook")
    assert str(moved / "falcon-axi-hook") in (home / ".config/opencode/plugins/axi-falcon-axi.js").read_text()


def test_installed_opencode_consumer_injects_hook_context_and_fails_open(invoke):
    node = shutil.which("node")
    assert node, "Node is required to verify the OpenCode plugin consumer"
    assert invoke(["setup", "hooks"])[0] == 0
    plugin = Path(os.environ["HOME"]) / ".config/opencode/plugins/axi-falcon-axi.js"
    program = """
import { readFileSync } from 'node:fs';
const source = readFileSync(process.argv[1], 'utf8');
const { FalconAxi } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const hooks = await FalconAxi({ directory: process.cwd() });
const output = { system: ['existing context'] };
await hooks['experimental.chat.system.transform']({}, output);
console.log(JSON.stringify(output));
"""
    command = [node, "--input-type=module", "-e", program, str(plugin)]
    result = subprocess.run(command, cwd=plugin.parent, capture_output=True, text=True, timeout=15)  # noqa: S603
    assert result.returncode == 0 and not result.stderr
    context = json.loads(result.stdout)["system"]
    assert context[0] == "existing context"
    assert "profile unresolved" in context[1]
    # A stale installed path is a local integration failure, never a session failure.
    plugin.write_text(plugin.read_text().replace("falcon-axi-hook", "absent-hook"))
    result = subprocess.run(command, cwd=plugin.parent, capture_output=True, text=True, timeout=15)  # noqa: S603
    assert result.returncode == 0 and not result.stderr
    assert json.loads(result.stdout)["system"] == [
        "existing context",
        "falcon-axi: local status unavailable; run falcon-axi setup",
    ]


@pytest.mark.parametrize(
    "extra,expected",
    [
        ([], None),
        (["--execute"], "VALIDATION_ERROR"),
        (["--execute", "--confirm", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ps"], "READ_ONLY_VIOLATION"),
    ],
)
def test_installed_rtr_preview_and_gates_never_authenticate(invoke, extra, expected):
    code, output, calls = invoke(["rtr", "run", "a" * 32, "--command", "ps", *extra])
    assert calls == []
    if expected:
        assert code != 0 and decode(output)["code"] == expected
    else:
        assert code == 0 and decode(output)["preview"]["session_deletion"] == "mandatory"


def test_installed_search_stop_reports_expired_repeat_without_recreating_job(invoke):
    path = "/humio/api/v1/repositories/search-all/queryjobs/synthetic-job"
    argv = ["search", "stop", "synthetic-job"]
    code, output, calls = invoke(argv, [token(), route("DELETE", path, body={})])
    assert code == 0 and decode(output)["stopped"] == "synthetic-job"
    assert [(call["method"], call["path"]) for call in calls] == [("POST", TOKEN), ("DELETE", path)]
    code, output, calls = invoke(argv, [token(), route("DELETE", path, status=404, body={})])
    assert code == 1 and decode(output)["code"] == "NOT_FOUND"
    assert [(call["method"], call["path"]) for call in calls] == [("POST", TOKEN), ("DELETE", path)]


def test_local_skill_install_route_preserves_generated_content(tmp_path):
    cli = os.environ.get("CATALOG_SKILLS_CLI")
    node = shutil.which("node")
    assert cli and node, "set CATALOG_SKILLS_CLI to a cached skills CLI; Node is required"
    guard = (
        "import net from 'node:net';"
        "net.Socket.prototype.connect = () => { throw Error('offline catalog test forbids sockets'); };"
        "globalThis.fetch = () => { throw Error('offline catalog test forbids fetch'); };"
    )
    result = subprocess.run(  # noqa: S603
        [
            node,
            "--import=data:text/javascript," + guard,
            cli,
            "add",
            str(REPO),
            "--skill",
            "falcon-axi",
            "--agent",
            "claude-code",
            "codex",
            "opencode",
            "--copy",
            "--global",
            "--yes",
            "--json",
        ],
        cwd=tmp_path,
        env={**os.environ, "DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    expected = REPO / "skills/falcon-axi"
    installed = Path(os.environ["HOME"]) / ".agents/skills/falcon-axi"
    assert {path.relative_to(installed): path.read_bytes() for path in installed.rglob("*.md")} == {
        path.relative_to(expected): path.read_bytes() for path in expected.rglob("*.md")
    }


@pytest.mark.parametrize(
    "relative,content",
    [
        (".claude/settings.json", "{broken"),
        (".codex/config.toml", "[broken"),
        (".config/opencode/plugins/axi-falcon-axi.js", "// unmanaged"),
    ],
)
def test_installed_setup_refuses_invalid_configuration_without_writes(invoke, relative, content):
    home = Path(os.environ["HOME"])
    path = home / relative
    path.parent.mkdir(parents=True)
    path.write_text(content)
    code, output, calls = invoke(["setup", "hooks"])
    assert code == 2 and calls == []
    assert decode(output)["code"] == "CONFIG_INVALID"
    assert {p: p.read_text() for p in home.rglob("*") if p.is_file()} == {path: content}
