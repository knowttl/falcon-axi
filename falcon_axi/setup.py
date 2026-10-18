"""Explicit, offline installation of user-owned session integrations."""

import json
import os
import re
import shlex
import shutil
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from falcon_axi.command import CommandSpec, Invocation
from falcon_axi.core import CliError
from falcon_axi.domain import CommandOutput

MARKER = "falcon-axi-session"
PLUGIN_MARKER = f"// Managed by {MARKER}\n"
TEMP_ROOT = Path("/tmp")  # noqa: S108 - a refusal boundary, never a write target


def guidance(invocation: Invocation) -> CommandOutput:
    return CommandOutput(
        {"setup": "Install falcon-axi in a durable location before registering session integrations"},
        (
            "Run `falcon-axi setup hooks` to install or repair Claude Code, Codex, and OpenCode integrations",
            "Set FALCON_AXI_CLIENT_ID and FALCON_AXI_CLIENT_SECRET, or configure a profile with a SecretRef",
            "Run `npx skills add knowttl/falcon-axi --skill falcon-axi` to install the agent skill separately",
        ),
    )


def _invalid(message: str) -> CliError:
    return CliError("CONFIG_INVALID", message, ["Repair the local agent configuration, then run `falcon-axi setup hooks`"])


def _durable(path: Path) -> None:
    # Check both the installation path and its resolved target, including parent symlinks.
    for candidate in (path.absolute(), path.resolve()):
        if (
            candidate == TEMP_ROOT
            or TEMP_ROOT in candidate.parents
            or any(part in {".treehouse", "worktrees", ".no-mistakes"} for part in candidate.parts)
            or any((parent / ".git").is_file() for parent in candidate.parents)
        ):
            raise CliError(
                "CONFIG_INVALID",
                "session hooks require a durable installation outside temporary directories and git worktrees",
                ["Install with `uv tool install falcon-axi`, then run `falcon-axi setup hooks`"],
            )


def _hook_binary(env: Mapping[str, str]) -> str:
    executable = Path(sys.argv[0]).absolute()
    if not executable.is_file():
        found = shutil.which("falcon-axi", path=env.get("PATH", ""))
        if not found:
            raise _invalid("cannot locate the installed falcon-axi executable")
        executable = Path(found).absolute()
    hook = executable.with_name("falcon-axi-hook" + (".exe" if os.name == "nt" else ""))
    if not hook.is_file() or not os.access(hook, os.X_OK):
        raise _invalid("cannot locate falcon-axi-hook beside falcon-axi; reinstall falcon-axi")
    _durable(executable)
    _durable(hook)
    found = shutil.which(hook.name, path=env.get("PATH", ""))
    return hook.name if found and Path(found).resolve() == hook.resolve() else str(hook)


def _text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _json_hook(path: Path, command: str) -> str:
    previous = _text(path)
    document = json.loads(previous) if previous else {}
    if not isinstance(document, dict) or not isinstance(document.get("hooks", {}), dict):
        raise _invalid("agent hook configuration must contain a hooks object")
    hooks = document.setdefault("hooks", {})
    sessions = hooks.setdefault("SessionStart", [])
    if not isinstance(sessions, list):
        raise _invalid("SessionStart must be an array")
    wanted = {"type": "command", "command": command, "timeout": 10}
    managed = False
    result = []
    for entry in sessions:
        if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
            raise _invalid("SessionStart entries must contain a hooks array")
        remaining = []
        for hook in entry["hooks"]:
            if not isinstance(hook, dict):
                raise _invalid("session hooks must be objects")
            if MARKER in str(hook.get("command", "")):
                if not managed:
                    remaining.append(wanted)
                    managed = True
            else:
                remaining.append(hook)
        if remaining:
            result.append({**entry, "hooks": remaining})
    if not managed:
        result.append({"matcher": "", "hooks": [wanted]})
    hooks["SessionStart"] = result
    return previous if previous and json.loads(previous) == document else json.dumps(document, indent=2) + "\n"


def _codex_features(path: Path) -> str:
    previous = _text(path)
    document = tomllib.loads(previous)
    features = document.get("features", {})
    if not isinstance(features, dict):
        raise _invalid("Codex features must be a table")
    if features.get("hooks") is True:
        return previous
    # Preserve comments and unrelated TOML instead of rewriting the user's configuration.
    lines = previous.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if re.fullmatch(r"\s*\[features\]\s*(?:#.*)?\n?", line)), None)
    if start is None:
        if features:
            raise _invalid("use a [features] table in Codex config.toml before installing hooks")
        candidate = previous.rstrip() + "\n\n[features]\nhooks = true\n"
    else:
        end = next((i for i in range(start + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
        index = next((i for i in range(start + 1, end) if re.match(r"\s*hooks\s*=", lines[i])), None)
        if index is None:
            lines[start] = lines[start].rstrip("\r\n") + "\n"
            lines.insert(start + 1, "hooks = true\n")
        else:
            lines[index] = "hooks = true\n"
        candidate = "".join(lines)
    if tomllib.loads(candidate).get("features", {}).get("hooks") is not True:
        raise _invalid("could not enable Codex hooks while preserving config.toml")
    return candidate


def _plugin(binary: str) -> str:
    return (
        PLUGIN_MARKER
        + """import { execFile } from "node:child_process";
export const FalconAxi = async ({ directory }) => ({
  "experimental.chat.system.transform": async (_input, output) => {
    const text = await new Promise((resolve) => {
      execFile(BINARY, [], { cwd: directory, timeout: 10000 }, (error, stdout) => {
        resolve(error ? "falcon-axi: local status unavailable; run falcon-axi setup" : stdout.trim());
      });
    });
    if (text) output.system.push(text);
  },
});
""".replace("BINARY", json.dumps(binary))
    )


def install(invocation: Invocation) -> CommandOutput:
    try:
        binary = _hook_binary(invocation.env)
        command = f"{shlex.quote(binary)} # {MARKER}"
        home = Path(invocation.env.get("HOME") or Path.home())
        claude = home / ".claude/settings.json"
        codex = home / ".codex/hooks.json"
        config = home / ".codex/config.toml"
        plugin = home / ".config/opencode/plugins/axi-falcon-axi.js"
        existing = _text(plugin)
        if plugin.exists() and not existing.startswith(PLUGIN_MARKER):
            raise _invalid("refusing to overwrite an unmanaged OpenCode plugin")
        # Prepare every document before the first write, so malformed input changes nothing.
        updates = {
            claude: _json_hook(claude, command),
            codex: _json_hook(codex, command),
            config: _codex_features(config),
            plugin: _plugin(binary),
        }
        changed = {path for path, content in updates.items() if content != _text(path)}
        for path in changed:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(updates[path], encoding="utf-8")
        status: dict[str, Any] = {"status": "installed" if changed else "unchanged"}
        status.update(
            claude="updated" if claude in changed else "unchanged",
            codex="updated" if codex in changed or config in changed else "unchanged",
            opencode="updated" if plugin in changed else "unchanged",
        )
        return CommandOutput({"hooks": status}, ())
    except (OSError, ValueError, RuntimeError) as error:
        raise _invalid("cannot install hooks; check agent configuration syntax and file permissions") from error


COMMAND_SPECS = (
    CommandSpec(
        name="setup",
        summary="  setup                     offline installation and credential guidance",
        help="falcon-axi setup\n\nPrint offline guidance without writing files.\n\n"
        "Examples:\n  falcon-axi setup\n  falcon-axi setup hooks",
        handler=guidance,
        operations=(),
        authentication="none",
    ),
    CommandSpec(
        name="setup hooks",
        summary="  setup hooks               install or repair all three session integrations",
        help="falcon-axi setup hooks\n\nInstall or repair Claude Code, Codex, and OpenCode session integrations.\n"
        "Requires a durable installation. No network calls or skill installation.\n\n"
        "Examples:\n  falcon-axi setup hooks\n  falcon-axi setup hooks --help",
        handler=install,
        operations=(),
        authentication="none",
    ),
)
