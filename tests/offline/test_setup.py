"""Local integrations install under an isolated home and never contact Falcon."""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from falcon_axi.cli import run
from falcon_axi.hook import main
from falcon_axi.setup import MARKER


@pytest.fixture
def installation(tmp_path, monkeypatch):
    # The install must be durable; temporary HOME destinations are allowed.
    root = Path("/opt/falcon")
    # Reuse pytest's temporary files, presenting them as a durable install only for this fixture.
    binary = tmp_path / "bin/falcon-axi"
    binary.parent.mkdir()
    binary.touch()
    hook = binary.with_name("falcon-axi-hook")
    hook.write_text("#!/bin/sh\nprintf 'local hook context\\n'\n")
    hook.chmod(0o700)
    monkeypatch.setattr(sys, "argv", [str(binary)])
    from falcon_axi import setup

    original = setup._durable
    monkeypatch.setattr(setup, "_durable", lambda path: original(root / path.name))
    env = {"HOME": str(tmp_path / "home"), "PATH": str(binary.parent)}
    return env, binary


def test_guidance_is_offline_and_writes_nothing(tmp_path):
    before = set(tmp_path.rglob("*"))
    output, code = run(["setup"], env={"HOME": str(tmp_path)})
    assert code == 0
    assert "setup hooks" in output
    assert set(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("relative_path", [False, True])
def test_all_integrations_install_and_rerun_without_writes(installation, monkeypatch, relative_path):
    env, binary = installation
    if relative_path:
        monkeypatch.chdir(binary.parent.parent)
        env["PATH"] = "bin"
    hook_command = str(binary.with_name("falcon-axi-hook")) if relative_path else "falcon-axi-hook"
    output, code = run(["setup", "hooks"], env=env)
    assert code == 0
    assert "status: installed" in output
    home = Path(env["HOME"])
    files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in home.rglob("*") if p.is_file()}
    assert len(files) == 4
    for relative in (".claude/settings.json", ".codex/hooks.json"):
        entry = json.loads((home / relative).read_text())["hooks"]["SessionStart"][0]
        assert entry["matcher"] == ""
        assert entry["hooks"] == [{"type": "command", "command": f"{hook_command} # {MARKER}", "timeout": 10}]
        result = subprocess.run(  # noqa: S602 - exercise the emitted host shell command
            entry["hooks"][0]["command"], shell=True, cwd=home, env={**os.environ, **env}, capture_output=True
        )
        assert result.returncode == 0
        assert result.stdout == b"local hook context\n"
    assert tomllib.loads((home / ".codex/config.toml").read_text())["features"]["hooks"] is True
    output, code = run(["setup", "hooks"], env=env)
    assert code == 0
    assert "status: unchanged" in output
    assert files == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}


def test_repair_moved_binary_preserves_other_hooks_and_config(installation, monkeypatch):
    env, binary = installation
    home = Path(env["HOME"])
    claude = home / ".claude/settings.json"
    claude.parent.mkdir(parents=True)
    other = {"matcher": "startup", "hooks": [{"type": "command", "command": "another-tool", "timeout": 3}]}
    claude.write_text(json.dumps({"theme": "dark", "hooks": {"SessionStart": [other]}}))
    config = home / ".codex/config.toml"
    config.parent.mkdir()
    config.write_text('# keep this\nmodel = "example"\n[features]\nhooks = false\nother = true\n')
    assert run(["setup", "hooks"], env=env)[1] == 0
    moved = binary.parent / "moved/falcon-axi"
    moved.parent.mkdir()
    moved.touch()
    moved_hook = moved.with_name("falcon-axi-hook")
    moved_hook.write_bytes(binary.with_name("falcon-axi-hook").read_bytes())
    moved_hook.chmod(0o700)
    monkeypatch.setattr(sys, "argv", [str(moved)])
    assert run(["setup", "hooks"], env=env)[1] == 0
    document = json.loads(claude.read_text())
    assert document["theme"] == "dark"
    assert document["hooks"]["SessionStart"][0] == other
    hooks = document["hooks"]["SessionStart"][1]["hooks"]
    assert shlex.split(hooks[0]["command"])[0] == str(moved_hook)
    assert len(hooks) == 1
    settings = tomllib.loads(config.read_text())
    assert settings == {"model": "example", "features": {"hooks": True, "other": True}}
    assert "# keep this" in config.read_text()


@pytest.mark.parametrize("relative_path", [False, True])
def test_opencode_plugin_injects_local_context_and_fails_open(installation, monkeypatch, relative_path):
    env, binary = installation
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed only to exercise the OpenCode plugin consumer")
    if relative_path:
        monkeypatch.chdir(binary.parent.parent)
        env["PATH"] = "bin"
    assert run(["setup", "hooks"], env=env)[1] == 0
    plugin = Path(env["HOME"]) / ".config/opencode/plugins/axi-falcon-axi.js"
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
    result = subprocess.run(  # noqa: S603
        command, cwd=env["HOME"], env={**os.environ, **env}, capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == {"system": ["existing context", "local hook context"]}
    binary.with_name("falcon-axi-hook").unlink()
    result = subprocess.run(  # noqa: S603
        command, cwd=env["HOME"], env={**os.environ, **env}, capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == {
        "system": ["existing context", "falcon-axi: local status unavailable; run falcon-axi setup"]
    }


@pytest.mark.parametrize(
    "features",
    [
        '[features]\n"hooks" = false # hook setting\nother = true\n',
        "[features]\n'hooks' = false # hook setting\nother = true\n",
        '["features"]\nhooks = false # hook setting\nother = true\n',
        "['features']\nhooks = false # hook setting\nother = true\n",
        '[ "features" ]\nhooks = false # hook setting\nother = true\n',
        "features = { hooks = false, other = true } # hook setting\n",
        "features.hooks = false # hook setting\nfeatures.other = true\n",
        '"features"."hooks" = false # hook setting\nfeatures.other = true\n',
        "features = {} # hook setting\n",
        "features.other = true # hook setting\n",
        "[features]\nother = true # hook setting",
        '[features]\nnote = """\n[example]\n""" # hook setting\n[features.nested]\nother = true\n',
    ],
)
def test_codex_features_preserve_valid_toml_settings_and_comments(installation, features):
    env, _ = installation
    config = Path(env["HOME"]) / ".codex/config.toml"
    config.parent.mkdir(parents=True)
    previous = '# keep this\nmodel = "example"\n' + features
    config.write_text(previous)
    expected = tomllib.loads(previous)
    expected["features"]["hooks"] = True

    output, code = run(["setup", "hooks"], env=env)

    assert code == 0
    assert "claude: updated" in output
    assert "codex: updated" in output
    assert "opencode: updated" in output
    installed = config.read_text()
    assert tomllib.loads(installed) == expected
    assert "# keep this" in installed
    assert "# hook setting" in installed
    output, code = run(["setup", "hooks"], env=env)
    assert code == 0
    assert "status: unchanged" in output
    assert config.read_text() == installed


@pytest.mark.parametrize(
    "relative,content",
    [
        (".claude/settings.json", "{damaged"),
        (".codex/hooks.json", '{"hooks":{"SessionStart":{}}}'),
        (".codex/config.toml", "[broken"),
        (".codex/config.toml", "features = false\n"),
        (".codex/config.toml", "[[features]]\nhooks = false\n"),
        (".config/opencode/plugins/axi-falcon-axi.js", "// user plugin\n"),
        (".config/opencode/plugins/axi-falcon-axi.js", ""),
    ],
)
def test_invalid_configuration_is_refused_before_any_write(installation, relative, content):
    env, _ = installation
    home = Path(env["HOME"])
    path = home / relative
    path.parent.mkdir(parents=True)
    path.write_text(content)
    output, code = run(["setup", "hooks"], env=env)
    assert code == 2
    assert "CONFIG_INVALID" in output
    assert {p for p in home.rglob("*") if p.is_file()} == {path}
    assert path.read_text() == content


@pytest.mark.parametrize("kind", ["temporary", "worktree", "symlink", ".treehouse", "worktrees", ".no-mistakes"])
def test_non_durable_executable_is_refused(tmp_path, monkeypatch, kind):
    from falcon_axi.setup import _durable

    if kind == "temporary":
        target = tmp_path / "falcon-axi-hook"
    elif kind == "symlink":
        target = tmp_path / "linked"
        target.symlink_to(tmp_path / "target")
    elif kind == "worktree":
        (tmp_path / ".git").write_text("gitdir: synthetic\n")
        target = tmp_path / "bin/falcon-axi-hook"
    else:
        target = Path("/opt") / kind / "bin/falcon-axi-hook"
    with pytest.raises(Exception, match="durable installation"):
        _durable(target)


@pytest.mark.parametrize("temporary_name", ["falcon-axi", "falcon-axi-hook"])
def test_resolved_temporary_boundary_refuses_either_executable_before_writes(tmp_path, monkeypatch, temporary_name):
    from falcon_axi import setup

    temporary = tmp_path / "temporary"
    temporary.mkdir()
    alias = tmp_path / "tmp-alias"
    alias.symlink_to(temporary, target_is_directory=True)
    monkeypatch.setattr(setup, "TEMP_ROOT", alias)
    binary = tmp_path / "bin/falcon-axi"
    binary.parent.mkdir()
    binary.touch()
    hook = binary.with_name("falcon-axi-hook")
    hook.touch()
    hook.chmod(0o700)
    target = temporary / temporary_name
    target.touch()
    target.chmod(0o700)
    link = binary.parent / temporary_name
    link.unlink()
    link.symlink_to(target)
    monkeypatch.setattr(sys, "argv", [str(binary)])
    home = tmp_path / "destination"

    output, code = run(["setup", "hooks"], env={"HOME": str(home), "PATH": str(binary.parent)})

    assert code == 2
    assert "durable installation" in output
    assert not home.exists()


@pytest.mark.parametrize("configured", [False, True, "invalid"])
def test_hook_is_one_line_and_exits_zero_without_network(tmp_path, monkeypatch, capsys, configured):
    for name in list(os.environ):
        if name.startswith("FALCON_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("FALCON_AXI_CONFIG", str(tmp_path / "config.json"))
    if configured is True:
        monkeypatch.setenv("FALCON_AXI_CLIENT_ID", "synthetic-client")
        monkeypatch.setenv("FALCON_AXI_CLIENT_SECRET", "synthetic-secret")
        monkeypatch.setenv("FALCON_AXI_REGION", "us-2")
    elif configured == "invalid":
        (tmp_path / "config.json").write_text("invalid")
        (tmp_path / "config.json").chmod(0o600)
    assert main() == 0
    output = capsys.readouterr()
    assert len(output.out.splitlines()) == 1
    assert not output.err
    assert "synthetic-client" not in output.out
    assert "synthetic-secret" not in output.out
    assert ("profile resolved" if configured is True else "profile unresolved") in output.out
    if configured is True:
        assert "https://api.us-2.crowdstrike.com" in output.out
