from pathlib import Path

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.skill import INSTALL_HINT, skill_hint, skill_markdown
from scripts import skill
from tests.support.golden import replay, scenarios
from tests.support.recorded import NO_CREDENTIAL_ENV, RecordedTransport

REPO = Path(__file__).resolve().parents[2]


def test_committed_skill_matches_deterministic_generator(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = skill_markdown()
    monkeypatch.setenv("FALCON_AXI_PROFILE", "synthetic-profile")
    monkeypatch.setenv("CODEX_THREAD_ID", "synthetic-session")
    assert skill_markdown() == expected
    assert (REPO / "skills/falcon-axi/SKILL.md").read_text(encoding="utf-8") == expected


def test_check_refuses_drift_without_writing_and_generation_repairs_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "SKILL.md"
    monkeypatch.setattr(skill, "SKILL_FILE", target)
    assert skill.main(["--check"]) == 1
    assert not target.exists()
    target.write_text("stale", encoding="utf-8")
    assert skill.main(["--check"]) == 1
    assert target.read_text(encoding="utf-8") == "stale"
    assert skill.main([]) == 0
    assert skill.main(["--check"]) == 0


@pytest.mark.parametrize("marker", ["CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "OPENCODE", "PI_CODING_AGENT"])
def test_bare_home_suggests_install_inside_each_host(marker: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env = {**NO_CREDENTIAL_ENV, "HOME": str(tmp_path / "home"), marker: "1"}
    stdout, code = run([], RecordedTransport([]), env)
    assert code == 1
    assert INSTALL_HINT in decode(stdout)["help"]


@pytest.mark.parametrize("argv", [[], ["--help"], ["--region", "us-1"], ["scopes"], ["host", "list"]])
def test_hint_is_only_on_bare_home_inside_a_host(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env = {**NO_CREDENTIAL_ENV, "HOME": str(tmp_path)}
    assert INSTALL_HINT not in run(argv, RecordedTransport([]), env)[0]
    if argv:
        assert INSTALL_HINT not in run(argv, RecordedTransport([]), {**env, "CODEX_THREAD_ID": "1"})[0]


@pytest.mark.parametrize(
    ("marker", "root"),
    [
        ("CLAUDECODE", ".claude/skills"),
        ("CODEX_THREAD_ID", ".agents/skills"),
        ("PI_CODING_AGENT", ".pi/agent/skills"),
        ("PI_CODING_AGENT", ".agents/skills"),
        ("OPENCODE", ".config/opencode/skills"),
        ("OPENCODE", ".claude/skills"),
        ("OPENCODE", ".agents/skills"),
    ],
)
def test_user_skill_suppresses_hint(marker: str, root: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "home" / root / "falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    assert skill_hint({"HOME": str(tmp_path / "home"), marker: "1"}) == ()


@pytest.mark.parametrize(
    ("marker", "root"),
    [
        ("CLAUDECODE", ".claude/skills"),
        ("CODEX_SESSION_ID", ".agents/skills"),
        ("PI_CODING_AGENT", ".pi/skills"),
        ("OPENCODE", ".opencode/skills"),
    ],
)
def test_project_skill_found_from_subdirectory(marker: str, root: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".git").mkdir()
    child = tmp_path / "src"
    child.mkdir()
    target = tmp_path / root / "falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    monkeypatch.chdir(child)
    assert skill_hint({"HOME": str(tmp_path / "home"), marker: "1"}) == ()


@pytest.mark.parametrize(
    ("marker", "override"),
    [("CLAUDECODE", "CLAUDE_CONFIG_DIR"), ("PI_CODING_AGENT", "PI_CODING_AGENT_DIR"), ("OPENCODE", "XDG_CONFIG_HOME")],
)
def test_host_root_overrides(marker: str, override: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    base = tmp_path / "custom"
    target = base / ("opencode/skills" if marker == "OPENCODE" else "skills") / "falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    assert skill_hint({"HOME": str(tmp_path / "home"), marker: "1", override: str(base)}) == ()


def test_probe_failure_does_not_break_home(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> Path:
        raise OSError("directory unavailable")

    monkeypatch.setattr(Path, "cwd", unavailable)
    stdout, code = run([], RecordedTransport([]), {**NO_CREDENTIAL_ENV, "CODEX_SESSION_ID": "1"})
    assert code == 1
    assert decode(stdout)["code"] == "PROFILE_REQUIRED"
    assert INSTALL_HINT not in stdout


def test_another_hosts_skill_does_not_suppress_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "home/.claude/skills/falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    assert skill_hint({"HOME": str(tmp_path / "home"), "CODEX_THREAD_ID": "1"}) == (INSTALL_HINT,)


def test_project_probe_stops_at_repository_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / ".agents/skills/falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    monkeypatch.chdir(project)
    assert skill_hint({"HOME": str(tmp_path / "home"), "CODEX_SESSION_ID": "1"}) == (INSTALL_HINT,)


def test_claude_finds_main_checkout_skill_from_worktree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    main = tmp_path / "main"
    gitdir = main / ".git/worktrees/branch"
    gitdir.mkdir(parents=True)
    target = main / ".claude/skills/falcon-axi/SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("synthetic installed skill", encoding="utf-8")
    worktree = tmp_path / "branch"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
    monkeypatch.chdir(worktree)
    assert skill_hint({"HOME": str(tmp_path / "home"), "CLAUDECODE": "1"}) == ()


def test_authenticated_home_keeps_install_hint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    scenario = next(entry for entry in scenarios() if entry["name"] == "home-view")
    stdout, code = replay({**scenario, "envExtra": {"CODEX_THREAD_ID": "1", "HOME": str(tmp_path / "home")}})
    assert code == 0
    assert INSTALL_HINT in decode(stdout)["help"]
