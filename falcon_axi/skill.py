"""Static skill guidance and best-effort, file-only installation discovery."""

from collections.abc import Mapping
from pathlib import Path

HOME_GUIDANCE = (
    "Run `falcon-axi detection list` to see more detections",
    "Run `falcon-axi detection list --product idp` for Identity Protection detections",
    "Run `falcon-axi host list --filter \"hostname:'WIN-*'\"` to search hosts",
    "Run `falcon-axi cve show <CVE-ID>` for Falcon Intelligence on one CVE",
    "Run `falcon-axi scopes` to see what this API client needs",
)
INSTALL_HINT = "Run `npx skills add knowttl/falcon-axi --skill falcon-axi` to install the falcon-axi skill"


def skill_markdown() -> str:
    """Render only durable CLI guidance, never credentials or tenant state."""
    return "\n".join(
        [
            "---",
            "name: falcon-axi",
            "description: >-",
            "  Inspect CrowdStrike Falcon detections, hosts, accounts, vulnerabilities, identity, and search results.",
            "  Read-only investigation; no containment, remediation, or tenant configuration changes.",
            "---",
            "",
            "# falcon-axi",
            "",
            "Read CrowdStrike Falcon from the shell.",
            "Run `uvx falcon-axi ...` without a global install.",
            "",
            "## Read-only boundary",
            "",
            "No command changes a host, detection, policy, or identity.",
            "Starting and stopping NG-SIEM search jobs are the only tenant-side effects.",
            "Identity GraphQL uses a write-labelled scope only for fixed read-only query documents.",
            "There is no arbitrary REST or GraphQL escape hatch.",
            "",
            "## Orientation",
            "",
            "Run `uvx falcon-axi` for recent detections, or invoke a known command directly.",
            "",
            *(f"- {line.replace('`falcon-axi', '`uvx falcon-axi')}" for line in HOME_GUIDANCE),
            "",
            "## Commands",
            "",
            "Run `uvx falcon-axi --help` for the complete command list.",
            "Read `references/<command>.md` for a command's reference, replacing spaces with hyphens.",
            "",
            "Run `uvx falcon-axi <command> --help` for accepted flags, defaults, arguments, and examples.",
            "",
            "## Credentials and output",
            "",
            "Use `uvx falcon-axi auth status` to diagnose credentials without printing their values.",
            "Secrets belong in environment variables or env/file SecretRefs in config.json, never command arguments.",
            "Use `--profile <name>` or `--config <path>` for configured credentials, and `--region` for the Falcon cloud.",
            "Use `--member-cid` to select a Flight Control child tenant and `--no-member-cid` to clear an inherited selection.",
            "Standalone tenant CIDs and credentials are redacted; composite detection ids remain intact.",
            "Quote detection ids and shell-sensitive filters.",
            "",
            "Output and errors are TOON on stdout; help entries carry actionable next steps.",
            "Exit codes are 0 for success, 1 for failures, and 2 for usage errors.",
            "A continuation_cursor is opaque and bound to its credential and query; follow the emitted next-page command.",
            "Search jobs have no pagination; bound results in CQL and check parsed_query for unexpected interpretation.",
            "Stop search jobs when no longer needed.",
            "",
        ]
    )


def skill_files() -> dict[str, str]:
    """Keep command references separate so additions do not rewrite shared guidance."""
    from falcon_axi.commands import COMMAND_SPECS

    return {
        "SKILL.md": skill_markdown(),
        **{
            f"references/{spec.name.replace(' ', '-')}.md": (
                f"# {spec.name}\n\n"
                f"{spec.summary.strip()}\n\n"
                "```text\n"
                f"{spec.help.replace('falcon-axi', 'uvx falcon-axi')}\n"
                "```\n"
            )
            for spec in COMMAND_SPECS.values()
        },
    }


def skill_hint(env: Mapping[str, str]) -> tuple[str, ...]:
    """Check only roots loaded by the detected host; a failed probe stays silent."""
    if env.get("CLAUDECODE"):
        host = "claude"
    elif env.get("CODEX_THREAD_ID") or env.get("CODEX_SESSION_ID"):
        host = "codex"
    elif env.get("PI_CODING_AGENT"):
        host = "pi"
    elif env.get("OPENCODE"):
        host = "opencode"
    else:
        return ()
    try:
        home = Path(env["HOME"]) if env.get("HOME") else Path.home()
        agents = Path(".agents/skills")
        claude = Path(".claude/skills")
        if host == "claude":
            users = [Path(env["CLAUDE_CONFIG_DIR"]) / "skills" if env.get("CLAUDE_CONFIG_DIR") else home / claude]
            projects = [claude]
        elif host == "codex":
            users, projects = [home / agents], [agents]
        elif host == "pi":
            own = Path(env["PI_CODING_AGENT_DIR"]) if env.get("PI_CODING_AGENT_DIR") else home / ".pi/agent"
            users, projects = [own / "skills", home / agents], [Path(".pi/skills"), agents]
        else:
            config = Path(env["XDG_CONFIG_HOME"]) if env.get("XDG_CONFIG_HOME") else home / ".config"
            users = [config / "opencode/skills", home / claude, home / agents]
            projects = [Path(".opencode/skills"), claude, agents]
        roots = list(users)
        cwd = Path.cwd()
        for directory in (cwd, *cwd.parents):
            roots.extend(directory / relative for relative in projects)
            dotgit = directory / ".git"
            if dotgit.exists():
                if host == "claude" and dotgit.is_file():
                    pointer = dotgit.read_text(encoding="utf-8").strip()
                    if pointer.startswith("gitdir:"):
                        gitdir = (directory / pointer.partition(":")[2].strip()).resolve()
                        if gitdir.parent.name == "worktrees":
                            roots.append(gitdir.parent.parent.parent / claude)
                break
        if any((root / "falcon-axi/SKILL.md").is_file() for root in roots):
            return ()
        return (INSTALL_HINT,)
    except (OSError, RuntimeError, ValueError):
        return ()
