# Agent integration

## Install session context

After the first stable npm publication, install the CLI with `npm install --global @knowttl/falcon-axi`, then opt in:

```sh
falcon-axi setup hooks
```

Before stable publication, follow the [artifact installation instructions](design/v1-typescript.md#installation-and-full-parity-candidate) before opting in.

This installs or repairs integrations for Claude Code, Codex, and OpenCode.
At session start, they provide local profile status, region, version, and a command hint without contacting Falcon.
Ordinary reads and `falcon-axi setup` do not install hooks.
Repeated installation with the same configuration is a no-op.
Setup preserves unrelated hooks and refuses malformed configuration or an unmanaged file at its plugin target.
All four managed configuration files must be valid UTF-8.
Invalid encoding returns `CONFIG_INVALID` before any configuration is written; repair the affected file and rerun setup.

Hook targets must resolve to a durable CLI installation.
Temporary installations and git worktrees are refused, including temporary executables created by one-shot runners.
See the [executable-path and repair contract](design/v1.md#122-session-hook-and-skill) for pinned paths and when to rerun setup.

| Agent | Managed configuration |
| --- | --- |
| Claude Code | `~/.claude/settings.json`, `SessionStart` hook |
| Codex | `~/.codex/hooks.json`, `SessionStart` hook; `[features].hooks = true` in `~/.codex/config.toml` |
| OpenCode | `~/.config/opencode/plugins/axi-falcon-axi.js` |

These are user-level paths under `HOME`, falling back to the OS home directory.
The installer does not use the host-specific skill-discovery directory overrides for its targets.
Hooks grant no API permissions; Falcon access still requires separately configured credentials and scopes.

## Install on-demand guidance

The [generated skill](../skills/falcon-axi/SKILL.md) and its per-command references load on demand:

```sh
npx skills add knowttl/falcon-axi --skill falcon-axi
```

Add `-g` for a user-wide skill.
Choose either integration or use both; hook setup does not install the skill.
The skill grants no permissions.
Follow its generated invocation examples to run without a global CLI install.

## Remove session integrations

Remove only hook entries whose command contains `falcon-axi-session` from `~/.claude/settings.json` and `~/.codex/hooks.json`.
Delete the managed `~/.config/opencode/plugins/axi-falcon-axi.js` file.
Setup also enables `[features].hooks` in `~/.codex/config.toml`; leave it enabled if other integrations use hooks.
Preserve unrelated settings and hooks.
Removing session integrations leaves any separately installed skill in place.
