# falcon-axi

An agent-facing CLI for reading the CrowdStrike Falcon platform from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

Output is token-efficient TOON on stdout, errors are structured documents rather than prose, and every view
ends with the commands that are worth running next.

## Status: stage 1 of the v1 design

The package is real and installable, and it ships the first vertical slice of
[`docs/design/v1.md`](docs/design/v1.md) rather than the whole v1 surface.

What stage 1 ships:

- the package foundation: a Python package, the `falcon-axi` console script, and one offline
  `uv run scripts/verify.py` entry point;
- the sealed read-only transport and its closed operation registry, with evidence carried per
  operation and a single permitted network sink;
- credential resolution through the environment or a `0600` credentials file, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, and `auth status`;
- the detections slice: `falcon-axi`, `falcon-axi detection list`, and `falcon-axi detection show`.

What stage 1 does **not** ship yet, so no output advertises it:

- `host` and `vuln` commands, and every domain `docs/design/v1.md` §1.3 defers;
- `falcon-axi scopes` and `falcon-axi setup`, including the session hook and the generated skill;
- `--all`, `--max-rows`, and `--fields`; a single call takes `--limit` and `--cursor` only;
- profile configuration in `~/.config/falcon-axi/config.json`; `--profile` is refused by name rather
  than silently ignored.

`docs/design/v1.md` remains the authority for the full v1 surface, and its §17 open questions are
still open. Nothing here answers one of them.
[`docs/design/v1-python.md`](docs/design/v1-python.md) amends it for language, HTTP client, test
layout, and packaging: falcon-axi is pure Python on `crowdstrike-falconpy`, with no Node runtime and
no MCP process anywhere.

## Read-only

**falcon-axi v1 is read-only.**
It requires only CrowdStrike read permissions, and it implements no write, create, update, delete,
execute, containment, quarantine, release, response, or otherwise mutating operation.

This is an architectural invariant, not a default posture.
It is enforced at the transport layer through a closed registry of read operations rather than by
convention, and the excluded capability classes are named explicitly in the design.
See `docs/design/v1.md` §0, §1.5, §3, and §4.

If a task needs containment, a real-time-response session, a detection-status update, or any other
change to the tenant, falcon-axi is the wrong tool and will not be persuaded otherwise.

The registered operations require only `Alerts:read`, `Hosts:read`, and `Vulnerabilities:read`, and
the commands stage 1 ships need only `Alerts:read`.
Whether member-CID token minting additionally requires `Flight Control:read` remains an explicitly
unresolved question in `docs/design/v1.md` §17.7.
A falcon-axi release that asks for a write scope is wrong.

## Quick start for agents

falcon-axi is not on PyPI while the repository is private, so every install path names the Git
repository.
[uv](https://docs.astral.sh/uv/) provisions Python 3.11 or newer on demand, so no system Python is
required.

Run it with no install at all, which is the Python analog of `npx -y`:

```sh
uvx --from git+https://github.com/knowttl/falcon-axi@v0.2.0 falcon-axi auth status
uvx --from git+https://github.com/knowttl/falcon-axi@v0.2.0 falcon-axi detection list --severity high --since 24h
```

Or install the command once and call it directly:

```sh
# Linux, WSL, macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install git+https://github.com/knowttl/falcon-axi@v0.2.0
```

```powershell
# Windows
winget install --id astral-sh.uv
uv tool install git+https://github.com/knowttl/falcon-axi@v0.2.0
```

Pin the tag rather than the default branch; suggestions printed by the tool use the bare `falcon-axi`
name, so run the equivalent command through whichever invocation form is installed.

## Credentials

Provision a **read-only** API client in the Falcon console under Support and resources > API clients
and keys, granting `Alerts:read` and nothing more.
Supply it through one of the two accepted channels:

```sh
export FALCON_CLIENT_ID=...
export FALCON_CLIENT_SECRET=...
```

```sh
install -m 0600 /dev/null ~/.config/falcon-axi/credentials
printf 'FALCON_CLIENT_ID=%s\nFALCON_CLIENT_SECRET=%s\n' "$id" "$secret" > ~/.config/falcon-axi/credentials
```

**No secret is ever accepted as a command-line argument**, and a flag whose name looks like a secret
is rejected at registration rather than at runtime.
The environment wins over the file, and a half-configured environment fails with
`CREDENTIAL_INCOMPLETE` rather than silently falling through to the file and selecting the wrong
identity.
The credentials file must be a regular file owned by the caller with mode `0600`, or it is refused
unread.

| Variable | Meaning |
| --- | --- |
| `FALCON_CLIENT_ID` | API client id |
| `FALCON_CLIENT_SECRET` | API client secret |
| `FALCON_BASE_URL` | Falcon cloud base URL, instead of `--region` |
| `FALCON_MEMBER_CID` | Flight Control child tenant to read, instead of `--member-cid` |
| `FALCON_AXI_CREDENTIALS_FILE` | Credentials file path, default `~/.config/falcon-axi/credentials` |

## API client permissions

Create the client in the Falcon console under Support and resources > API clients and keys, and grant
only read scopes.

| Scope | Why |
| --- | --- |
| `Alerts:read` | **Required for stage 1.** Everything that ships today - the home view, `detection list`, `detection show`, and `auth status` - needs this and nothing else. |
| `Hosts:read` | **Optional, for later.** Registered in the transport for the `host` domain, which stage 1 does not ship. |
| `Vulnerabilities:read` | **Optional, for later.** Registered in the transport for the `vuln` domain, which stage 1 does not ship. |

So a tight detections-only client with `Alerts:read` is the right client to create now, and a broader
read client with all three is the right one only if you want it to keep working unchanged when those
domains ship.

**Never grant a write, response, containment, Real Time Response, or otherwise mutating scope.**
falcon-axi requests none of them, would refuse to use one, and a client provisioned with one is the
wrong client for this tool.

Whether minting a member-CID token additionally requires `Flight Control:read` is an open design
question (`docs/design/v1.md` §17.7), not a settled requirement.
If `--member-cid` fails with `TENANT_DENIED` on a client that reads its own tenant fine, that scope is
the first thing to check.

## Region and tenant

`--region` takes one of `us-1`, `us-2`, `eu-1`, `us-gov-1`, or a full base URL.
The default is `us-1`, and a credential that belongs to another cloud is re-targeted from the
`X-Cs-Region` response header rather than failing, which `auth status` reports.
An origin outside the trusted Falcon hosts is refused as `ORIGIN_NOT_ALLOWED` unless
`--allow-unknown-origin` is passed deliberately.

`--member-cid <cid>` reads one Flight Control child tenant for that invocation, and
`--no-member-cid` clears an inherited `FALCON_MEMBER_CID`.
The two cannot be combined.
A CID is treated as sensitive: it is masked in output and never echoed into a suggestion.

## Workflow

1. `falcon-axi auth status` - confirm a credential resolved, from which channel, into which region,
   and how much rate-limit headroom is left.
2. `falcon-axi` - the content-first home view: tenant line plus the five newest detections.
3. `falcon-axi detection list` - the working surface, with filters and pagination.
4. `falcon-axi detection show <id>` - one detection in full.

```
falcon-axi                                          what is firing right now
falcon-axi auth status                              whether a credential resolved, and where to
falcon-axi detection list                           the 20 newest detections
falcon-axi detection list --severity critical       one severity
falcon-axi detection list --status new --since 24h  one status, one window
falcon-axi detection list --filter "severity_name:'Critical'+status:'new'"
falcon-axi detection show "ldt:aid:1234"            one detection
falcon-axi detection show "ldt:aid:1234" --full     without truncating long fields
```

`--severity` takes `informational`, `low`, `medium`, `high`, or `critical`.
`--status` takes `new`, `in_progress`, `closed`, or `reopened`.
`--since` takes a relative window such as `30m`, `24h`, or `7d`.
`--filter` takes raw Alerts FQL, where `+` is AND, `,` is OR, and values are single-quoted; it
composes with the shorthand flags.

## Output and errors

Output is TOON on stdout.
A list view prints a definitive `count:` line, a compact four-field schema, and a `help[]` array of
the next commands, so an empty result is an answer rather than an ambiguous silence.

```
count: 2 of 384 total
continuation_cursor: eyJvcGVyYXRpb24iOiJHZXRRdWVyaWVzQWxlcnRzVjIi...
detections[2]{id,severity,tactic,hostname}:
  "ldt:synthetic-agent-01:1001",High,Defense Evasion,WIN-DC-01
  "ldt:synthetic-agent-02:1002",Critical,Execution,WIN-WS-42
help[2]: "Run `falcon-axi detection show <id>` for the full detection","Run `falcon-axi detection list --limit 2 --cursor ...` for the next page"
```

An error is the same kind of document, also on stdout, carrying a stable `code` and actionable
`help`:

```
error: the Falcon credential was refused
code: AUTH_FAILED
help[2]: "The API client has no scopes granted, or is disabled","Grant `Alerts:read` (read only) in the Falcon console under Support and resources > API clients and keys"
```

Exit codes distinguish the caller's mistake from the run's failure: `0` on success, `2` for usage
errors (`VALIDATION_ERROR`, `CREDENTIAL_INCOMPLETE`, `FQL_INVALID`), and `1` for every other
failure.
The stable codes are `VALIDATION_ERROR`, `CREDENTIAL_INCOMPLETE`, `FQL_INVALID`, `AUTH_REQUIRED`,
`AUTH_FAILED`, `SCOPE_DENIED`, `TENANT_DENIED`, `ORIGIN_NOT_ALLOWED`, `REGION_MISMATCH`, `NOT_FOUND`,
`PAGINATION_LIMIT`, `RATE_LIMITED`, `UPSTREAM_ERROR`, `UPSTREAM_UNAVAILABLE`, `NETWORK_UNREACHABLE`,
`TLS_UNTRUSTED`, `READ_ONLY_VIOLATION`, and `UNKNOWN`.
An unknown flag or unknown command fails loudly with the valid set rather than being ignored.

`access_token`, `client_id`, `client_secret`, `member_cid`, `token`, and `Authorization` are redacted
on stdout and stderr.

Help is hierarchical: `falcon-axi --help` lists the commands and global flags, and
`falcon-axi detection list --help` documents that command's flags, filterable fields, and examples.
Ask the command rather than guessing its flags.

## Pagination

One call reads one page.
`--limit N` sets the rows for this call, defaulting to 20 with a ceiling of 10000, and a truncated
result prints a `continuation_cursor` plus a ready-to-run next-page suggestion that replays the same
filters.
Pass it back with `--cursor <token>`.

The cursor is opaque and bound to the credential and the filter that produced it, so it cannot be
edited, reused across a different query, or shared between tenants.
`--all`, `--max-rows`, and `--fields` do not exist in stage 1: loop on `--cursor` when more than one
page is genuinely needed.
Reading past 10000 Alerts results fails with `PAGINATION_LIMIT` and asks for a narrower filter,
because the documented route past that boundary is not registered in v1.

## Verify

```sh
uv sync
uv run scripts/verify.py
```

`uv run scripts/verify.py` is the single local entry point and runs entirely offline: ruff,
`mypy --strict`, the architecture boundary check, and the offline test suite against wholly
synthetic fixtures.
A pytest fixture refuses any socket, so no test can reach the network, and no fixture contains a
captured Falcon response, credential, token, or tenant identifier.

The offline suite includes the cross-language parity gate in `tests/golden/`: for every one of the
52 recorded invocations, the Python implementation reproduces the document the TypeScript stage 1 it
replaced printed, byte for byte, with the same exit code.

Offline fixtures prove deterministic behavior, not upstream fidelity: they are authored from the
documented response schemas cited in `docs/design/v1.md` §18, so every error-translation pattern
stays provisional until a real response confirms it.
Live Falcon calls need read-scoped credentials, are run by hand, and stay outside the required
checks; the opt-in live smoke suite of §15 is not implemented yet.

This project has no GitHub Actions workflow by captain directive; validation is local, and adding a
workflow requires the captain to lift that directive.

## Agent skill

[`skills/falcon-axi/SKILL.md`](skills/falcon-axi/SKILL.md) is the agent skill for this CLI, in the
Agent Skills format.
Install it from the repository:

```sh
npx skills add knowttl/falcon-axi --skill falcon-axi -g
```

Drop `-g` for a project-scoped install; the repository is private, so the install needs GitHub access to
it.
`falcon-axi setup` does not exist in stage 1, so the CLI installs no skill, session hook, or plugin
itself.

## Relationship to falcon-mcp

[`CrowdStrike/falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp) is used as a behavioral,
domain, scope, FQL, credential, and test reference only.
It is not a fork base, not a dependency, and not part of falcon-axi at runtime: falcon-axi runs no
MCP process, imports no `falcon_mcp` or `mcp` module, and installs neither.
Its only runtime dependencies are `crowdstrike-falconpy` and `toon-format`.

## License

MIT. See [`LICENSE`](LICENSE).
