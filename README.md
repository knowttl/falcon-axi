# falcon-axi

An agent-facing CLI for reading the CrowdStrike Falcon platform from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

Output is token-efficient TOON on stdout, errors are structured documents rather than prose, and every view
ends with the commands that are worth running next.

## Status: stage 2 of the v1 design

The package is real and installable, and it ships the three read domains of
[`docs/design/v1.md`](docs/design/v1.md) rather than the whole v1 surface.

What is shipped:

- the package foundation: a Python package, the `falcon-axi` console script, and one offline
  `uv run scripts/verify.py` entry point;
- the sealed read-only transport and its closed operation registry, with evidence carried per
  operation and a single permitted network sink;
- credential resolution through the environment or a `0600` credentials file, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, and `auth status`;
- the three read domains: `falcon-axi`, `detection list`, `detection show`, `host list`,
  `host show`, and `vuln list`;
- `falcon-axi scopes`, the command-to-scope matrix, printed from the same operation registry the
  transport enforces and without making a request.

What is **not** shipped yet, so no output advertises it:

- every domain `docs/design/v1.md` §1.3 defers, `intel` and NG-SIEM among them;
- `falcon-axi setup`, including the session hook and the generated skill;
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
the shipped commands need exactly that set and nothing else.
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

The pinned tag is the last release; `host list`, `host show`, `vuln list`, and `scopes` land in the
next one, so install from the default branch to use them before that tag exists.

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
and keys, granting `Alerts:read`, `Hosts:read`, and `Vulnerabilities:read` and nothing more.
Supply it through one of the two accepted channels:

```sh
export FALCON_CLIENT_ID=...
export FALCON_CLIENT_SECRET=...
```

```sh
mkdir -p ~/.config/falcon-axi
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
| `Alerts:read` | The home view, `detection list`, and `detection show`. |
| `Hosts:read` | `host list` and `host show`. |
| `Vulnerabilities:read` | `vuln list`. |

Run `falcon-axi scopes` for the same matrix from the tool itself; it is printed from the operation
registry the transport enforces, so it cannot drift from what falcon-axi actually calls, and it
needs no credential.
Grant only the scopes for the domains you intend to read: each is independent, and a command whose
scope is missing fails with `SCOPE_DENIED` naming exactly what to grant.

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
5. `falcon-axi host show <device_id>` - the host a detection fired on.
6. `falcon-axi vuln list --host <device_id>` - that host's exposure.

```
falcon-axi                                          what is firing right now
falcon-axi auth status                              whether a credential resolved, and where to
falcon-axi scopes                                   what to grant the API client
falcon-axi detection list                           the 20 newest detections
falcon-axi detection list --severity critical       one severity
falcon-axi detection list --status new --since 24h  one status, one window
falcon-axi detection list --filter "severity_name:'Critical'+status:'new'"
falcon-axi detection show "ldt:aid:1234"            one detection
falcon-axi detection show "ldt:aid:1234" --full     without truncating long fields
falcon-axi host list --platform windows             the Windows fleet
falcon-axi host list --hostname "WIN-*"             hostname search; Hosts filters take wildcards
falcon-axi host list --status contained             hosts Falcon has contained, as data
falcon-axi host show abc123                         one host
falcon-axi vuln list --severity critical --status open
falcon-axi vuln list --host abc123                  one host's vulnerabilities
```

`detection list` takes `--severity` (`informational`, `low`, `medium`, `high`, `critical`),
`--status` (`new`, `in_progress`, `closed`, `reopened`), and `--since`.
`host list` takes `--hostname`, `--platform` (`windows`, `mac`, `linux`), `--status` (`normal`,
`containment_pending`, `contained`, `lift_containment_pending`), and `--since` on `last_seen`.
`vuln list` takes `--host`, `--severity` (`low`, `medium`, `high`, `critical`), `--status` (`open`,
`closed`, `reopen`, `expired`), and `--since` on `created_timestamp`.
`--since` takes a relative window such as `30m`, `24h`, or `7d`.
`--filter` takes raw FQL for that collection, where `+` is AND, `,` is OR, and values are
single-quoted; it composes with the shorthand flags.

Two domain rules come from the API and are enforced before the request is made:
`vuln list` requires a filter, from a shorthand flag or `--filter`, and Spotlight filters reject a
`*` wildcard anywhere.
`host list` accepts wildcards, because the Hosts filter table documents `hostname` as supporting
them.

`host list` and `host show` report containment status as data.
falcon-axi cannot change it; there is no command that contains, lifts containment on, or otherwise
touches a host.

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

`host list` prints `hosts[N]{device_id,hostname,platform,last_seen}` and `vuln list` prints
`vulnerabilities[N]{id,cve,severity,hostname}`, in the same shape.

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
`falcon-axi host list --help` documents that command's flags, filterable fields, and examples.
Ask the command rather than guessing its flags.

## Pagination

One call reads one page.
`--limit N` sets the rows for this call, defaulting to 20, with a ceiling of 10000 on
`detection list` and 5000 on `host list` and `vuln list`, each the API's own documented maximum.
A truncated result prints a `continuation_cursor` plus a ready-to-run next-page suggestion that
replays the same filters.
Pass it back with `--cursor <token>`.

The cursor is opaque and bound to the credential and the filter that produced it, so it cannot be
edited, reused across a different query, or shared between tenants.
It hides the fact that Falcon paginates detections and hosts by offset and vulnerabilities by an
`after` token: the CLI vocabulary is `--cursor` in all three.
`--all`, `--max-rows`, and `--fields` do not exist yet: loop on `--cursor` when more than one
page is genuinely needed.
Reading past 10000 Alerts results fails with `PAGINATION_LIMIT` and asks for a narrower filter,
because the documented route past that boundary is not registered in v1.
`host list` stops at the documented Hosts `limit + offset` ceiling of 10000 the same way.

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

The offline suite includes the recorded-invocation gate in `tests/golden/`: every recorded
invocation reproduces its expected document byte for byte, with the same exit code.
The stage 1 scenarios there are the cross-language parity gate, whose expected documents were
generated by the TypeScript implementation this package replaced.

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
`falcon-axi setup` does not exist yet, so the CLI installs no skill, session hook, or plugin
itself.

## Relationship to falcon-mcp

[`CrowdStrike/falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp) is used as a behavioral,
domain, scope, FQL, credential, and test reference only.
It is not a fork base, not a dependency, and not part of falcon-axi at runtime: falcon-axi runs no
MCP process, imports no `falcon_mcp` or `mcp` module, and installs neither.
Its only runtime dependencies are `crowdstrike-falconpy` and `toon-format`.

## License

MIT. See [`LICENSE`](LICENSE).
