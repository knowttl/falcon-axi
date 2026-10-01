# falcon-axi

An agent-facing CLI for reading the CrowdStrike Falcon platform from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

Output is token-efficient TOON on stdout, errors are structured documents rather than prose, and every view
ends with the commands that are worth running next.

## Status: partial implementation of the v1 design

The package is real and installable, and it ships five read domains plus NG-SIEM search.
The shipped and deferred commands are listed below; [`docs/design/v1.md`](docs/design/v1.md) owns the full v1 design.

What is shipped:

- the package foundation: a Python package, the `falcon-axi` console script, and one offline
  `uv run scripts/verify.py` entry point;
- the sealed transport and its closed operation registry, with evidence carried per operation, a
  second and third enforcement tier confining the two write-labelled scopes to three named
  operations, and a single permitted network sink;
- credential resolution through the environment or a `0600` credentials file, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, and `auth status`;
- the home view and five read domains: `falcon-axi`, `detection list`, `detection show`, `host list`,
  `host show`, `host logins`, `account list`, `account show`, `vuln list`, and `cve show`;
- NG-SIEM search: `search start`, `search status`, and `search stop`, the three operations captain
  exception N1 admits;
- the Identity Protection directory and timeline: `identity list`, `identity show`, and
  `identity timeline`, sending only fixed read-only GraphQL query documents under captain exception
  N2, the other place falcon-axi asks for a write-labelled scope;
- identity-aware detections (`detection list --product idp`, with account and source-endpoint
  fields when present) and `identity activity <account>`, a fixed NG-SIEM search over one account's
  Identity Protection events that adds no operation and no scope beyond N1's;
- `falcon-axi scopes`, the command-to-scope matrix, printed from the same operation registry the
  transport enforces and without making a request.

What is **not** shipped yet, so no output advertises it:

- every domain `docs/design/v1.md` §1.3 defers, including intel actors, indicators, and reports,
  every NG-SIEM capability outside the three search lifecycle operations (no ingest, no lookup
  files, no parser or dashboard writes, and no Charlotte AI), and every Identity Protection capability
  beyond the directory and timeline: no standalone incident or security-assessment queries, no policy rules,
  and no GraphQL mutation of any kind.
  `cve show` is the one intel read that ships; there is no `cve list`;
- `falcon-axi setup`, including the session hook and the generated skill;
- `--all` and `--max-rows`, and `--fields` on detection and host lists; list pagination takes
  `--limit` and `--cursor` only;
- profile configuration in `~/.config/falcon-axi/config.json`; `--profile` is refused by name rather
  than silently ignored.

`docs/design/v1.md` remains the authority for the full v1 surface, and its §17 open questions are
still open. Nothing here answers one of them.
[`docs/design/v1-python.md`](docs/design/v1-python.md) amends it for language, HTTP client, test
layout, and packaging: falcon-axi is pure Python on `crowdstrike-falconpy`, with no Node runtime and
no MCP process anywhere.

## Read-only, with two captain-granted exceptions

**falcon-axi v1 changes no state in a Falcon tenant, apart from starting and stopping an NG-SIEM
search job, and sending fixed read-only queries through a write-labelled Identity Protection scope.**
It implements no write, create, update, delete, execute, containment, quarantine, release, or
response operation of any other kind.

This is an architectural invariant, not a default posture.
It is enforced at the transport layer through a closed registry rather than by convention: every
registered operation is a read except `StartSearchV1` and `StopSearchV1` (captain exception N1) and
`api_preempt_proxy_post_graphql` (captain exception N2).
A second enforcement tier confines N1 to those two ids and to the single scope `NGSIEM:write`, and a
third confines N2 to its one id and the single scope `Identity Protection GraphQL:write`, so another
write operation cannot be added without editing the allowlist in the transport itself.
The excluded capability classes are named explicitly in the design.
See `docs/design/v1.md` §0, §1.5, §3, §4.3, and §4.4.

**N2 is not general write authority.**
Falcon scopes the one Identity Protection GraphQL endpoint `WRITE` even for read-only queries, and the
same endpoint also accepts mutations.
So falcon-axi never sends GraphQL a caller supplies: the identity commands name one of a closed set
of registered `query` documents, every caller value travels as a JSON variable and never inside the
document text, and the network sink refuses any other body.
There is no `--query` flag, no GraphQL passthrough, and no password reset, account disable, or any
other action on an identity.

If a task needs containment, a real-time-response session, a detection-status update, NG-SIEM
ingest, a parser change, an identity action, or any other change to the tenant, falcon-axi is the
wrong tool and will not be persuaded otherwise.

See [API client permissions](#api-client-permissions) for provisioning, including optional search writes
and license-gated account and CVE access.
Whether member-CID token minting additionally requires `Flight Control:read` remains an explicitly
unresolved question in `docs/design/v1.md` §17.7.
A falcon-axi release that asks for any other write scope is wrong.

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

The pinned tag is the last release.
For commands added after that tag, including host login history, Discover accounts, and CVE intelligence, install from the
default branch until a newer tag exists; see the shipped command list above.

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

For released commands, pin the tag rather than the default branch; suggestions printed by the tool use the
bare `falcon-axi` name, so run the equivalent command through whichever invocation form is installed.

## Credentials

Provision an API client as described in [API client permissions](#api-client-permissions).
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

Create the client in the Falcon console under Support and resources > API clients and keys.

Run `falcon-axi scopes` for the authoritative command-to-scope matrix.
It is projected from the operation and GraphQL document registries the transport enforces and needs no
credential.
`cve show` requires the license-gated `Vulnerabilities (Falcon Intelligence):read`, not Spotlight's
`Vulnerabilities:read`.
`Assets:read` is needed only by the two `account` commands and is license-gated to Falcon Discover or
Exposure Management; a client that cannot be granted it loses those two commands and nothing else.
Grant only the scopes for the domains you intend to read: each is independent, and a command whose
scope is missing fails with `SCOPE_DENIED` naming exactly what to grant.

**Never grant a write, response, containment, Real Time Response, or otherwise mutating scope other
than `NGSIEM:write` and `Identity Protection GraphQL:write`.**
falcon-axi requests none of them, would refuse to use one, and a client provisioned with one is the
wrong client for this tool.
`NGSIEM:write` and `Identity Protection GraphQL:write` are the two exceptions, each is required by its
commands alone, and leaving either ungranted is a supported configuration.

The Identity Protection scopes are expected to appear in the console only for a tenant licensed for
Falcon Identity Protection.
This console visibility requirement is inferred from other license-gated scopes, not verified for
Identity Protection.
To enable `identity list`, `identity show`, and `identity timeline`, edit the falcon-axi API client and grant `Identity Protection
GraphQL` (the console offers write only), `Identity Protection Entities` (read), and `Identity
Protection Timeline` (read).
A command missing required permissions answers `SCOPE_DENIED` naming its required scopes; use
`falcon-axi scopes` for the per-command requirements.

Whether minting a member-CID token additionally requires `Flight Control:read` is an open design
question (`docs/design/v1.md` §17.7), not a settled requirement.
If `--member-cid` fails with `TENANT_DENIED` on a client that reads its own tenant fine, that scope is
the first thing to check.

## Region and tenant

`--region` takes one of `us-1`, `us-2`, `eu-1`, `us-gov-1`, or a full base URL.
The default is `us-1`, and a credential that belongs to another cloud is re-targeted from the
`X-Cs-Region` response header rather than failing, which `auth status` reports.
Falcon can announce that cloud with a redirect and `X-Cs-Region`.
falcon-axi does not follow the redirect, and re-mints once against the verified host for that region.
An origin outside the trusted Falcon hosts is refused as `ORIGIN_NOT_ALLOWED` unless
`--allow-unknown-origin` is passed deliberately.

`--member-cid <cid>` reads one Flight Control child tenant for that invocation, and
`--no-member-cid` clears an inherited `FALCON_MEMBER_CID`.
The two cannot be combined.
A standalone member-CID value is sensitive: auth status, suggestions, URLs, and logs mask it or do not print it.
The `--member-cid` flag remains available for child-tenant selection, but its value is never echoed into output.
Alerts v2 composite detection ids contain the own-tenant or selected child CID and are printed as-is, including
when passed to `detection show`.
NG-SIEM search event CID fields (`cid`, `#repo.cid`) are redacted in output.

## Workflow

1. `falcon-axi auth status` - confirm a credential resolved, from which channel, into which region,
   and how much rate-limit headroom is left.
2. `falcon-axi` - the content-first home view: tenant line plus the five newest detections.
3. `falcon-axi detection list` - the working surface, with filters and pagination.
4. `falcon-axi detection show <id>` - one detection in full.
5. `falcon-axi host show <device_id>` - the host a detection fired on.
6. `falcon-axi vuln list --host <device_id>` - that host's exposure.
7. `falcon-axi cve show <CVE-ID>` - what Falcon Intelligence knows about one CVE, which is not host exposure.
8. `falcon-axi detection list --product idp` and `falcon-axi identity activity <account_id>` - for an
   identity detection, what that account did.
9. `falcon-axi search start --query '<cql>'` - when the question is not one of the domains
   above, ask NG-SIEM directly, then poll with `search status <id>` and cancel with
   `search stop <id>`.
10. `falcon-axi identity list --name 'Admin*'` - who an account is, how risky it is, and (with
   `identity show <id>` and `identity timeline <id>`) what it owns and what it did.

```
falcon-axi                                          what is firing right now
falcon-axi auth status                              whether a credential resolved, and where to
falcon-axi scopes                                   what to grant the API client
falcon-axi detection list                           the 20 newest detections
falcon-axi detection list --severity critical       one severity
falcon-axi detection list --status new --since 24h  one status, one window
falcon-axi detection list --product idp             Identity Protection detections
falcon-axi detection list --filter "severity_name:'Critical'+status:'new'"
falcon-axi detection show "ldt:aid:1234"            one detection
falcon-axi detection show "ldt:aid:1234" --full     without truncating long fields
falcon-axi host list --platform windows             the Windows fleet
falcon-axi host list --hostname "WIN-*"             hostname search; Hosts filters take wildcards
falcon-axi host list --status contained             hosts Falcon has contained, as data
falcon-axi host show abc123                         one host
falcon-axi host logins abc123 --since 24h           recent interactive logins on one host
falcon-axi account list --filter "admin_privileges:'Yes'"   Discover accounts with admin rights
falcon-axi account show abc123                      one Discover account
falcon-axi vuln list --severity critical --status open
falcon-axi vuln list --host abc123                  one host's vulnerabilities
falcon-axi cve show CVE-2021-44228               Falcon Intelligence detail for one CVE
falcon-axi identity activity <account_id> --since 7d  an account's identity events
falcon-axi search start --query '#event_simpleName=ProcessRollup2 | head(5)'
falcon-axi search status 01JABCDEF                  one poll: running, cancelled, or done
falcon-axi search stop 01JABCDEF                    cancel a job you no longer need
falcon-axi identity list --name 'Admin*' --type user   Identity Protection users, with risk
falcon-axi identity show 00000000-0000-0000-0000-000000000001      one identity in full
falcon-axi identity timeline 00000000-0000-0000-0000-000000000001 --since 24h
```

`detection list` takes `--severity` (`informational`, `low`, `medium`, `high`, `critical`),
`--status` (`new`, `in_progress`, `closed`, `reopened`), `--product` (`epp` for endpoint alerts, `idp`
for Identity Protection, `mobile`, `xdr`, `overwatch`, `cwpp`, `ngsiem`, `thirdparty`,
`data-protection`), and `--since`.
`host list` takes `--hostname`, `--platform` (`windows`, `mac`, `linux`), `--status` (`normal`,
`containment_pending`, `contained`, `lift_containment_pending`), and `--since` on `last_seen`.
`vuln list` takes `--host`, `--severity` (`low`, `medium`, `high`, `critical`), `--status` (`open`,
`closed`, `reopen`, `expired`), and `--since` on `created_timestamp`.
`vuln list --fields description,base_score` adds those columns to the default
`id,cve,severity,hostname` row; run `falcon-axi vuln list --help` for the allowed names.
An unknown name is refused and the valid names are listed.
`host logins <device_id>` accepts exactly one host and takes `--since` (a relative window) and `--limit`.
Run `falcon-axi host logins --help` for defaults and limits.
Its rows are recent interactive logins from the Host Timeline, not a full audit trail.
`account list` takes `--filter` (raw FQL on Discover account fields), `--limit`, and
`--cursor`; the accounts are the ones Discover has seen log in on endpoints, not an identity
directory.
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

### Identity

Identity Protection detections are Alerts with `product:'idp'`, readable under `Alerts:read`.
They have no device, so a `detection list` page that holds one gains `account` and `product` columns,
and `hostname` shows the endpoint the alert came from or `n/a`; `detection show` prints `account`,
`account_id`, `source_ip`, and `product` when present.
A page of endpoint alerts is unchanged.

`identity activity <account> [--since 24h]` starts one NG-SIEM search over the account's Active Directory,
SSO, and risk-score events and returns the latest 200, newest first.
The account is an objectGUID (`account_id` in `detection show`), a sAMAccountName, or a UPN, and is
matched in full, ignoring case.
Anything else is refused before a request is made, because the value becomes part of the query.
It prints a job id; poll it with `search status <id>` and stop it with `search stop <id>`.
It is a search under N1, not a new operation: it needs `NGSIEM:write` like `search start`, and nothing else.
The identity directory (users, risk scores, associations) is not shipped: its only API route is a GraphQL
endpoint that requires a write scope even to read.

### NG-SIEM search

An NG-SIEM search is a job, not a query, so it is three commands rather than one.
`search start` creates the job and prints its id, `search status <id>` is one poll that reports
`running`, `cancelled`, or `done` with its events, and `search stop <id>` cancels it.
The CLI never blocks on a poll loop: the caller owns it, and a job left running should be stopped.

`--query` takes CQL, which is pipe-based and is neither FQL nor SQL: start from a tag or field
filter and pipe into commands, as in `#event_simpleName=ProcessRollup2 | head(5)` or
`#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count())`.
`--since` bounds the window and defaults to `24h`; `--repository` defaults to `search-all`.
There is no `--limit` and no `--cursor`, because a query job carries no pagination metadata: bound
the result set in the query itself with `| head(N)` or an aggregate.

`search status` prints `parsed_query`, the API's own normalization of what it ran.
Compare it with the query sent: NG-SIEM demotes an unrecognised word to a free-text stage instead of
erroring, so a malformed pipe returns the wrong rows silently rather than failing.

### Identity Protection

`identity list` reads the Falcon Identity Protection directory, users and endpoints with their risk
severity.
It takes `--name` and `--email` patterns (`*` is a wildcard, a bare `*` is refused), `--domain`,
`--type user|endpoint`, `--limit` (ceiling 200), and `--cursor`.
`identity show <id>` prints one identity's risk factors, accounts, associations, and open incidents,
and `identity timeline <id>` prints its recent activity newest first, from `--since` (default `7d`)
and narrowed with `--category` (`activity`, `notification`, `threat`, `entity`, `audit`, `policy`,
`system`; comma-separated).
An identity id is an entity GUID, as printed by `identity list`.
For detail bounds and truncation markers, see [the output contract](docs/design/v1.md#102-default-schemas).

These commands are backed by Identity Protection's GraphQL endpoint, not NG-SIEM, and they send only
fixed, read-only query documents (captain exception N2, above).
The schema CrowdStrike publishes for it is not public, so the documents follow CrowdStrike's and
falcon-mcp's own queries; `docs/design/v1.md` §17 records that they are not yet validated against a
live tenant.
A GraphQL error reported on an HTTP 200 is an `UPSTREAM_ERROR`, never an empty result.

## Output and errors

Output is TOON on stdout.
A non-empty list view prints a `count:` line, a compact domain-specific schema, and a `help[]` array of
the next commands.
Empty results are stated explicitly rather than left as ambiguous silence.
Identity pages report rows shown without a total; their schemas are defined in
[the output contract](docs/design/v1.md#102-default-schemas).

```
count: 2 of 384 total
continuation_cursor: eyJvcGVyYXRpb24iOiJHZXRRdWVyaWVzQWxlcnRzVjIi...
detections[2]{id,severity,tactic,hostname}:
  "ldt:synthetic-agent-01:1001",High,Defense Evasion,WIN-DC-01
  "ldt:synthetic-agent-02:1002",Critical,Execution,WIN-WS-42
help[2]: "Run `falcon-axi detection show <id>` for the full detection","Run `falcon-axi detection list --limit 2 --cursor ...` for the next page"
```

`cve show` prints `cve`, `severity`, `cvss_v3_score`, `exploit_status`, `publish_date`, `updated`, and
`description`, and counts related actor, report, threat, and affected-product lists instead of expanding them.
`host list` prints `hosts[N]{device_id,hostname,platform,last_seen}` and `vuln list` prints
`vulnerabilities[N]{id,cve,severity,hostname}` by default, in the same shape.
`vuln list --fields` appends the selected columns.
`search status` is the exception: a CQL result set has no fixed shape, so its columns are whatever
the query projected.

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

Secrets and tenant CID fields, including `cid` and `#repo.cid` in search events, are redacted
on stdout and stderr; composite detection ids are the exception described under child-tenant selection
above and in [`docs/design/v1.md` §5.5](docs/design/v1.md#55-redaction).

Help is hierarchical: `falcon-axi --help` lists the commands and global flags, and
`falcon-axi host list --help` documents that command's flags, filterable fields, and examples.
Ask the command rather than guessing its flags.

## Pagination

One call reads one page.
`--limit N` sets the rows for this call; `host logins` applies it to the selected host's login window.
Use the command's `--help` for defaults and ceilings; the detailed limit contract lives in
[`docs/design/v1.md` §7.3](docs/design/v1.md#73-default-limits).
A truncated result prints a `continuation_cursor` plus a ready-to-run next-page suggestion that
replays the same filters.
Pass it back with `--cursor <token>`.

The cursor is opaque and bound to the credential and the filter that produced it, so it cannot be
edited, reused across a different query, or shared between tenants.
It hides the fact that Falcon paginates detections, hosts, and accounts by offset, vulnerabilities by an
`after` token, and identities by a GraphQL `endCursor`: the CLI vocabulary is `--cursor` for every paginated command.
`host logins` has no cursor: a full window warns that more logins may exist rather than claiming completeness.
`--all` and `--max-rows` do not exist yet: loop on `--cursor` when more than one
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

Offline fixtures prove deterministic behavior, not upstream fidelity.
[`docs/design/v1.md` §9.4](docs/design/v1.md#94-translation-never-passthrough) owns the error-evidence policy
and points to the recorded endpoint-specific confirmations.
Live Falcon calls are run by hand and stay outside the required checks; the opt-in live smoke suite
of §15 is not implemented yet.

GitHub Actions runs the same offline gate, `uv run scripts/verify.py`, on every pull request and every push
to `main`.
It uses no secrets and makes no Falcon calls.

## Agent skill

[`skills/falcon-axi/SKILL.md`](skills/falcon-axi/SKILL.md) is the agent skill for this CLI, in the
Agent Skills format.
Install it from the repository:

```sh
npx skills add knowttl/falcon-axi --skill falcon-axi -g
```

Drop `-g` for a project-scoped install.
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
