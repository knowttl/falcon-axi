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
- AXI credential profiles and SecretRefs, per-call XDG paths, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, `auth status`, `profile list`, and `config path`;
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
- `falcon-axi scopes`, the command-to-scope matrix, available without making a request;
- the generated [agent skill](#agent-skill) and its bare-home install hint, specified in
  [the integration contract](docs/design/v1.md#122-session-hook-and-skill);
- bounded `--all` walks with `--max-rows` on detection, host, account, and vuln lists, retaining partial
  results and emitting a continuation cursor only when the next position is reachable.

What is **not** shipped yet, so no output advertises it:

- every domain `docs/design/v1.md` §1.3 defers, including intel actors, indicators, and reports,
  every NG-SIEM capability outside the three search lifecycle operations (no ingest, no lookup
  files, no parser or dashboard writes, and no Charlotte AI), and every Identity Protection capability
  beyond the directory and timeline: no standalone incident or security-assessment queries, no policy rules,
  and no GraphQL mutation of any kind.
  `cve show` is the one intel read that ships; there is no `cve list`;
- `falcon-axi setup`, including the session hook;
- `--fields` on detection and host lists;

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
So falcon-axi never sends GraphQL a caller supplies: the GraphQL directory and timeline commands name one of a closed set
of registered `query` documents, every caller value travels as a JSON variable and never inside the
document text, and the network sink refuses any other body.
The GraphQL commands have no `--query` flag or passthrough, and there is no password reset, account disable,
or any other action on an identity.

If a task needs containment, a real-time-response session, a detection-status update, NG-SIEM
ingest, a parser change, an identity action, or any other change to the tenant, falcon-axi is the
wrong tool and will not be persuaded otherwise.

See [API client permissions](#api-client-permissions) for provisioning, including optional search writes
and license-gated account and CVE access.
Whether member-CID token minting additionally requires `Flight Control:read` remains an explicitly
unresolved question in `docs/design/v1.md` §17.7.
A falcon-axi release that asks for any other write scope is wrong.

## Quick start for agents

Install from PyPI after the first published release: `pip install falcon-axi` or `uv tool install falcon-axi`.
[uv](https://docs.astral.sh/uv/) provisions Python 3.11 or newer on demand, so no system Python is
required.

Run it with no install at all, which is the Python analog of `npx -y`:

```sh
uvx --from git+https://github.com/knowttl/falcon-axi@v0.3.0 falcon-axi auth status
uvx --from git+https://github.com/knowttl/falcon-axi@v0.3.0 falcon-axi detection list --severity high --since 24h
```

The pinned tag is the last release.

Or install the command once and call it directly:

```sh
# Linux, WSL, macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install git+https://github.com/knowttl/falcon-axi@v0.3.0
```

```powershell
# Windows
winget install --id astral-sh.uv
uv tool install git+https://github.com/knowttl/falcon-axi@v0.3.0
```

For released commands, pin the tag rather than the default branch; suggestions printed by the tool use the
bare `falcon-axi` name, so run the equivalent command through whichever invocation form is installed.

## Credentials

Provision an API client as described in [API client permissions](#api-client-permissions).
Supply it using the [AXI credential standard](https://github.com/knowttl/artium-axi/blob/main/docs/credential-standard.md).
For an environment profile:

```sh
export FALCON_AXI_CLIENT_ID=...
export FALCON_AXI_CLIENT_SECRET=...
```

Or create `config.json` in `$XDG_CONFIG_HOME/falcon-axi/` (absolute XDG paths only),
falling back to `~/.config/falcon-axi/` on Linux/macOS.
Windows uses `%APPDATA%\falcon-axi\` and ignores XDG variables.
Paths are resolved on every invocation.

```json
{
  "version": 1,
  "defaultProfile": "production",
  "profiles": {
    "production": {
      "region": "us-1",
      "clientId": "<client-id>",
      "clientSecret": {"env": "FALCON_AXI_CLIENT_SECRET"}
    }
  }
}
```

**No secret is ever accepted as a command-line argument**, and a flag whose name looks like a secret
is rejected at registration rather than at runtime.
`clientSecret` accepts `{"env":"NAME"}` or `{"file":"/absolute/local/path"}`.
Omitting it defaults to `FALCON_AXI_CLIENT_SECRET`; inline secrets and stored references are rejected.
File contents are UTF-8 with a leading BOM and trailing whitespace removed.
On POSIX, config files must be owned by the caller, regular, and not group/world writable;
secret files must have no group/world permissions (0400 and 0600 both work).
On Windows, reads reject reparse points, including symlinks and junctions;
`auth status` additionally verifies a protected DACL granting FullControl only to the current user, SYSTEM, and Administrators.
No file-writing command or persistent token cache exists.

Selection order is `--profile`, `FALCON_AXI_PROFILE`, a complete environment profile,
`defaultProfile`, then the only configured profile.
A partial environment profile fails with `CONFIG_INVALID`.
Selected file profiles ignore environment profile fields, except variables explicitly named by SecretRefs.
`--region`, `--member-cid`, and `--no-member-cid` override selected profile fields.
Unknown keys and invalid profile names are rejected.
`profile list` lists names without resolving secrets; `config path` reports paths.
The packaged `falcon_axi/axi-credential.schema.json` describes one profile for hosts.

The old dotenv credentials file is never read.
If it exists and the new config does not, `CONFIG_MOVED` names both paths and the new format.
Vendor-native `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_MEMBER_CID`, `FALCON_BASE_URL`,
and `FALCON_PROXY_URL` remain deprecated aliases for one minor release, with a stderr notice.
`FALCON_BASE_URL` aliases `FALCON_AXI_REGION`; the other replacements insert `_AXI` after `FALCON`.
The new variable wins when both are set.

| Variable | Meaning |
| --- | --- |
| `FALCON_AXI_CLIENT_ID` | Environment profile API client id |
| `FALCON_AXI_CLIENT_SECRET` | Environment profile secret, or the default SecretRef |
| `FALCON_AXI_REGION` | Environment profile region name or URL |
| `FALCON_AXI_MEMBER_CID` | Environment profile Flight Control child tenant |
| `FALCON_AXI_PROXY_URL` | HTTPS proxy URL |
| `FALCON_AXI_CONFIG` | Config path; `--config` takes precedence |
| `FALCON_AXI_PROFILE` | Selected profile; `--profile` takes precedence |
| `FALCON_AXI_READ_ONLY` | `1`/`true` blocks search start/stop and identity activity; `0`/`false` allows the existing exceptions |
| `FALCON_AXI_WRITE_LOG` | Journal path reported by `config path`; no journal is written |

The default journal path is `$XDG_STATE_HOME/falcon-axi/writes.log`, or
`~/.local/state/falcon-axi/writes.log`; Windows uses `%LOCALAPPDATA%\falcon-axi\writes.log`.
Invalid boolean values fail closed with `CONFIG_INVALID`.

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
`--no-member-cid` clears the selected profile's inherited member CID.
The two cannot be combined.
A standalone member-CID value is sensitive: auth status, suggestions, URLs, and logs mask it or do not print it.
The `--member-cid` flag remains available for child-tenant selection, but its value is never echoed into output.
Alerts v2 composite detection ids contain the own-tenant or selected child CID and are printed as-is, including
when passed to `detection show`.
NG-SIEM search event CID fields (`cid`, `#repo.cid`) are redacted in output.

Suggestions preserve invocation context as specified in
[`docs/design/v1.md` §7.2](docs/design/v1.md#72-what-the-cli-exposes).

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
falcon-axi detection show "<composite id>"         one detection; copy the list's id column
falcon-axi detection show "<composite id>" --full  without truncating long fields
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
for Identity Protection), and `--since`.
Run `falcon-axi detection list --help` for the complete product values.
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
single-quoted; it is grouped when composed with shorthand flags so those flags constrain every OR branch.

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
They have no device, so a `detection list` page that holds one gains `account`, `account_id`, `device_id`,
and `product` columns, and `hostname` shows the source endpoint or `n/a`.
`detection show` prints the same account, source-endpoint, and product fields when present.
A page of endpoint alerts is unchanged.

`identity activity <account> [--since 24h]` starts one NG-SIEM search over the account's Active Directory,
SSO, and risk-score events, bounded to the latest 200, newest first.
The account is an objectGUID (`account_id` in `detection show`), a sAMAccountName, or a UPN, and is
matched in full, ignoring case.
Names must follow [the activity query contract](docs/design/v1.md#identity-activity-a-fixed-search-not-a-fourth-operation),
which defines the allowed characters, event families, and matching fields.
Other values are refused before a request is made, because the value becomes part of the query.
It prints a job id; poll it with `search status <id>` and stop it with `search stop <id>`.
Use the same [region and tenant](#region-and-tenant) when following the job's suggestions.
It is a search under N1, not a new operation; see `falcon-axi scopes` for its required permission.
The separately shipped [Identity Protection directory](#identity-protection) uses GraphQL under N2.
`identity activity` does not use that endpoint or require its scopes.

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
GraphQL identity pages report rows shown without a total; their schemas are defined in
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
errors (`VALIDATION_ERROR`, `CONFIG_INVALID`, `FQL_INVALID`), and `1` for every other
failure.
The stable codes are `VALIDATION_ERROR`, `CONFIG_INVALID`, `CONFIG_INSECURE`, `CONFIG_MOVED`,
`PROFILE_REQUIRED`, `PROFILE_AMBIGUOUS`, `PROFILE_NOT_FOUND`, `FQL_INVALID`, `AUTH_REQUIRED`,
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

By default, one call reads one page.
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
Detection, host, account, and vuln lists accept `--all` to walk pages and `--max-rows N` to cap query rows
(default 1000; requires `--all`).
For budget accounting when records disappear before hydration, see
[`docs/design/v1.md` §7.2](docs/design/v1.md#72-what-the-cli-exposes).
During a walk, page size follows the endpoint maximum and remaining budget, independently of `--limit`.
An incomplete walk retains its rows, exits 0, and prints `partial: true` with `stop_reason: max_rows` or
`stop_reason: pagination_limit`.
A cursor appears only when the next position is reachable.
Alerts walks stop defensively at 10000 query rows, because the documented route past that boundary is not
registered in v1.
Hosts stop at 9999 query rows under the endpoint's `limit + offset < 10000` rule.
At either boundary, narrow the filter to read the remaining data.
`PAGINATION_LIMIT` is an error only when the boundary is reached with no retained rows.
Discover accounts and Spotlight have no such wall.

## Verify

```sh
uv sync
uv run scripts/verify.py
```

[`scripts/verify.py`](scripts/verify.py) defines the complete check sequence and is the single local
entry point, running entirely offline against wholly synthetic fixtures.
A pytest fixture refuses any socket, so no test can reach the network, and no fixture contains a
captured Falcon response, credential, token, or tenant identifier.

The offline suite includes the recorded-invocation gate in `tests/golden/`.
[`docs/design/v1-python.md` §5](docs/design/v1-python.md#5-behavior-that-must-not-change-during-the-port) owns its comparison contract and release-version exception.

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
