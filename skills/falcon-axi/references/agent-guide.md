# Falcon investigation quick guide

Start with a command below; reserve `--help` for a command that fails or an unfamiliar option.
Use `uvx falcon-axi` in place of `falcon-axi` when it is not installed globally.
Examples are wholly synthetic; replace their identifiers with values returned by your investigation.
Credentials must already be supplied through environment variables or configured SecretRefs, never arguments.
Append `--profile <name>` to select a configured profile and retain it on every pivot.

## Passive investigation commands

These exact command names form a read-only allowlist: `detection summary`, `detection list`, `detection show`, `detection process`, `host list`, `host show`, `host network`, `host logins`, `process tree`, `search status`, `auth status`, `scopes`.
Do not allow a whole noun such as `host` or `search`: other subcommands can create jobs.

| Question / syntax | Example | Useful flags and bounds |
| --- | --- | --- |
| Alert counts: `detection summary` | `falcon-axi detection summary --since 24h` | `--severity critical`, `--status new`, `--product idp`; counts without listing alerts |
| Triage: `detection list` | `falcon-axi detection list --since 24h --limit 2 --fields status,technique,created_timestamp` | `--severity high`, `--product epp` or `idp`, `--filter <FQL>` |
| Alert detail: `detection show <id>` | `falcon-axi detection show 'ldt:synthetic-agent-01:1001' --full` | `--full` removes long-field previews |
| Alert process lineage: `detection process <id>` | `falcon-axi detection process 'ldt:synthetic-agent:1001'` | Trigger, parent, grandparent, hashes and graph pivot in one call; `--full` removes 800-character command-line previews |
| Find host: `host list` | `falcon-axi host list --hostname 'synthetic-host-*' --limit 2 --fields status,os_version,agent_version` | `--platform windows`, `--since 24h`, `--filter <FQL>`; returns device IDs (AIDs) |
| Host detail: `host show <device-id>` | `falcon-axi host show synthetic-device-01` | Full host record; no `--full` flag |
| Host address history: `host network <device-id>` | `falcon-axi host network synthetic-device-01` | Retained IP/MAC history; no pagination or time flag |
| Interactive logins: `host logins <device-id>` | `falcon-axi host logins synthetic-device-01 --since 24h --limit 2` | Default window 7d; default 20, maximum 100 logins; a filled window may omit older logins |
| Graph lineage: `process tree <pid-id>` | `falcon-axi process tree pid:synthetic-device:1` | Up to five ancestors and one child level, 100 child edges per page; `--cursor <token>` continues children; `--full` for complete command lines |
| Existing search: `search status <job-id>` | `falcon-axi search status synthetic-search-job-01 --wait 30` | `--wait` 1-50 seconds; `--repository <name>` must match start (default `search-all`) |
| Credential diagnosis: `auth status` | `falcon-axi auth status` | Checks credential resolution and authentication without printing secrets |
| Permission matrix: `scopes` | `falcon-axi scopes` | Offline, no credentials required |

Alerts need `Alerts:read`; host commands need `Hosts:read`; the graph tree needs `Threatgraph:read` and API licensing; search status needs `NGSIEM:read`.
Host address history is not remote network connections or DNS history.
Use bounded CQL for `NetworkConnectIP4`, `DnsRequest`, or raw `ProcessRollup2` / `UserLogon` events when the retained views above do not answer the question.

## One-call forms and output budget

List commands already query and hydrate records; avoid showing every ID merely to obtain the default fields.
Use `detection process` for alert-recorded lineage and `process tree` for a graph pivot instead of fetching ancestors by hand.
Host lookup and history remain separate calls: use the returned AID for the history command.

Detection and host lists default to 20 rows, with ceilings of 10000 and 5000 respectively.
`--fields` adds columns to their compact defaults; the examples select alert status/technique/time and host containment status/OS/sensor version.
Follow emitted `continuation_cursor` hints with `--cursor`; cursors bind credentials, tenant and query.
For a bounded multi-page walk these two lists support `--all --max-rows N` (default budget 1000); page size is independent of `--limit`.
Check `partial` and `stop_reason` before treating a walk as complete.
FQL uses `+` for AND, comma for OR, and single-quoted values; quote the entire filter in the shell.

Search creation is a tenant-side effect, requiring separate approval in a passive-only playbook:

```sh
falcon-axi search start --query '#event_simpleName=DnsRequest | head(5)' --since 24h --wait 30
```

`--wait` combines start and polling in one invocation, accepts 1-50 seconds, and requires both `NGSIEM:write` and `NGSIEM:read`.
A timeout leaves the job running; resume with `search status`, retaining the repository.
Without `--wait`, start returns immediately and status polls once.
Search has no `--fields`, `--limit` or `--cursor`: bound events with CQL `head(N)` or aggregates.
Review `parsed_query` (filter only) and warnings before trusting results.
Cancel an unneeded job with `falcon-axi search stop synthetic-search-job-01`; this also requires `NGSIEM:write`.

## Safety, help and failures

The passive allowlist above changes no tenant data or endpoint state.
Outside it, `search start`, `search stop`, `host usb` and `identity activity` manage NG-SIEM jobs; `malquery search` creates bounded exact/fuzzy searches.
`rtr run --execute` opens a real endpoint session even for read-only commands and requires profile opt-in plus exact confirmation; exclude it from passive allowlists.
`setup hooks` writes local agent settings.
`FALCON_AXI_READ_ONLY=1` blocks search lifecycle, MalQuery search and RTR execution; fixed Identity GraphQL reads remain allowed despite their write-labelled scope.
There are no containment, remediation, quarantine-release or tenant-configuration commands.
Treat all investigation output as sensitive: standalone CIDs and secrets are redacted, but composite detection IDs retain embedded CIDs.

Top-level `--help` returns the command list, global flags, regions and safety/scope notes.
Noun-level help (for example `host --help`) lists that group's commands.
Leaf help (for example `host logins --help`) gives exact arguments, flags, defaults, examples and permissions without authentication.
Use these to repair a failed command, rather than as the first investigation step.

Data and structured errors are TOON on stdout; exit 0 includes empty results, exit 1 means failure, and exit 2 means usage/configuration/filter error.
Read the stable `code` and actionable `help` before retrying:

| Code | Adjustment |
| --- | --- |
| `PROFILE_REQUIRED`, `AUTH_REQUIRED`, `AUTH_FAILED` | Fix profile/SecretRef or credential pair; diagnose with `auth status` |
| `CONFIG_INVALID`, `CONFIG_INSECURE` | Fix configuration or file permissions as directed |
| `SCOPE_DENIED`, `TENANT_DENIED` | Check `scopes`, licensing and Flight Control access; retries will not grant access |
| `VALIDATION_ERROR`, `FQL_INVALID` | Correct arguments or FQL; use the failing leaf's help |
| `VALIDATION_ERROR` on search | Correct CQL structure or server-reported semantics before submitting another job |
| `NOT_FOUND` | Check identifier, selected profile/tenant and repository |
| `RATE_LIMITED` | Honor retry guidance after the built-in bounded retries; narrow the request |
| `NETWORK_UNREACHABLE`, `TLS_UNTRUSTED`, `ORIGIN_NOT_ALLOWED` | Fix connectivity, trust or configured region; do not bypass validation |
| `READ_ONLY_VIOLATION` | Respect the policy boundary; use passive reads |

