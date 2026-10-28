# falcon-axi

Read CrowdStrike Falcon from the shell with compact, structured results for agents and the humans running them.

[![PyPI](https://img.shields.io/pypi/v/falcon-axi)](https://pypi.org/project/falcon-axi/) [![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE) [![Python](https://img.shields.io/pypi/pyversions/falcon-axi)](https://pypi.org/project/falcon-axi/) [![Provenance](https://img.shields.io/badge/provenance-PyPI_Trusted_Publishing-blue)](https://pypi.org/project/falcon-axi/#history) [![AXI](https://img.shields.io/badge/AXI-agent--friendly-blue)](https://github.com/kunchenguid/axi)

[Why](#why-this-exists) • [Quickstart](#quickstart) • [Agents](#use-with-your-agent) • [Coverage](#what-it-covers) • [Safety](#safety) • [Configuration](#configuration) • [Output](#output-and-exit-codes) • [Troubleshooting](#troubleshooting) • [Contributing](#contributing) • [Security](#security) • [License](#license)

## Why this exists

Raw Falcon APIs leave agents stitching together routes, pagination, and large product-specific responses.
falcon-axi provides verified read routes, bounded pages, compact TOON output, and actionable next-step hints.
It is read-only by default, with explicit boundaries for search jobs and guarded response sessions.
Synthetic offline checks verify local behavior and safety constraints; they do not claim live-tenant validation.

## Quickstart

Requires Python 3.11 or newer and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Install globally, then open the home view for recent detections:

```sh
uv tool install falcon-axi
falcon-axi
# Without a permanent install: uvx falcon-axi
```

Create a Falcon API client with the [required permissions](docs/commands.md#api-client-permissions).
Have your secret manager supply `FALCON_AXI_CLIENT_ID` and `FALCON_AXI_CLIENT_SECRET` in the environment.
Keep credentials out of command arguments, shell history, and agent chat.
For named profiles or secret files, see [configuration](docs/configuration.md).

```sh
falcon-axi setup
falcon-axi auth status
```

Read a severity count; this empty result is replayed from a synthetic offline fixture:

```console
$ falcon-axi detection summary --severity critical
detections: 0 detections matching critical severity
```

## Use with your agent

Opt in to local session context after installing the CLI in a durable location:

```sh
falcon-axi setup hooks
```

Hooks provide profile status, region, version, and a command hint to Claude Code, Codex, and OpenCode without contacting Falcon.
For on-demand guidance and the full command references, install the [agent skill](skills/falcon-axi/SKILL.md):

```sh
npx skills add knowttl/falcon-axi --skill falcon-axi
```

Choose either integration or both; neither grants Falcon permissions, and setup does not install the skill.
See [agent integration](docs/agent-integration.md) for targets, durable-install requirements, and hook removal.

<a id="features"></a>
<a id="commands"></a>

## What it covers

Names omit the `falcon-axi` prefix; every group links to its complete command reference.
The [generated leaf table](docs/commands.md#commands) owns the shipped command list.
Run any command with `--help` for arguments, limits, and examples.

| Groups | Purpose | Access | Reference |
| --- | --- | --- | --- |
| `detection`, `host`, `process` | Alerts, endpoint history, and process lineage | Read; `host usb` starts a search | [Investigation](docs/commands.md#detection-summary) |
| `account`, `asset`, `application`, `login`, `iot`, `host-group` | Discover inventory and group membership | Read | [Inventory](docs/commands.md#account-list) |
| `vuln`, `cve` | Spotlight findings and CVE intelligence | Read | [Vulnerabilities](docs/commands.md#vuln-list) |
| `actor`, `report`, `malware`, `indicator`, `ioc`, `sandbox`, `quarantine` | Threat intelligence, observed indicators, and file metadata | Read | [Intelligence](docs/commands.md#actor-list) |
| `identity` | Directory risk, activity, assessment, sensors, and rules | Read; `activity` starts a search | [Identity](docs/commands.md#identity-list) |
| `search`, `malquery` | NG-SIEM jobs and bounded malware-pattern searches | Read and search lifecycle | [Search](docs/commands.md#search-start), [MalQuery](docs/commands.md#malquery-search) |
| `container`, `image`, `serverless`, `cloud-asset`, `iom`, `cloud-risk` | Workloads, cloud inventory, and misconfigurations | Read | [Cloud](docs/commands.md#cloud-asset-list) |
| `classification`, `data-policy`, `policy`, `exclusion`, `firewall`, `ioa`, `correlation-rule` | Security configuration and rule inventories | Read | [Policies](docs/commands.md#policy-list) |
| `shield`, `file-change`, `case`, `sensor-usage`, `recon-rule`, `recon-notification`, `recon-record` | Posture, change history, cases, usage, and Recon | Read | [Posture](docs/commands.md#shield-list) |
| `rtr` | Passive session history and guarded read-only commands | Read; execution opens a session | [RTR](docs/read-only.md#rtr-operator-guidance) |
| `auth`, `profile`, `config`, `scopes`, `setup` | Credential diagnostics, permissions, and agent setup | Read; `setup hooks` writes local agent settings | [Setup](docs/commands.md#setup) |

## Safety

falcon-axi is read-only by default: no containment, remediation, quarantine release, configuration changes, or arbitrary API passthrough.
Tenant-side effects are limited to NG-SIEM jobs, bounded MalQuery searches, and guarded RTR sessions.
RTR previews locally; execution requires profile opt-in, a fixed command allowlist, `--execute`, and exact `--confirm`.
Set `FALCON_AXI_READ_ONLY=1` to block search lifecycle commands, MalQuery search, and RTR execution.
Passive history, local previews, and fixed read-only Identity GraphQL queries remain available.
Identity GraphQL requires a write-labelled scope but accepts only registered read-only documents.
Credentials use environment or file references; tokens stay in memory, and credentials and standalone tenant CIDs are redacted.
Composite detection IDs retain embedded tenant CIDs, so treat investigation output as sensitive.
See [read-only enforcement](docs/read-only.md) for gates, data handling, and recovery.

<a id="api-client-permissions"></a>

Create an API client under **Support and resources > API clients and keys** in Falcon, granting only the domains you use.
Run `falcon-axi scopes` offline or consult the [permissions matrix](docs/commands.md#api-client-permissions); product licensing also controls availability.

## Configuration

Run `falcon-axi config path` to inspect config and journal paths.

| Platform | Default config path |
| --- | --- |
| Linux / macOS | `~/.config/falcon-axi/config.json`, or absolute `$XDG_CONFIG_HOME/falcon-axi/config.json` |
| Windows | `%APPDATA%\falcon-axi\config.json`, falling back to `~/AppData/Roaming/falcon-axi/config.json` |

| Environment variable | Purpose | Default |
| --- | --- | --- |
| `FALCON_AXI_PROFILE` | Named profile; overridden by `--profile` | Automatic selection |
| `FALCON_AXI_CONFIG` | Config file; overridden by `--config` | Platform path above |
| `FALCON_AXI_REGION` | Environment profile cloud; `--region` overrides profiles | `us-1` |
| `FALCON_AXI_MEMBER_CID` | Environment profile child tenant; `--member-cid` overrides profiles | None |
| `FALCON_AXI_CLIENT_ID` | Environment profile client ID | Unset |
| `FALCON_AXI_CLIENT_SECRET` | Environment profile secret / default SecretRef | Unset |
| `FALCON_AXI_PROXY_URL` | HTTPS proxy URL | Direct connection |
| `FALCON_AXI_READ_ONLY` | Block search lifecycle, MalQuery search, and RTR execution | `false`; enable with `1` / `true` |
| `FALCON_AXI_WRITE_LOG` | Mandatory RTR execution journal | State directory `writes.log` |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | Absolute POSIX config / state roots | `~/.config`, `~/.local/state` |
| `APPDATA`, `LOCALAPPDATA` | Windows config / state roots | `~/AppData/Roaming`, `~/AppData/Local` |
| `HOME`, `PATH` | Home and hook executable discovery | Process environment / OS home |
| `CLAUDECODE`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID`, `PI_CODING_AGENT`, `OPENCODE` | Detect the host for skill-install hints | Unset |
| `CLAUDE_CONFIG_DIR`, `PI_CODING_AGENT_DIR` | Host skill-discovery roots | `~/.claude`, `~/.pi/agent` |
| `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_MEMBER_CID`, `FALCON_BASE_URL`, `FALCON_PROXY_URL` | Deprecated aliases; replacements win | Unset |

See [configuration](docs/configuration.md) for profiles, precedence, regions, SecretRefs, and path defaults.
`--no-member-cid` clears inherited child selection; `--version`, `-v`, and `-V` print the installed version.

<a id="output-and-errors"></a>
<a id="pagination"></a>

## Output and exit codes

Data and structured errors use [TOON](https://toonformat.dev/) on stdout; diagnostics use stderr.
Lists have explicit empty states, small default schemas, and next-step hints.
Supported detail commands preview long fields; use their `--full` flag for complete content.
One invocation reads one page by default; pass emitted `continuation_cursor` values to `--cursor` where supported.
Detection, host, account, and vulnerability lists support bounded `--all` walks; search jobs use CQL result bounds instead.
See [pagination and walks](docs/commands.md#pagination-and-walks) for caps and partial-result semantics.

| Exit code | Meaning |
| --- | --- |
| `0` | Success, including empty results |
| `1` | Authentication, permission, network, policy, or other failure |
| `2` | `VALIDATION_ERROR`, `CONFIG_INVALID`, or `FQL_INVALID` |

Errors include a stable `code` and actionable `help`; unknown commands and flags fail loudly.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `PROFILE_REQUIRED` / `AUTH_REQUIRED` / `AUTH_FAILED` | Check the credential pair or SecretRef with `falcon-axi auth status` |
| `CONFIG_INSECURE` | Fix ownership, permissions, or Windows DACL as the error directs |
| `SCOPE_DENIED` / `TENANT_DENIED` | Check `falcon-axi scopes`, licensing, and Flight Control access |
| `ORIGIN_NOT_ALLOWED` / `FQL_INVALID` / `RATE_LIMITED` | Follow structured help for the region, filter, or retry delay |
| Hook installation refused | Use a durable installation and repair malformed agent configuration |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development, offline verification, documentation generation, and releases, and [AGENTS.md](AGENTS.md) for repository constraints.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and sensitive-output handling.

## License

[MIT](LICENSE).
