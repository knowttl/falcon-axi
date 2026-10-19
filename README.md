# falcon-axi

Read CrowdStrike Falcon from the shell with compact, structured results for agents and the humans running them.

[![PyPI](https://img.shields.io/pypi/v/falcon-axi)](https://pypi.org/project/falcon-axi/)
[![Python](https://img.shields.io/pypi/pyversions/falcon-axi)](https://pypi.org/project/falcon-axi/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release provenance: PyPI Trusted Publishing](https://img.shields.io/badge/provenance-PyPI_Trusted_Publishing-blue)](https://pypi.org/project/falcon-axi/#history)

Ask for a severity count without retrieving every detection.
Actual output replayed against the repository's synthetic offline fixture:

```console
$ falcon-axi detection summary --severity critical
detections: 0 detections matching critical severity
```

[Quickstart](#quickstart) • [Use with your agent](#use-with-your-agent) • [Features](#features) • [Safety](#safety) • [Configuration](#configuration) • [Commands](#commands)

## Why this exists

Investigating Falcon often means stitching together API requests, pagination, and product-specific response shapes.
falcon-axi exposes those reads as shell commands with small default schemas, structured errors, and next-step suggestions.
It runs as a Python CLI without an MCP server process and uses CrowdStrike's FalconPy SDK.

## Features

- **Investigation:** detections, severity counts, hosts, login and network history, vulnerabilities, and threat intelligence.
- **Inventory:** Discover assets and accounts, identities, IoT, cloud assets, containers, images, and serverless findings.
- **Configuration reads:** policies, exclusions, firewall and IOA rules, cases, Data Protection, SaaS posture, and Recon.
- **Search:** bounded NG-SIEM jobs and fixed account-activity queries, with explicit status and cancellation.
- **Structured output:** [TOON](https://toonformat.dev/) data and errors on stdout, with optional fields and continuation cursors.
- **Agent integration:** local session context for Claude Code, Codex, and OpenCode, plus an installable skill.

## Quickstart

Requires Python 3.11 or newer.
Install from PyPI with either command:

```sh
pip install falcon-axi
# Or install in an isolated tool environment:
uv tool install falcon-axi
```

For invocation without a permanent install:

```sh
uvx falcon-axi setup
```

Create a Falcon API client with the [permissions](#api-client-permissions) needed for your reads.
Have your secret manager or protected shell environment supply `FALCON_AXI_CLIENT_ID` and `FALCON_AXI_CLIENT_SECRET`.
Do not put credentials in shell command arguments, shell history, or agent chat.

```sh
falcon-axi setup
falcon-axi auth status
falcon-axi detection summary --severity critical
```

The example above shows the actual empty-result output; your tenant determines the counts.
Run `falcon-axi` for recent detections, or `falcon-axi detection list --severity high --since 24h` for a filtered page.
For persistent profile configuration, see [Configuration](#configuration).

## Use with your agent

Install the CLI in a durable location, then opt in to session context:

```sh
falcon-axi setup hooks
```

This installs or repairs integrations for Claude Code, Codex, and OpenCode.
At session start they provide local profile status, region, version, and a command hint without contacting Falcon.
Ordinary read commands never install hooks.
Temporary installations and git worktrees are refused as hook targets.

The [generated skill](skills/falcon-axi/SKILL.md) provides on-demand guidance instead of session context:

```sh
npx skills add knowttl/falcon-axi --skill falcon-axi
```

Add `-g` for a user-wide skill.
Choose either integration or use both; setup does not install the skill.

<details>
<summary>Remove session integrations</summary>

Remove only hook entries whose command contains `falcon-axi-session` from `~/.claude/settings.json` and `~/.codex/hooks.json`.
Delete the managed `~/.config/opencode/plugins/axi-falcon-axi.js` file.
Setup also enables `[features].hooks` in `~/.codex/config.toml`; leave it enabled if other integrations use hooks.
Preserve unrelated settings and hooks.

</details>

## Safety

falcon-axi reads Falcon data without changing hosts, detections, policies, or identities.
It cannot contain endpoints, run response sessions, release quarantined files, update configuration, or send GraphQL mutations.
There is no arbitrary API passthrough.

Starting and stopping an NG-SIEM search job are its only tenant-side effects.
They require `NGSIEM:write`; `identity activity` starts the same kind of job.
Set `FALCON_AXI_READ_ONLY=1` to block search start, search stop, and identity activity locally.
Identity directory, timeline, and assessment reads require a scope Falcon labels write, but send only fixed read-only query documents.
They accept no caller-supplied GraphQL.

Credentials and standalone tenant CID fields are redacted from stdout and stderr.
Composite detection IDs contain a tenant CID and remain intact so they can be passed to detail commands.
Treat output containing detection IDs or security findings as sensitive.

Credentials stay in your environment or referenced local files.
API requests send credentials to Falcon's OAuth endpoint and query inputs to the selected Falcon API cloud, through your configured proxy if present.
Tokens are held in memory; no persistent token cache is written.
The explicit setup installer writes local agent configuration.
See [read-only enforcement and validation](docs/read-only.md) for the mechanics and evidence limits.

### API client permissions

Create an API client under **Support and resources > API clients and keys** in Falcon.
Grant only the domains you use; available scopes depend on product licensing.

<details>
<summary>Required scopes by command</summary>

<!-- permissions:start -->
| Scope | Commands | Requirement |
| --- | --- | --- |
| `Alerts:read` | detection summary, detection list, detection show | yes |
| `Hosts:read` | host list, host show, host logins, host network | yes |
| `Assets:read` | account list, account show, asset list, asset show, application list, login list | yes |
| `Falcon Discover IoT:read` | iot list | yes |
| `Vulnerabilities:read` | vuln show, vuln list | yes |
| `Vulnerabilities (Falcon Intelligence):read` | cve list, cve show | yes |
| `Actors (Falcon Intelligence):read` | actor list, actor show | yes |
| `Reports (Falcon Intelligence):read` | report list, report show | yes |
| `Malware Families (Falcon Intelligence):read` | malware list, malware show | yes |
| `Indicators (Falcon Intelligence):read` | indicator list, indicator show | yes |
| `Falcon Container Image:read` | container list, image list, image vulnerabilities, serverless list | yes |
| `Data Protection:read` | classification list, classification show, data-policy list, data-policy show | yes |
| `NGSIEM:write` | identity activity, search start, search stop | yes |
| `NGSIEM:read` | search status | yes |
| `Identity Protection GraphQL:write` | identity list, identity show, identity timeline, identity assessment | yes |
| `Identity Protection Entities:read` | identity list, identity show, identity sensor list, identity sensor show | yes |
| `Identity Protection Timeline:read` | identity timeline | yes |
| `Identity Protection Assessment:read` | identity assessment | yes |
| `Identity Protection Policy Rules:read` | identity rule list, identity rule show | yes |
| `IOC Management:read` | ioc list, ioc show | yes |
| `IOCs (Indicators of Compromise):read` | ioc hosts, ioc processes | yes |
| `Host Groups:read` | host-group list, host-group members | yes |
| `Prevention Policies:read` | policy list, policy members | selected --type |
| `Sensor Update Policies:read` | policy list, policy members | selected --type |
| `Firewall Management:read` | policy list, policy members, firewall rule list, firewall rule show, firewall group list | yes |
| `Device Control Policies:read` | policy list, policy members | selected --type |
| `Response Policies:read` | policy list, policy members | selected --type |
| `Content Update Policies:read` | policy list, policy members | selected --type |
| `Cloud Security API Assets:read` | cloud-asset list, cloud-asset show | yes |
| `Cloud Security API Detections:read` | iom list, iom show | yes |
| `Cloud Security API Risks:read` | cloud-risk list | yes |
| `SaaS Security:read` | shield list, shield show | yes |
| `Machine Learning Exclusions:read` | exclusion list, exclusion show | selected --type |
| `IOA Exclusions:read` | exclusion list, exclusion show | selected --type |
| `Sensor Visibility Exclusions:read` | exclusion list, exclusion show | selected --type |
| `Quarantined Files:read` | quarantine list, quarantine show | yes |
| `Custom IOA Rules:read` | ioa group list | yes |
| `Correlation Rules:read` | correlation-rule list | yes |
| `Cases:read` | case list, case show | yes |
| `Sensor Usage:read` | sensor-usage list | yes |
| `Monitoring rules (Falcon Intelligence Recon):read` | recon-rule list, recon-rule show, recon-notification list, recon-notification show, recon-record list, recon-record show | yes |
<!-- permissions:end -->

</details>

`falcon-axi scopes` prints the complete per-command matrix offline, including all product and policy scopes.
The [full permissions table](docs/commands.md#api-client-permissions) is generated from the same registry.
No other write scope is needed.
Missing permissions produce `SCOPE_DENIED`; leaving optional scopes ungranted is supported.

## Configuration

`falcon-axi config path` reports configuration paths.
On Linux and macOS, config defaults to `~/.config/falcon-axi/config.json`, respecting an absolute `XDG_CONFIG_HOME`.
Windows uses `%APPDATA%\falcon-axi\config.json`.

| Flag | Environment variable | Profile key / purpose |
| --- | --- | --- |
| `--profile <name>` | `FALCON_AXI_PROFILE` | Select a named profile |
| `--config <path>` | `FALCON_AXI_CONFIG` | Override config path |
| `--region <region>` | `FALCON_AXI_REGION` | `region`: `us-1` (default), `us-2`, `eu-1`, `us-gov-1`, or base URL |
| `--member-cid <cid>` | `FALCON_AXI_MEMBER_CID` | `memberCid`: select one Flight Control child tenant |
| `--no-member-cid` | | Clear inherited child-tenant selection |
| | `FALCON_AXI_CLIENT_ID` | `clientId`: environment profile client ID |
| | `FALCON_AXI_CLIENT_SECRET` | Default secret reference |
| | `FALCON_AXI_PROXY_URL` | HTTPS proxy URL |
| | `FALCON_AXI_READ_ONLY` | `1` / `true` blocks search lifecycle; `0` / `false` allows it |
| `--help` | | Per-command flags, arguments, limits, and examples |
| `--version`, `-v`, `-V` | | Bare installed version |

<details>
<summary>Named profiles and secret files</summary>

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

Replace the client ID locally, never in chat.
Use `{"file":"/absolute/local/path"}` to reference a UTF-8 secret file instead.
Inline secrets are rejected.
On POSIX, secret files must have mode 0400 or 0600; config files must not be group/world writable, and both must be owned by you.
On Windows, links and reparse points are rejected; `auth status` also checks the protected user/SYSTEM/Administrators DACL.

Selection order is an explicit `--profile`, `FALCON_AXI_PROFILE`, a complete environment profile, `defaultProfile`, then the only configured profile.
A partial environment credential pair fails rather than falling back.
An explicitly selected profile ignores environment credential fields except its named SecretRefs.
Region and member-CID flags override profile fields.

```sh
falcon-axi profile list
falcon-axi auth status --profile production
```

</details>

## Commands

Names below omit the `falcon-axi` prefix.
This table and the [full command and permissions reference](docs/commands.md) are generated from the CLI registry and checked locally for drift.
Run any command with `--help` for its arguments and examples.

<details>
<summary>Complete command table</summary>

<!-- commands:start -->
| Command | Purpose |
| --- | --- |
| `detection summary` | counts of detections by severity |
| `detection list` | list detections from the Falcon Alerts collection |
| `detection show` | <id>       the full detail for one detection |
| `host list` | list hosts from the Falcon Hosts collection |
| `host show` | <device id>     the full detail for one host |
| `host logins` | <device id>   recent interactive logins on one host |
| `host network` | <device id>  IP and MAC address history for one host |
| `account list` | list Discover accounts observed on endpoints |
| `account show` | <id>         the full detail for one account |
| `asset list` | list Discover managed and unmanaged assets |
| `asset show` | <id>           details for one Discover asset |
| `application list` | list Discover applications |
| `login list` | list Discover-observed logins across assets |
| `iot list` | list Discover IoT assets |
| `vuln show` | <id>            details for one Spotlight vulnerability record |
| `vuln list` | list Spotlight vulnerabilities; a filter is required |
| `cve list` | list Falcon Intelligence CVEs |
| `cve show` | <CVE-ID>         Falcon Intelligence detail for one CVE |
| `actor list` | list Falcon Intelligence actors |
| `actor show` | <id>           the detail for one intelligence actor |
| `report list` | list Falcon Intelligence reports |
| `report show` | <id>          the detail for one intelligence report |
| `malware list` | list intelligence malware families |
| `malware show` | <id>         the full malware family record |
| `indicator list` | list Falcon Intelligence indicators |
| `indicator show` | <id>       detail for one intelligence indicator |
| `container list` | list Kubernetes containers |
| `image list` | list container image assessments |
| `image vulnerabilities` | list container image vulnerabilities |
| `serverless list` | read serverless vulnerability SARIF |
| `classification list` | list Data Protection classifications |
| `classification show` | <id>  full Data Protection classification |
| `data-policy list` | list Data Protection policies |
| `data-policy show` | <id>     full Data Protection policy |
| `identity activity` | <acct>  start a search for one account's identity events |
| `search start` | start an NG-SIEM CQL search job |
| `search status` | <id>        poll one search job and read its events |
| `search stop` | <id>          cancel one search job |
| `identity list` | list Identity Protection users and endpoints with their risk |
| `identity show` | <id>        one identity's risk, accounts, associations, and open incidents |
| `identity timeline` | <id>    one identity's recent activity |
| `identity assessment` | security assessment score and risk factors |
| `identity sensor list` | list Identity Protection sensors |
| `identity sensor show` | <id> one Identity Protection sensor's details |
| `identity rule list` | list Identity Protection policy rules |
| `identity rule show` | <id>   the full Identity Protection policy rule |
| `ioc list` | list custom indicators |
| `ioc show` | <id>             read one custom indicator |
| `ioc hosts` | <type:value>  list observed hosts for a custom IOC |
| `ioc processes` | <type:value>  list observed processes for a custom IOC |
| `host-group list` | list host-group list |
| `host-group members` | <id>     list host-group members |
| `policy list` | list policies of one required type |
| `policy members` | <id>       list hosts assigned to a policy |
| `cloud-asset list` | list CSPM cloud assets |
| `cloud-asset show` | <id>         inspect one cloud-asset |
| `iom list` | list cloud Indicators of Misconfiguration |
| `iom show` | <id>         inspect one iom |
| `cloud-risk list` | list aggregated cloud risks |
| `shield list` | list SaaS security posture checks |
| `shield show` | <id>          detail for one SaaS security posture check |
| `exclusion list` | list ML, IOA, sensor-visibility, or certificate exclusions |
| `exclusion show` | <id>       the full exclusion record for a required --type |
| `quarantine list` | list quarantined file metadata |
| `quarantine show` | <id>      the full quarantined file record |
| `firewall rule list` | read firewall_rules |
| `firewall rule show` | <id>    read one record |
| `firewall group list` | read firewall_groups |
| `ioa group list` | read ioa_groups |
| `correlation-rule list` | read correlation_rules |
| `case list` | read cases |
| `case show` | <id>             read one record |
| `auth status` | whether a credential resolved, and where to |
| `profile list` | configured profile names, without reading secrets |
| `config path` | config and write-journal paths |
| `scopes` | the command-to-scope matrix, with no request made |
| `sensor-usage list` | weekly sensor usage reports |
| `recon-rule list` | list Recon monitoring rules |
| `recon-rule show` | <id>          full record detail |
| `recon-notification list` | list Recon notifications |
| `recon-notification show` | <id>  full record detail |
| `recon-record list` | list Recon exposed-data records |
| `recon-record show` | <id>        full record detail |
| `setup` | offline installation and credential guidance |
| `setup hooks` | install or repair all three session integrations |
<!-- commands:end -->

</details>

## Output and errors

Data and structured errors use TOON on stdout; diagnostics use stderr.
List results use compact columns, explicit empty states, and next-step hints.
Detection, host, and vulnerability lists accept `--fields` to append selected columns; invalid field names are refused.
Detail commands that support `--full` use it to expand truncated content.

Exit status is `0` for success, `2` for `VALIDATION_ERROR`, `CONFIG_INVALID`, or `FQL_INVALID`, and `1` for other failures.
Errors carry a stable `code` and actionable `help`.
Unknown flags and commands fail loudly.

## Pagination

One invocation reads one page by default.
Use `--limit N` where supported, then pass the emitted `continuation_cursor` back as `--cursor <token>`, preserving query and credential context.
Cursors are opaque and cannot be moved between queries or tenants.

Detection, host, account, and vulnerability lists support `--all --max-rows N` (default cap 1000).
An incomplete walk keeps its rows, exits successfully, and prints `partial: true` with a `stop_reason`.
Detection walks stop at 10000 query rows; host walks stop at 9999.
Narrow the filter at these boundaries; a cursor is emitted only if the next page is reachable.
Run the selected list with `--help` for its own limits.

NG-SIEM jobs have no cursor or limit flags.
Bound results in CQL with a command such as `head(200)`, poll with `search status <id>`, and cancel unfinished jobs with `search stop <id>`.
Check `parsed_query` in status output: NG-SIEM can interpret unknown words as free text.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `PROFILE_REQUIRED` / `AUTH_REQUIRED` | Supply an environment credential pair or configure an env/file SecretRef; run `auth status` |
| `AUTH_FAILED` | Check that the client is enabled and its credential is current |
| `CONFIG_INSECURE` | Fix file ownership, permissions, or Windows DACL as indicated by the error |
| `SCOPE_DENIED` | Compare `falcon-axi scopes` with the client's grants and product licenses |
| `TENANT_DENIED` for a child CID | Check Flight Control access in Falcon; tenant discovery is not provided |
| `ORIGIN_NOT_ALLOWED` / region mismatch | Check `--region`; known Falcon region discovery is automatic |
| `FQL_INVALID` | Use the selected command's documented fields; Spotlight requires a filter and rejects wildcards |
| `RATE_LIMITED` | Follow the structured error's retry guidance |
| Hook installation refused | Use a durable CLI installation and repair malformed agent configuration |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the offline verification commands, synthetic fixtures, and documentation generation.
Tests run locally; GitHub test CI is disabled.
API shapes follow official CrowdStrike sources and offline fixtures; no live-tenant validation is claimed.

## License

[MIT](LICENSE).

If this project saved you time or helped your workflow, please consider giving it a ⭐ on GitHub to help others find it!
