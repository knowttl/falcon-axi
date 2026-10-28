# Design index

Status: implemented in Python.
The [full command reference](../commands.md) is generated from the shipped command registry and owns delivery status; the [README](../../README.md#what-it-covers) summarizes command groups.
This page preserves the domain rollout inventory formerly in the README; it is historical context, not a second command registry.

- [v1 behavior and safety design](v1.md): command contracts, scopes, pagination, redaction, transport enforcement, and closed decisions in section 17.
- [Python implementation amendment](v1-python.md): package structure, SDK confinement, golden comparisons, packaging, and commissioning history.
- [Read-only enforcement](../read-only.md): shipped transport enforcement and source-parity validation limits.
- [Contributor workflow](../../CONTRIBUTING.md): offline verification and documentation generation.

## Implemented domain rollout

What is shipped:

- Data Protection configuration reads: `classification list`, `classification show`,
  `data-policy list`, and `data-policy show`; see [Data Protection](../commands.md#classification-list) for usage.
- the package foundation: a Python package, the `falcon-axi` console script, and one offline
  `uv run scripts/verify.py` entry point;
- `-v`, `-V`, and `--version`, printing the bare version;
- the sealed transport and its closed operation registry, with evidence carried per operation,
  [closed exception tiers](v1.md#33-the-transport-is-the-enforcement-point), and a single permitted network sink;
- AXI credential profiles and SecretRefs, per-call XDG paths, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, `auth status`, `profile list`, and `config path`;
- the home view and core read domains: `falcon-axi`, `detection list`, `detection show`, `host list`,
  `host show`, `host logins`, `account list`, `account show`, `vuln list`, `vuln show`, `cve list`, and `cve show`;
- `detection summary`, an on-demand severity count with the same filters as `detection list`;
- cloud inventory and findings: `cloud-asset list`, `cloud-asset show`, `iom list`, `iom show`,
  and `cloud-risk list`.
  See the [cloud contract](v1.md#121-cloud-inventory-and-posture) for pagination, output, and the risk-detail limitation;
- Discover inventory: `asset list`, `asset show`, `application list`, and `login list`, plus
  `host network <device_id>` for Falcon sensor-host IP and MAC address history;
- Falcon Shield SaaS posture checks: `shield list` and `shield show`, using `SaaS Security:read`;
- NG-SIEM search: `search start`, `search status`, and `search stop`, the three operations captain
  exception N1 admits; see the [search contract](v1.md#43-ng-siem-search-was-excluded-on-the-credential-scope-test-and-captain-exception-n1-reversed-it) and [output contract](v1.md#102-default-schemas) for diagnostics;
- Falcon Intelligence: `actor list`, `actor show` (including `--mitre` for JSON ATT&CK mappings),
  `report list`, and `report show`, with FQL filters and cursor pagination on lists;
- the Identity Protection directory and timeline: `identity list`, `identity show`, and
  `identity timeline`, sending only fixed read-only GraphQL query documents under captain exception
  N2;
- `identity assessment [--domain <name>]`, a fixed read-only security-assessment query under N2,
  and `identity sensor list` / `identity sensor show`, ordinary REST reads of sensor inventory;
- identity-aware detections (`detection list --product idp`, with account and source-endpoint
  fields when present) and `identity activity <account>`, a fixed NG-SIEM search over one account's
  Identity Protection events that adds no operation and no scope beyond N1's;
- `falcon-axi scopes`, the command-to-scope matrix, available without making a request;
- `falcon-axi setup` for offline guidance and `falcon-axi setup hooks` for Claude Code, Codex, and OpenCode session integrations;
- firewall configuration reads: `firewall rule list`, `firewall rule show`, and `firewall group list`;
- `ioa group list`, `correlation-rule list`, `case list`, and `case show`.
  These reads match CrowdStrike's documented APIs and falcon-mcp; they have not been tenant-validated.
- Falcon Intelligence indicators: `indicator list` with opaque marker continuation and `indicator show`.
  These reads match first-party API sources and are tested offline, without tenant validation.
- malware families: `malware list` and `malware show`;
- Identity Protection policy rules: `identity rule list` and `identity rule show`, using REST reads;
- Discover IoT inventory: `iot list`, with token pagination and the license-gated Falcon Discover IoT:read scope.
  These three areas follow the official API reference, falconpy, and PSFalcon; they have synthetic offline tests and are not tenant-validated.
- the generated [agent skill](../../README.md#use-with-your-agent) and its bare-home install hint, specified in
  [the integration contract](v1.md#122-session-hook-and-skill);
- bounded `--all` walks with `--max-rows` on detection, host, account, and vuln lists, retaining partial
  results and emitting a continuation cursor only when the next position is reachable.
- `--fields` on detection, host, and vuln lists to append selected columns to the default row.
- container and serverless reads: `container list`, `image list`, `image vulnerabilities`, and `serverless list`.
  They match first-party API sources and are tested offline, without tenant validation.
  See the [container and serverless contract](v1.md#25-container-and-serverless-reads) for filters, paging boundaries, and SARIF output, and [API client permissions](../commands.md#api-client-permissions) for provisioning.

- custom IOC reads: `ioc list`, `ioc show`, `ioc hosts <type:value>`, and
  `ioc processes <type:value> --host <device_id>`;
- host-group reads: `host-group list` and `host-group members <id>`.
  See [the command reference](v1.md#141-custom-iocs-and-host-groups) for pagination and observation inputs.
- policy inventory, host membership, and Device Control USB configuration details.
  See the policy contract in [v1 §1.2](v1.md#12-shipped-read-domains-plus-ng-siem-search-and-the-identity-directory-under-captain-exceptions-n1-and-n2) for supported types and read boundaries, and the [generated command reference](../commands.md#policy-list) for usage.

- weekly sensor usage reports: `sensor-usage list [--filter <FQL>]`;
- Falcon Recon reads: `recon-rule list|show`, `recon-notification list|show`, and
  `recon-record list|show` for monitoring rules, notifications, and exposed-data records.
  Lists take `--filter`, `--limit`, and `--cursor`.
  Detail views preview long strings; pass `--full` for untruncated content.
  See [the sensor usage and Recon contract](v1.md#24-sensor-usage-and-falcon-recon-reads)
  for API evidence and validation limits, and run `falcon-axi scopes` for permissions.
- Exclusion inventories: `exclusion list --type ml|ioa|sensor-visibility|certificate` and
  `exclusion show <id> --type ...`; quarantined file metadata: `quarantine list` and `quarantine show <id>`.
  These commands read configuration and file metadata only, with no release, delete, or exclusion changes.


## Deliberately excluded

Tenant discovery and standalone Identity Protection incident queries remain absent.
There is no arbitrary GraphQL, GraphQL mutation, containment, ingest, configuration change, report PDF, or rule-file download.
The complete exclusion contract is in [v1 section 1.5](v1.md#15-command-surface-non-goals), and the closed exceptions are owned by [v1 section 0](v1.md#0-invariant-r-v1-is-read-only-with-four-captain-granted-exceptions).
