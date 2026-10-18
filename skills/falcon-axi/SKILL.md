---
name: falcon-axi
description: >-
  Inspect CrowdStrike Falcon detections, hosts, accounts, vulnerabilities, identity, and search results.
  Read-only investigation; no containment, remediation, or tenant configuration changes.
---

# falcon-axi

Read CrowdStrike Falcon detections, hosts, vulnerabilities, and NG-SIEM searches from the shell.
Run `uvx falcon-axi ...` without a global install.

## Read-only boundary

No command changes a host, detection, policy, or identity.
Starting and stopping NG-SIEM search jobs are the only tenant-side effects.
Identity GraphQL uses a write-labelled scope only for fixed read-only query documents.
There is no arbitrary REST or GraphQL escape hatch.

## Orientation

Run `uvx falcon-axi` for recent detections, or invoke a known command directly.

- Run `uvx falcon-axi detection list` to see more detections
- Run `uvx falcon-axi detection list --product idp` for Identity Protection detections
- Run `uvx falcon-axi host list --filter "hostname:'WIN-*'"` to search hosts
- Run `uvx falcon-axi cve show <CVE-ID>` for Falcon Intelligence on one CVE
- Run `uvx falcon-axi scopes` to see what this API client needs

## Commands

```text
uvx falcon-axi detection summary         counts of detections by severity
uvx falcon-axi detection list            list detections from the Falcon Alerts collection
uvx falcon-axi detection show <id>       the full detail for one detection
uvx falcon-axi host list                 list hosts from the Falcon Hosts collection
uvx falcon-axi host show <device id>     the full detail for one host
uvx falcon-axi host logins <device id>   recent interactive logins on one host
uvx falcon-axi account list              list Discover accounts observed on endpoints
uvx falcon-axi account show <id>         the full detail for one account
uvx falcon-axi vuln list                 list Spotlight vulnerabilities; a filter is required
uvx falcon-axi cve show <CVE-ID>         Falcon Intelligence detail for one CVE
uvx falcon-axi indicator list            list Falcon Intelligence indicators
uvx falcon-axi indicator show <id>       detail for one intelligence indicator
uvx falcon-axi container list            list Kubernetes containers
uvx falcon-axi image list                list container image assessments
uvx falcon-axi image vulnerabilities     list container image vulnerabilities
uvx falcon-axi serverless list           read serverless vulnerability SARIF
uvx falcon-axi identity activity <acct>  start a search for one account's identity events
uvx falcon-axi search start              start an NG-SIEM CQL search job
uvx falcon-axi search status <id>        poll one search job and read its events
uvx falcon-axi search stop <id>          cancel one search job
uvx falcon-axi identity list             list Identity Protection users and endpoints with their risk
uvx falcon-axi identity show <id>        one identity's risk, accounts, associations, and open incidents
uvx falcon-axi identity timeline <id>    one identity's recent activity
uvx falcon-axi auth status               whether a credential resolved, and where to
uvx falcon-axi profile list              configured profile names, without reading secrets
uvx falcon-axi config path               config and write-journal paths
uvx falcon-axi scopes                    the command-to-scope matrix, with no request made
```

Run `uvx falcon-axi <command> --help` for accepted flags, defaults, arguments, and examples.

## Credentials and output

Use `uvx falcon-axi auth status` to diagnose credentials without printing their values.
Secrets belong in environment variables or env/file SecretRefs in config.json, never command arguments.
Use `--profile <name>` or `--config <path>` for configured credentials, and `--region` for the Falcon cloud.
Use `--member-cid` to select a Flight Control child tenant and `--no-member-cid` to clear an inherited selection.
Standalone tenant CIDs and credentials are redacted; composite detection ids remain intact.
Quote detection ids and shell-sensitive filters.

Output and errors are TOON on stdout; help entries carry actionable next steps.
Exit codes are 0 for success, 1 for failures, and 2 for usage errors.
A continuation_cursor is opaque and bound to its credential and query; follow the emitted next-page command.
Search jobs have no pagination; bound results in CQL and check parsed_query for unexpected interpretation.
Stop search jobs when no longer needed.
