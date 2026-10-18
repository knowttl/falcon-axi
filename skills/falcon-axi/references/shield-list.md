# shield list

shield list               list SaaS security posture checks

```text
uvx falcon-axi shield list [--status <status>] [--impact <impact>] [--limit N] [--cursor <token>]

List Falcon Shield SaaS security posture checks. This is not the detection alerts list.
--status   Passed, Failed, Dismissed, Pending, Can't Run, Stale, NA, Not Available (case-insensitive)
--impact   Low, Medium, High (case-insensitive)
--limit    rows in this call (default 20, local cap 100)
--cursor   opaque continuation token from a previous call

Examples:
  uvx falcon-axi shield list --status failed --impact high
  uvx falcon-axi shield list --limit 50

Read-only. Requires SaaS Security:read (Falcon Shield).
```
