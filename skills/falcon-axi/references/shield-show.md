# shield show

shield show <id>          detail for one SaaS security posture check

```text
uvx falcon-axi shield show <check id> [--full]

Read one Falcon Shield posture check, including remediation details returned by the API.
Long text is truncated at 800 characters by default; --full returns untruncated text.

Examples:
  uvx falcon-axi shield show <id>
  uvx falcon-axi shield show <id> --full

Read-only. Requires SaaS Security:read (Falcon Shield).
```
