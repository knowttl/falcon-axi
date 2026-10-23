# sandbox show

sandbox show <report-id> existing report summary and environment details

```text
uvx falcon-axi sandbox show <report-id>

Includes file_type, classification_tags, submit_url, and sha256 per environment.
Omits tenant CID, user identity, and artifact download handles.

Examples:
  uvx falcon-axi sandbox show synthetic-report-01
  uvx falcon-axi sandbox list --filter "verdict:'malicious'"

Read-only; requires Sandbox (Falcon Intelligence):read and Falcon Intelligence (Sandbox).
```
