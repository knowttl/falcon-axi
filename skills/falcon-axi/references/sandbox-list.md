# sandbox list

sandbox list             existing sandbox reports by hash or FQL

```text
uvx falcon-axi sandbox list (--sha256 <hash> | --filter <FQL>) [--limit <n>] [--cursor <token>]

--sha256  exactly 64 hex characters; builds sandbox.sha256:'<hash>'
--filter  FQL instead of a hash; exactly one selector is required
--limit   reports per page (default 20, maximum 5000)
--cursor  opaque continuation token for the same query
One row per sandbox environment; count and pagination refer to reports.
The hash filter field is partner-corroborated, not CrowdStrike-documented.

Examples:
  uvx falcon-axi sandbox list --sha256 0000000000000000000000000000000000000000000000000000000000000000
  uvx falcon-axi sandbox list --filter "verdict:'malicious'"

Read-only; requires Sandbox (Falcon Intelligence):read and Falcon Intelligence (Sandbox).
Reads existing reports only; an empty result can mean not licensed or no data.
```
