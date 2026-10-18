# recon-rule list

recon-rule list               list Recon monitoring rules

```text
uvx falcon-axi recon-rule list [--filter <FQL>] [--limit N] [--cursor <token>]

list Recon monitoring rules
--filter     raw FQL; + is AND, `,` is OR, values are single-quoted
--limit      rows in this call (default 20, ceiling 500)
--cursor     opaque continuation token; queries stop at 10000 results
Requires Monitoring rules (Falcon Intelligence Recon):read. Read-only.
Examples:
  uvx falcon-axi recon-rule list --filter "status:'active'"
  uvx falcon-axi recon-rule list --limit 100
```
