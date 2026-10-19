# correlation-rule list

correlation-rule list      read correlation_rules

```text
uvx falcon-axi correlation-rule list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 500)
--cursor  opaque continuation token from the previous call
Read-only. Requires Correlation Rules:read.
Examples:
  uvx falcon-axi correlation-rule list
  uvx falcon-axi correlation-rule list --limit 2
```
