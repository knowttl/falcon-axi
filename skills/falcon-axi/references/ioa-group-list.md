# ioa group list

ioa group list             read ioa_groups

```text
uvx falcon-axi ioa group list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 500)
--cursor  opaque continuation token from the previous call
Read-only. Requires Custom IOA Rules:read.
Examples:
  uvx falcon-axi ioa group list
  uvx falcon-axi ioa group list --limit 2
```
