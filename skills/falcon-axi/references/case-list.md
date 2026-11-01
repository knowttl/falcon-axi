# case list

case list                  read cases

```text
npx -y @knowttl/falcon-axi case list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 500)
--cursor  opaque continuation token from the previous call
Read-only. Requires Cases:read.
Examples:
  npx -y @knowttl/falcon-axi case list
  npx -y @knowttl/falcon-axi case list --limit 2
```
