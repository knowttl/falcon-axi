# rtr session list

rtr session list           read sessions

```text
npx -y @knowttl/falcon-axi@next rtr session list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 5000)
--cursor  opaque continuation token from the previous call
Read-only. Requires Real time response:read.
Examples:
  npx -y @knowttl/falcon-axi@next rtr session list
  npx -y @knowttl/falcon-axi@next rtr session list --limit 2
```
