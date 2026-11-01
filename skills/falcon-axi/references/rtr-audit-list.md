# rtr audit list

rtr audit list             read audit_sessions

```text
npx -y @knowttl/falcon-axi rtr audit list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 1000)
--cursor  opaque continuation token from the previous call
Read-only. Requires Real time response audit:read.
Examples:
  npx -y @knowttl/falcon-axi rtr audit list
  npx -y @knowttl/falcon-axi rtr audit list --limit 2
```
