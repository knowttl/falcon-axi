# firewall group list

firewall group list        read firewall_groups

```text
uvx falcon-axi firewall group list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  raw FQL; + is AND, comma is OR, values are single-quoted
--limit   rows in this call (default 20, ceiling 5000)
--cursor  opaque continuation token from the previous call
Read-only. Requires Firewall Management:read.
Examples:
  uvx falcon-axi firewall group list
  uvx falcon-axi firewall group list --limit 2
```
