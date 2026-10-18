# host-group list

host-group list     list host-group list

```text
uvx falcon-axi host-group list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  FQL on group attributes: name, group_type, created_timestamp, modified_timestamp
--limit   rows per call (default 20, ceiling 5000)
--cursor  opaque continuation token

Examples:
  uvx falcon-axi host-group list --limit 100
  uvx falcon-axi host-group list --filter "group_type:'dynamic'"

Read-only; requires Host Groups:read. No membership changes are performed.
```
