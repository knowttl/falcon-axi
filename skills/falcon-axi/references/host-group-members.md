# host-group members

host-group members <id>     list host-group members

```text
npx -y @knowttl/falcon-axi@next host-group members <id> [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  FQL on host attributes: hostname, platform_name, status
--limit   rows per call (default 20, ceiling 5000)
--cursor  opaque continuation token

Examples:
  npx -y @knowttl/falcon-axi@next host-group members <id> --limit 100
  npx -y @knowttl/falcon-axi@next host-group members <id> --filter "platform_name:'Windows'"

Read-only; requires Host Groups:read. No membership changes are performed.
```
