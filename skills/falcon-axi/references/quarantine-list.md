# quarantine list

quarantine list           list quarantined file metadata

```text
npx -y @knowttl/falcon-axi@next quarantine list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter     raw FQL (hostname, sha256, state, paths.path, paths.state)
--limit      rows in this call (default 20, ceiling 500)
--cursor     opaque continuation token from a previous call

Reads file metadata only. Requires Quarantined Files:read.
Examples:
  npx -y @knowttl/falcon-axi@next quarantine list
  npx -y @knowttl/falcon-axi@next quarantine list --filter "hostname:'SYNTHETIC-*'"
```
