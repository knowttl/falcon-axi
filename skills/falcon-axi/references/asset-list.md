# asset list

asset list                list Discover managed and unmanaged assets

```text
uvx falcon-axi asset list [--filter <FQL>] [--limit N] [--cursor <token>]

Lists Discover managed and unmanaged assets, distinct from Falcon sensor hosts.
--filter     raw FQL, including entity_type, hostname, platform_name, and criticality
             default id:'*' (all Discover assets)
--limit      rows in this call (default 20, ceiling 1000)
--cursor     opaque continuation token from a previous call

Examples:
  uvx falcon-axi asset list --filter "entity_type:'managed'"
  uvx falcon-axi asset list --filter "entity_type:'unmanaged'"

Read-only; requires Assets:read (Falcon Discover or Exposure Management).
```
