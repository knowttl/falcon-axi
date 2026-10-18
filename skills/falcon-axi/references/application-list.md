# application list

application list          list Discover applications

```text
uvx falcon-axi application list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter     raw FQL on Discover application fields such as name, vendor, and host.hostname
             default name:'*' (all named applications)
--limit      rows in this call (default 20, ceiling 1000)
--cursor     opaque continuation token from a previous call

Examples:
  uvx falcon-axi application list --filter "name:'Chrome'"
  uvx falcon-axi application list --filter "vendor:'Microsoft Corporation'"

Read-only; requires Assets:read (Falcon Discover or Exposure Management).
```
