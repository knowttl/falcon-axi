# identity rule list

identity rule list        list Identity Protection policy rules

```text
uvx falcon-axi identity rule list [--name <name>] [--enabled true|false] [--simulation-mode true|false]

--name             filter by rule name
--enabled          filter by enablement status
--simulation-mode  filter by simulation mode

Queries all matching IDs and hydrates them in chunks of 100; this API has no pagination parameters.
Examples:
  uvx falcon-axi identity rule list
  uvx falcon-axi identity rule list --enabled true

Read-only. Requires Identity Protection Policy Rules:read; no GraphQL permission needed.
```
