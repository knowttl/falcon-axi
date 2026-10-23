# malquery status

malquery status <id>      exact-search request status and bounded metadata results

```text
uvx falcon-axi malquery status <id> [--limit N]

id: UUID returned by exact search; reads once, with no automatic polling.
--limit: maximum displayed rows, default 20, CLI cap 100; no upstream pagination parameter.
Renders request status and sha256, family, filetype, filesize; a capped result is marked partial.

Examples:
  uvx falcon-axi malquery status 00000000-0000-4000-8000-000000000001
  uvx falcon-axi malquery status 00000000-0000-4000-8000-000000000001 --limit 100

Read-only; requires MalQuery:read and Falcon MalQuery. No hunt or download is started.
```
