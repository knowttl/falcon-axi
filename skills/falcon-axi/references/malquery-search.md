# malquery search

malquery search           bounded exact or fuzzy literal-pattern search (N4)

```text
uvx falcon-axi malquery search --string <ASCII> | --hex <bytes> [--fuzzy] [--limit N]

At least one pattern is required; combine --string and --hex to search for both.
--string: 1-4096 printable ASCII characters with nonblank content (API type ascii).
--hex: 1-4096 literal hex byte pairs, optional spaces; no wildcards or YARA.
--fuzzy: synchronous metadata rows, with possible false positives; default exact returns a request id.
--limit: maximum matches, default 20, CLI cap 100 (not a published API maximum).
No pagination, automatic polling, or replay; status uses `malquery status <id>`.

Examples:
  uvx falcon-axi malquery search --string SYNTHETIC-PATTERN --limit 20
  uvx falcon-axi malquery search --hex '4d 5a' --fuzzy --limit 10

Requires MalQuery:write and Falcon MalQuery under captain exception N4.
FALCON_AXI_READ_ONLY refuses searches. Hunt and all sample downloads remain excluded.
```
