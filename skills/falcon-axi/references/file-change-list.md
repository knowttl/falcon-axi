# file-change list

file-change list              list FileVantage change history

```text
uvx falcon-axi file-change list [--filter <FQL>] [--limit N] [--cursor <token>]

Read FileVantage change history, newest action_timestamp first.
--filter   raw FQL; for example host.name:'SYNTHETIC-HOST' or action_timestamp:>'now-7d'
--limit    rows per call (default 20, ceiling 5000); hydration uses batches of 500 ids
--cursor   opaque after token bound to the query, sort, region, tenant and credential
change_ids lists identifiers in the same order as the compact rows.
Read-only; requires Falcon FileVantage:read and Falcon FileVantage licensing.
Empty results can mean no matching changes or no FileVantage license.
Captured file contents are excluded.

Example: uvx falcon-axi file-change list --filter "host.name:'SYNTHETIC-HOST'"
```
