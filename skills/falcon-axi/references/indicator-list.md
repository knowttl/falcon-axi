# indicator list

indicator list            list Falcon Intelligence indicators

```text
uvx falcon-axi indicator list [--filter <FQL>] [--limit N] [--cursor <token>]

Lists Falcon Intelligence indicators, distinct from tenant custom IOCs.
--filter     raw FQL, for example type:'domain' or malicious_confidence:'high'
--limit      rows per call (default 20, ceiling 10000)
--cursor     opaque continuation token; keep the same filter and credential

Results use fixed marker order. Each page total describes the remaining query,
not a stable snapshot. Pagination uses the complete last marker internally.
Examples:
  uvx falcon-axi indicator list --filter "type:'domain'"
  uvx falcon-axi indicator list --limit 100

Read-only; requires Indicators (Falcon Intelligence):read and the corresponding license.
```
