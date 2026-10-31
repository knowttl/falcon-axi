# search start

search start              start an NG-SIEM CQL search job

```text
uvx falcon-axi search start --query <CQL> [--repository <name>] [--since <window>] [--wait <seconds>]

--query      the CQL search to run; required
--repository repository or view to search (default search-all)
--since      window to search, such as 24h or 7d (default 24h)
--wait       poll for completion for 1-50 seconds (default: return the job id immediately)

CQL is pipe-based and is neither FQL nor SQL: a filter, then commands.
Start from a tag or field filter and pipe into commands, and bound the result set in the
query itself with `| head(N)` or an aggregate; there is no --limit and no --cursor.
Examples:
  uvx falcon-axi search start --query '#event_simpleName=ProcessRollup2 | head(5)' --wait 30
  uvx falcon-axi search start --query '#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count())' --since 7d

This command starts a job on the tenant and requires NGSIEM:write.
Using --wait also requires NGSIEM:read to poll status.
When --wait expires after start, it returns state: running and the job id successfully.
Poll it with `uvx falcon-axi search status <id> --wait 30`; the job keeps running.
For readable epoch-millisecond @timestamp values, append this CQL stage:
| formatTime("%Y-%m-%dT%H:%M:%SZ", field=@timestamp, as=time, timezone="UTC")
```
