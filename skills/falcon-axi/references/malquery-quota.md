# malquery quota

malquery quota            MalQuery quota counters and refresh time

```text
npx -y @knowttl/falcon-axi malquery quota

Renders download, hunt, and monitor counts and limits, days_left, and refresh_time.
Includes the documented download_counts and hunt_counts arrays; absent fields are unknown.

Examples:
  npx -y @knowttl/falcon-axi malquery quota
  npx -y @knowttl/falcon-axi malquery show 0000000000000000000000000000000000000000000000000000000000000000

Read-only; requires MalQuery:read and Falcon MalQuery. Does not consume search or download quota.
```
