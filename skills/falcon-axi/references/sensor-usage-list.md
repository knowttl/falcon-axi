# sensor-usage list

sensor-usage list         weekly sensor usage reports

```text
uvx falcon-axi sensor-usage list [--filter <FQL>]

Read weekly sensor usage reports. Requires Sensor Usage:read.
--filter     raw FQL; supported fields include event_date and period
Returns all weekly reports supplied by Falcon; no limit, cursor or entity detail endpoint.
Reports retain all metric categories so numeric zero values remain visible.
Examples:
  uvx falcon-axi sensor-usage list --filter "period:'30'"
  uvx falcon-axi sensor-usage list --filter "event_date:'2026-10-11'"
```
