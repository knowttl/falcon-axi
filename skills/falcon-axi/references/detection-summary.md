# detection summary

detection summary         counts of detections by severity

```text
uvx falcon-axi detection summary [--severity <name>] [--status <name>] [--product <name>] [--since <window>] [--filter <FQL>]

--severity   one of informational, low, medium, high, critical
--status     one of new, in_progress, closed, reopened
--product    one of epp, idp, mobile, xdr, overwatch, cwpp, ngsiem, thirdparty, data-protection
--since      relative window such as 24h or 7d
--filter     raw FQL, combined with the shorthand filters as in detection list

Counts by severity across matching alerts, including hidden alerts, without listing them.
other_count, when present, counts alerts in buckets omitted by Falcon.
Examples:
  uvx falcon-axi detection summary --since 24h
  uvx falcon-axi detection summary --product idp --status new

This command is read-only and requires only Alerts:read.
```
