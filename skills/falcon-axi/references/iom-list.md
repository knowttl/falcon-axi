# iom list

iom list              list cloud Indicators of Misconfiguration

```text
npx -y @knowttl/falcon-axi iom list [--filter <FQL>] [--sort <field.direction>] [--limit N] [--cursor <token>]

list cloud Indicators of Misconfiguration.
--filter   raw FQL; + is AND, `,` is OR, values are single-quoted
--sort     upstream sort expression, for example cloud_provider.asc
--limit    rows in this call (default 20, ceiling 1000)
--cursor   opaque continuation token bound to the filter, sort, region and credential

Read-only; requires Cloud Security API Detections:read.

Examples:
  npx -y @knowttl/falcon-axi iom list --filter "severity:'critical'+status:'non-compliant'"
  npx -y @knowttl/falcon-axi iom list --limit 100
```
