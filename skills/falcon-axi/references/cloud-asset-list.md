# cloud-asset list

cloud-asset list              list CSPM cloud assets

```text
uvx falcon-axi cloud-asset list [--filter <FQL>] [--sort <field.direction>] [--limit N] [--cursor <token>]

list CSPM cloud assets.
--filter   raw FQL; + is AND, `,` is OR, values are single-quoted
--sort     upstream sort expression, for example cloud_provider.asc
--limit    rows in this call (default 20, ceiling 1000)
--cursor   opaque continuation token bound to the filter, sort, region and credential

Read-only; requires Cloud Security API Assets:read.

Examples:
  uvx falcon-axi cloud-asset list --filter "cloud_provider:'aws'"
  uvx falcon-axi cloud-asset list --limit 100
```
