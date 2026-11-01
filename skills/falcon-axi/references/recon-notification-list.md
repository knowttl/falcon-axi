# recon-notification list

recon-notification list       list Recon notifications

```text
npx -y @knowttl/falcon-axi@next recon-notification list [--filter <FQL>] [--limit N] [--cursor <token>]

list Recon notifications
--filter     raw FQL; + is AND, `,` is OR, values are single-quoted
--limit      rows in this call (default 20, ceiling 500)
--cursor     opaque continuation token; queries stop at 10000 results
Requires Monitoring rules (Falcon Intelligence Recon):read. Read-only.
Examples:
  npx -y @knowttl/falcon-axi@next recon-notification list --filter "status:'new'"
  npx -y @knowttl/falcon-axi@next recon-notification list --limit 100
```
