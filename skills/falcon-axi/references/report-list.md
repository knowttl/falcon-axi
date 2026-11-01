# report list

report list               list Falcon Intelligence reports

```text
npx -y @knowttl/falcon-axi@next report list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter     raw FQL; + is AND, `,` is OR, values are single-quoted
--limit      rows in this call (default 20, ceiling 5000)
--cursor     opaque continuation token from a previous call

Default fields: id, name, created_date, last_modified_date.
Filterable fields include name, slug, target_countries, and target_industries.
Examples:
  npx -y @knowttl/falcon-axi@next report list
  npx -y @knowttl/falcon-axi@next report list --filter "name:'Synthetic*'"

This command is read-only and requires Reports (Falcon Intelligence):read (Falcon Intelligence subscription).
```
