# policy members

policy members <id>       list hosts assigned to a policy

```text
uvx falcon-axi policy members <id> --type <type> [--filter <FQL>] [--limit N] [--cursor <token>]

--type       required: prevention|sensor-update|firewall|device-control|response|content-update
--filter     raw FQL; + is AND, `,` is OR, values are single-quoted
--limit      rows in this call (default 20, ceiling 5000)
--cursor     opaque continuation token from a previous call

Reads policy inventory or assigned host details, without changing policies or precedence.
Requires the selected policy type's read scope; run `uvx falcon-axi scopes` for the matrix.
Device-control inventory uses the combined v1 schema, without v2 settings.
Examples:
  uvx falcon-axi policy list --type prevention --filter "enabled:true"
  uvx falcon-axi policy members <id> --type sensor-update
```
