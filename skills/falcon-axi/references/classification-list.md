# classification list

classification list       list Data Protection classifications

```text
uvx falcon-axi classification list [--filter <FQL>] [--sort <field.direction>] [--limit N] [--cursor <token>]

--filter  raw FQL; fields include name, created_at, modified_at, properties.protection_mode
--sort    name, created_at or modified_at with .asc or .desc
--limit   rows in this call (default 20, ceiling 500)
--cursor  opaque continuation token from a previous call; maximum offset 10000

Examples:
  uvx falcon-axi classification list --filter "name:'Confidential*'"
  uvx falcon-axi classification list --sort name.asc --limit 100

Read-only. Requires Data Protection:read (license-gated).
```
