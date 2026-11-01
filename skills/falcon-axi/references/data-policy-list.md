# data-policy list

data-policy list          list Data Protection policies

```text
npx -y @knowttl/falcon-axi data-policy list --platform win|mac [--filter <FQL>] [--sort <field.direction>]
                            [--limit N] [--cursor <token>]

--platform  required: win or mac; sent as the API's platform_name
--filter    raw FQL; fields include name, is_enabled, precedence, created_at, modified_at
--sort      name, precedence, created_at or modified_at with .asc or .desc
--limit     rows in this call (default 20, ceiling 500)
--cursor    opaque continuation token from a previous call; maximum offset 10000

Examples:
  npx -y @knowttl/falcon-axi data-policy list --platform win --filter "is_enabled:true"
  npx -y @knowttl/falcon-axi data-policy list --platform mac --sort precedence.asc

Read-only. Requires Data Protection:read (license-gated).
```
