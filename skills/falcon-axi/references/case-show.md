# case show

case show <id>             read one record

```text
npx -y @knowttl/falcon-axi@next case show <id> [--full]

Use the opaque id from list output. Long text is truncated to 800 characters.
--full  return untruncated text
Read-only. Requires Cases:read.
Example: npx -y @knowttl/falcon-axi@next case show <id> --full
```
