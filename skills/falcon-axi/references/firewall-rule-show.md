# firewall rule show

firewall rule show <id>    read one record

```text
npx -y @knowttl/falcon-axi firewall rule show <id> [--full]

Use the opaque id from list output. Long text is truncated to 800 characters.
--full  return untruncated text
Read-only. Requires Firewall Management:read.
Example: npx -y @knowttl/falcon-axi firewall rule show <id> --full
```
