# host show

host show <device id>     the full detail for one host

```text
npx -y @knowttl/falcon-axi host show <device id>

The device id is the agent id Falcon calls the AID, as printed by `npx -y @knowttl/falcon-axi host list`.

Example: npx -y @knowttl/falcon-axi host show abc123

This command is read-only and requires only Hosts:read.
```
