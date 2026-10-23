# host usb

host usb <device id>      start a search for one host's USB activity

```text
uvx falcon-axi host usb <device id> [--since <window>]

The device id is the 32-character hexadecimal AID printed by `uvx falcon-axi host list`.
--since      relative window such as 24h or 7d (default 24h)

Starts a fixed NG-SIEM search in search-all for USB connections, disconnections, and policy
violations on one host, newest first, bounded to 200 events. Poll with `search status`.
An empty result can mean no USB events or no Device Control licence.
Event and field names come from CrowdStrike's community-content dashboard; not live-verified.

Examples:
  uvx falcon-axi host usb 00000000000000000000000000000001
  uvx falcon-axi host usb 00000000000000000000000000000001 --since 7d

This command starts a job on the tenant and requires NGSIEM:write (captain exception N1).
It changes no host, device, or policy. Polling requires NGSIEM:read.
```
