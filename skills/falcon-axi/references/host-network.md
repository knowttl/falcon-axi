# host network

host network <device id>  IP and MAC address history for one host

```text
uvx falcon-axi host network <device id>
uvx falcon-axi host network --hostname <pattern>

Retrieves the IP and MAC address history Falcon retains for one sensor host.
The device id is the AID printed by `uvx falcon-axi host list`.
--hostname   match a hostname (wildcards allowed), instead of a device id; requires exactly one match
Example: uvx falcon-axi host network abc123
Example: uvx falcon-axi host network --hostname 'synthetic-host-*'
Hostname form: one lookup capped at 2 IDs, then one history read; 60s total deadline.
Ambiguous or incomplete lookups fail without reading history; upstream partial errors are disclosed.
Read-only; requires Hosts:read. This endpoint has no pagination parameters.
```
