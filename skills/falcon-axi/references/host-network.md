# host network

host network <device id>  IP and MAC address history for one host

```text
uvx falcon-axi host network <device id>

Retrieves the IP and MAC address history Falcon retains for one sensor host.
The device id is the AID printed by `uvx falcon-axi host list`.
Example: uvx falcon-axi host network abc123
Read-only; requires Hosts:read. This endpoint has no pagination parameters.
```
