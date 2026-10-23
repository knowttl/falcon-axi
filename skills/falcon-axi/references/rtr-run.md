# rtr run

rtr run                   preview or execute one read-only RTR command on one host

```text
uvx falcon-axi rtr run <device_id> --command '<complete command>' [--execute --confirm '<device_id>:<complete command>']

Default: local preview, no network request. Requires one 32-hex device id.
Execution requires profile rtr.enabled=true and exact host:command confirmation.
FALCON_AXI_READ_ONLY always forbids execution; previews remain available.
50-second execution budget; separate 10-second mandatory session deletion budget.
Output caps: 64 KiB and 64 status requests; incomplete/truncated output is explicit.
A durable private redacted journal is mandatory; no offline queue, pulse, or replay.
Commands: cat, cd, clear, csrutil, env, eventlog view/list, filehash, getsid, help,
history, ifconfig, ipconfig, ls, mount, netstat, ps, reg query, users.
No shell syntax; eventlog backup/export, scripts, and file transfers are excluded.
Examples:
  uvx falcon-axi rtr run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --command ps --profile triage
  uvx falcon-axi rtr run aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --command ps --profile triage --execute --confirm 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:ps'
```
