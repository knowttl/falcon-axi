# container list

container list            list Kubernetes containers

```text
npx -y @knowttl/falcon-axi@next container list [--filter <FQL>] [--limit N] [--cursor <token>]

Lists Kubernetes containers in fixed container_name.asc order.
--filter     FQL fields include container_id, cluster_name, namespace, running_status
--limit      rows per call (default 20, ceiling 200)
--cursor     opaque continuation token; keep the same filter and credential
Falcon exposes at most 10000 records per query; narrow --filter at that boundary.
Examples:
  npx -y @knowttl/falcon-axi@next container list --filter "namespace:'production'"
  npx -y @knowttl/falcon-axi@next container list --limit 100

Read-only; requires Falcon Container Image:read and the corresponding license.
```
