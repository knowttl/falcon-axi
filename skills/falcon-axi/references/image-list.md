# image list

image list                list container image assessments

```text
uvx falcon-axi image list [--filter <FQL>] [--limit N] [--cursor <token>]

Lists container image assessments in fixed image_id.asc order.
--filter     FQL fields include image_id, image_digest, registry, repository, tag
--limit      rows per call (default 20, ceiling 100)
--cursor     opaque continuation token; keep the same filter and credential
Falcon exposes at most 10000 records per query; narrow --filter at that boundary.
Examples:
  uvx falcon-axi image list --filter "repository:'example/service'"
  uvx falcon-axi image list --limit 100

Read-only; requires Falcon Container Image:read and the corresponding license.
```
