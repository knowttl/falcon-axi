# search stop

search stop <id>          cancel one search job

```text
npx -y @knowttl/falcon-axi@next search stop <search id> [--repository <name>]

--repository the repository the job was started against (default search-all)

Cancels one search job npx -y @knowttl/falcon-axi@next started. It changes no tenant data, no host, and no
detection: the only thing it stops is the job.

Example: npx -y @knowttl/falcon-axi@next search stop abc123

This command requires NGSIEM:write.
```
