# raw write

raw write                 preview or send one guarded Falcon API write

```text
npx -y @knowttl/falcon-axi raw write --method POST|PUT|PATCH|DELETE --path <api-path> [--query <key=value&...>] [--query-file <file|->] [--body-file <file|->] [--execute --confirm '<confirm>']

Default: local preview, no network request. The preview prints the exact confirm value.
Requires a file profile with writes.allowWrites=true and "raw-write" in writes.operations, even to preview.
Execution also needs --execute and the exact --confirm value; FALCON_AXI_READ_ONLY always forbids execution.
One request, never replayed. A private redacted journal records the intent before sending and the outcome after; it is mandatory.
Use --query-file for secret query values; --query rejects secret-named keys. The file or stdin (-) must contain a JSON object of strings or string arrays.
The body is one JSON object or array of at most 1 MiB, from a file or stdin (-), without duplicate members at any depth. Query and body cannot both read stdin.
The same path syntax rules as raw get apply. Falcon authorizes the selected route.
Raw writes read no target state and detect no no-ops; reconcile an unknown outcome in the Falcon console before retrying.
Examples:
  npx -y @knowttl/falcon-axi raw write --method PATCH --path /example/entities/thing/v1 --body-file body.json --profile ops
  npx -y @knowttl/falcon-axi raw write --method PATCH --path /example/entities/thing/v1 --body-file body.json --profile ops --execute --confirm '<confirm>'
```
