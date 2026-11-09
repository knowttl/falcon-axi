# raw get

raw get                   read one Falcon API path with the selected profile

```text
npx -y @knowttl/falcon-axi@next raw get --path <api-path> [--query <key=value&...>] [--query-file <file|->]

Sends one GET to the selected profile's Falcon cloud and prints the status, content type and body as TOON.
The path must be an absolute RFC 3986 path without dot segments, repeated slashes, query or fragment.
Use --query-file for secret query values; --query rejects secret-named keys. The file or stdin (-) must contain a JSON object of strings or string arrays.
One request per invocation, never replayed: no pagination, no continuation cursor, no field selection. Responses are capped at 4 MiB and binary bodies are refused.
Secret values are redacted and every field is kept, including the value beside a key that names a secret.
Examples:
  npx -y @knowttl/falcon-axi@next raw get --path /devices/queries/devices/v1 --query 'limit=5'
  npx -y @knowttl/falcon-axi@next raw get --path /detects/queries/detects/v1 --query 'filter=severity:>50&limit=2'
```
