# identity rule delete

identity rule delete <id> delete one Identity Protection policy rule

```text
npx -y @knowttl/falcon-axi identity rule delete <id> [--execute --confirm '<confirm>']

Use a rule identifier printed by identity rule list.
Default: local preview, no network request. The preview prints the exact confirm value.
Requires a file profile with writes.allowWrites=true and "identity-rule-delete" in writes.operations, even to preview.
Execution also needs --execute and the exact --confirm value; FALCON_AXI_READ_ONLY always forbids execution.
Sends one DELETE to /identity-protection/entities/policy-rules/v1 with the identifier as ids, never replayed.
A private redacted journal records the intent before sending and the outcome after; it is mandatory.
The identifier may contain only letters, digits, hyphens, and underscores.
Requires Identity Protection Policy Rules:write.
The command prints status, content type, and body. CrowdStrike publishes no success schema for this route.
Examples:
  npx -y @knowttl/falcon-axi identity rule delete synthetic-rule --profile ops
  npx -y @knowttl/falcon-axi identity rule delete synthetic-rule --profile ops --execute --confirm '<confirm>'
```
