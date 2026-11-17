# identity rule create

identity rule create      create one Identity Protection policy rule

```text
npx -y @knowttl/falcon-axi identity rule create --body-file <file|-> [--execute --confirm '<confirm>']

Default: local preview, no network request. The preview prints the exact confirm value.
Requires a file profile with writes.allowWrites=true and "identity-rule-create" in writes.operations, even to preview.
Execution also needs --execute and the exact --confirm value; FALCON_AXI_READ_ONLY always forbids execution.
Sends one POST to /identity-protection/entities/policy-rules/v1, never replayed.
A private redacted journal records the intent before sending and the outcome after; it is mandatory.
The body is one JSON object of at most 1 MiB, from a file or stdin (-), without duplicate members.
Required fields are name, action, trigger, enabled, and simulationMode.
action is ADD_TO_WATCH_LIST, ALLOW, APPLY_SSO_POLICY, BLOCK, FORCE_PASSWORD_CHANGE, or MFA.
trigger is access, accountEvent, alert, or federatedAccess.
Optional activity, destination, sourceEndpoint, and sourceUser objects use the documented condition fields only.
Requires Identity Protection Policy Rules:write.
The command prints status, content type, and body. CrowdStrike publishes no success schema for this route.
Examples:
  npx -y @knowttl/falcon-axi identity rule create --body-file rule.json --profile ops
  npx -y @knowttl/falcon-axi identity rule create --body-file rule.json --profile ops --execute --confirm '<confirm>'
```
