# data-policy show

data-policy show <id>     full Data Protection policy

```text
npx -y @knowttl/falcon-axi@next data-policy show <id>

Shows the policy record, including policy_properties and classification references.
The get endpoint needs only the id, without a platform selector.
Example: npx -y @knowttl/falcon-axi@next data-policy show <id>
Read-only. Requires Data Protection:read (license-gated).
```
