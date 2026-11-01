# identity timeline

identity timeline <id>    one identity's recent activity

```text
npx -y @knowttl/falcon-axi@next identity timeline <identity id> [--since <window>] [--category <names>] [--limit N] [--cursor <token>]

--since      relative window such as 24h or 7d (default 7d)
--category   comma-separated, from activity, notification, threat, entity, audit, policy, system
--limit      rows in this call (default 20, ceiling 200)
--cursor     opaque continuation token from a previous call

Prints the identity's recent activity, newest first: authentications, service access, LDAP and
RPC activity, and alerts, each with its user, endpoint, and address.
Examples:
  npx -y @knowttl/falcon-axi@next identity timeline 00000000-0000-0000-0000-000000000001 --since 24h
  npx -y @knowttl/falcon-axi@next identity timeline 00000000-0000-0000-0000-000000000001 --category threat,audit

This command sends only a fixed read-only Identity Protection query. It requires Identity Protection
Timeline:read and Identity Protection GraphQL:write (captain exception N2).
```
