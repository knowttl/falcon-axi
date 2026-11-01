# identity show

identity show <id>        one identity's risk, accounts, associations, and open incidents

```text
npx -y @knowttl/falcon-axi@next identity show <identity id> [--full]

--full       list every association; the default lists the first 25

The identity id is an entity GUID, as printed by `npx -y @knowttl/falcon-axi@next identity list`. For an Active Directory
user it may be the account object GUID, which is unverified (docs/design/v1.md section 17.15). Prints
risk, risk factors, accounts, associations, and open incidents.

Example: npx -y @knowttl/falcon-axi@next identity show 00000000-0000-0000-0000-000000000001

This command sends only a fixed read-only Identity Protection query. It requires Identity Protection
Entities:read and Identity Protection GraphQL:write (captain exception N2).
```
