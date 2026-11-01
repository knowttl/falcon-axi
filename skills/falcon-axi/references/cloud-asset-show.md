# cloud-asset show

cloud-asset show <id>         inspect one cloud-asset

```text
npx -y @knowttl/falcon-axi cloud-asset show <id>

The id is printed by `npx -y @knowttl/falcon-axi cloud-asset list`.
Shows resource identity and security context without raw configuration blobs.
Read-only; requires Cloud Security API Assets:read.

Example: npx -y @knowttl/falcon-axi cloud-asset show synthetic-cloud-asset-01
```
