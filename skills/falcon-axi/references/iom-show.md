# iom show

iom show <id>         inspect one iom

```text
npx -y @knowttl/falcon-axi iom show <id>

The id is printed by `npx -y @knowttl/falcon-axi iom list`.
Shows resource identity and security context without raw configuration blobs.
Read-only; requires Cloud Security API Detections:read.

Example: npx -y @knowttl/falcon-axi iom show synthetic-iom-01
```
