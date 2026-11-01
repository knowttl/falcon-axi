# asset show

asset show <id>           details for one Discover asset

```text
npx -y @knowttl/falcon-axi@next asset show <id>

Shows one Discover asset's platform, sensor association, network addresses, and observation times.
Use the Discover id from asset list, which is distinct from a Falcon device id.
Example: npx -y @knowttl/falcon-axi@next asset show synthetic-asset-01
Read-only; requires Assets:read (Falcon Discover or Exposure Management).
```
