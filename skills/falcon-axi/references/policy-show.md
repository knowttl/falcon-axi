# policy show

policy show <id>          device-control USB classes and exceptions

```text
npx -y @knowttl/falcon-axi@next policy show <id> --type device-control

--type  required: device-control (the only supported detail type)
Reads v2 USB settings, including enforcement mode, classes, actions, and exceptions.
Requires Device Control Policies:read and Falcon Device Control.
An empty result can mean not licensed or no data; no live-tenant validation is claimed.

Examples:
  npx -y @knowttl/falcon-axi@next policy show synthetic-policy-01 --type device-control
  npx -y @knowttl/falcon-axi@next policy list --type device-control
```
