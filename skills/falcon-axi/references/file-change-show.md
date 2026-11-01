# file-change show

file-change show <id>         inspect one FileVantage change

```text
npx -y @knowttl/falcon-axi@next file-change show <id>

Show change metadata, process fields and the documented diff object.
The id comes from change_ids in `npx -y @knowttl/falcon-axi@next file-change list`.
Read-only; requires Falcon FileVantage:read and Falcon FileVantage licensing.
Captured file contents are excluded; no content download is performed.

Example: npx -y @knowttl/falcon-axi@next file-change show 00000000000000000000000000000001
```
