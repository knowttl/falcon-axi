# file-change show

file-change show <id>         inspect one FileVantage change

```text
uvx falcon-axi file-change show <id>

Show change metadata, process fields and the documented diff object.
The id comes from change_ids in `uvx falcon-axi file-change list`.
Read-only; requires Falcon FileVantage:read and Falcon FileVantage licensing.
Captured file contents are excluded; no content download is performed.

Example: uvx falcon-axi file-change show 00000000000000000000000000000001
```
