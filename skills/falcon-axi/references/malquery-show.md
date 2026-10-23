# malquery show

malquery show <sha256>    indexed file metadata by SHA-256

```text
uvx falcon-axi malquery show <sha256>

sha256 must contain exactly 64 hex characters; validated before authentication.
Renders family, filesize, filetype, first_seen, label, md5, sha1, and sha256.
An empty result can mean no indexed file or missing Falcon MalQuery licensing.

Examples:
  uvx falcon-axi malquery show 0000000000000000000000000000000000000000000000000000000000000000
  uvx falcon-axi malquery quota

Read-only; requires MalQuery:read and Falcon MalQuery. No search or sample download.
```
