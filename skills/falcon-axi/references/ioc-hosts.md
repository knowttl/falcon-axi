# ioc hosts

ioc hosts <type:value>  list observed hosts for a custom IOC

```text
uvx falcon-axi ioc hosts <type:value> [--limit N] [--cursor <token>]

Types: domain, ipv4, ipv6, md5, sha256. IPv6 values retain their colons.
--limit   identifiers per call (default 20, ceiling 100)
--cursor  opaque continuation token

Returns observed identifiers; no process details or actions are requested.
Example: uvx falcon-axi ioc hosts domain:example.invalid
Read-only; requires IOCs (Indicators of Compromise):read.
```
