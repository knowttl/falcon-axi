# ioc list

ioc list                  list custom indicators

```text
uvx falcon-axi ioc list [--filter <FQL>] [--limit N] [--cursor <token>]

--filter  FQL on type, value, action, source, severity_number, expired, created_on, modified_on
--limit   rows per call (default 20, ceiling 500)
--cursor  opaque continuation token

Examples:
  uvx falcon-axi ioc list --filter "type:'domain'+expired:false"
  uvx falcon-axi ioc list --limit 100

Read-only; requires IOC Management:read.
```
