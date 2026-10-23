# process show

process show <pid-id>     read one observed process

```text
uvx falcon-axi process show <pid-id> [--full]

ID shape: pid:<32 hex device ID>:<decimal ID>; use ioc processes to find it.
Returns command_line, device_id, file_name, process_id, process_id_local,
start_timestamp, start_timestamp_raw, stop_timestamp, and stop_timestamp_raw.
--full  expand the command line beyond its 800-character preview

Examples:
  uvx falcon-axi process show pid:00000000000000000000000000000001:1234
  uvx falcon-axi process show pid:00000000000000000000000000000001:1234 --full

Read-only; requires IOCs (Indicators of Compromise):read.
Availability depends on the tenant's subscription and API client permissions.
```
