# identity sensor aggregate

identity sensor aggregate aggregate Identity Protection sensors by a field

```text
npx -y @knowttl/falcon-axi identity sensor aggregate --name <name> --type <type> --field <field> [--filter <FQL>] [--size N]

--name       label for the aggregation, returned in the result
--type       aggregation type, sent to Falcon as given
--field      sensor field to aggregate
--filter     Falcon Query Language expression for identity sensors
--size       maximum number of buckets

Sends one POST to /identity-protection/aggregates/devices/GET/v1 and prints each result's name, buckets, and counts.
CrowdStrike's references publish the request fields but not the accepted type or field values; Falcon rejects an unsupported value.
This command is read-only and requires Identity Protection Entities:read.
```
