# exclusion list

exclusion list            list ML, IOA, sensor-visibility, or certificate exclusions

```text
uvx falcon-axi exclusion list --type ml|ioa|sensor-visibility|certificate [--filter <FQL>] [--limit N] [--cursor <token>]

--type       required exclusion inventory
--filter     raw FQL; applied_globally and created_on work for all four types
             ml/sensor-visibility: value; ioa: pattern_id; certificate: name, modified_on
             value/name use : for exact matches and :* for substring globs
             unsupported fields may return zero matches without an error
--limit      rows in this call (default 20, ceiling 500; certificate ceiling 100)
--cursor     opaque continuation token from a previous call

Read-only. Requires IOA Exclusions:read, Sensor Visibility Exclusions:read, or
Machine Learning Exclusions:read for ml and certificate.
Examples:
  uvx falcon-axi exclusion list --type ml
  uvx falcon-axi exclusion list --type ioa --filter "pattern_id:'569'"
```
