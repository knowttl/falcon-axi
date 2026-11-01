# process tree

process tree <pid-id>     process, up to five ancestors, and one child level

```text
npx -y @knowttl/falcon-axi process tree <pid-id> [--cursor <token>] [--full]

Shows the process first, then up to 5 ancestors in parent order, then one child level.
Children use a fixed 100-edge page; --cursor continues children for the same process.
--full    complete command lines (default preview 800 characters)
--cursor  opaque child continuation token; lineage is read again on each page

Examples:
  npx -y @knowttl/falcon-axi process tree pid:synthetic-device:1234
  npx -y @knowttl/falcon-axi process tree pid:synthetic-device:1234 --full

Read-only; requires Threatgraph:read and a subscription with ThreatGraph API access.
Response shape source: CrowdStrike SDK sample falconpy samples/threat_graph/threat_finder.py,
not a resource schema in the API spec; source-matched and tested offline, not tenant-validated.
```
