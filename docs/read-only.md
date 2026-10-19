# Read-only enforcement

falcon-axi reads Falcon data without changing hosts, detections, policies, or identities.
Starting and stopping NG-SIEM search jobs are its only tenant-side effects.
Identity Protection's write-labelled GraphQL scope is used solely for registered read-only query documents.

## Closed transport boundary

The [design invariant](design/v1.md#0-invariant-r-v1-is-read-only-with-two-captain-granted-exceptions) is enforced through a closed operation registry before the SDK is constructed.
HTTP verbs and scope names alone do not prove a read: Falcon uses POST for reads, and some read-scoped operations have effects.
Every registered operation carries its documented scope and corroborating source evidence.
Only the permitted network sink can import and call the FalconPy harness.

Captain exception N1 admits exactly `StartSearchV1` and `StopSearchV1` with `NGSIEM:write`.
Captain exception N2 admits exactly `api_preempt_proxy_post_graphql` with `Identity Protection GraphQL:write`.
These are closed ID allowlists; they do not authorize additional writes.
The GraphQL sink accepts registered documents only, with caller inputs in variables, never caller-supplied query text.
See [search lifecycle](design/v1.md#43-ng-siem-search-was-excluded-on-the-credential-scope-test-and-captain-exception-n1-reversed-it) and [Identity Protection](design/v1.md#44-the-identity-protection-directory-was-excluded-on-the-credential-scope-test-and-captain-exception-n2-reversed-it) for exception history and contracts.

`FALCON_AXI_READ_ONLY=1` blocks search start, stop, and identity activity.
It does not change the fixed read-only GraphQL contract.
There is no host containment, response session, quarantine release, ingest, configuration write, or GraphQL mutation surface.

## Sensitive output

Credentials and standalone CID fields are redacted on stdout and stderr.
Composite detection IDs retain their embedded tenant CID so callers can use them as detail identifiers.
Search event `cid` and `#repo.cid` fields are redacted.
See [redaction](design/v1.md#55-redaction) for the precise contract.

## Evidence and validation

Operations and response shapes follow CrowdStrike's official API reference, FalconPy, and the official [falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) source where available.
Where falcon-mcp lacks an area, registry entries identify the official API reference and FalconPy plus PSFalcon corroboration.
Per-operation citations live in `falcon_axi/transport/operations.py`; fixed query evidence lives in `falcon_axi/transport/graphql.py`.
The CLI does not depend on or run falcon-mcp.

Synthetic fixtures, golden invocations, and network-denied offline checks establish local behavior and transport constraints.
They do not establish live-tenant fidelity, product entitlement, or permission visibility in a particular console.
No tenant validation is claimed.
The [validation boundary](design/v1.md#15-safe-live-test-boundaries) records the source-parity policy and limits.
