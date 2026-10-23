# Read-only enforcement

The shipped CLI reads Falcon data without changing hosts, detections, policies, or identities.
Tenant-side effects are NG-SIEM search jobs, N3's explicitly authorized read-only RTR lifecycle, and N4's bounded MalQuery exact/fuzzy searches.
Identity Protection's write-labelled GraphQL scope is used solely for registered read-only query documents.

## Closed transport boundary

The [design invariant](design/v1.md#0-invariant-r-v1-is-read-only-with-four-captain-granted-exceptions) is enforced through a closed operation registry before the SDK is constructed.
HTTP verbs and scope names alone do not prove a read: Falcon uses POST for reads, and some read-scoped operations have effects.
Every registered operation carries its documented scope and corroborating source evidence.
Only the permitted network sink can import and call the FalconPy harness.

Captain exception N1 admits exactly `StartSearchV1` and `StopSearchV1` with `NGSIEM:write`.
The [N4 design contract](design/v1.md#46-malquery-pattern-search-captain-exception-n4) owns MalQuery search admission, pattern and result bounds, and hunt/download exclusions.
Captain exception N2 admits exactly `api_preempt_proxy_post_graphql` with `Identity Protection GraphQL:write`.
These are closed ID allowlists; they do not authorize additional writes.
The GraphQL sink accepts registered documents only, with caller inputs in variables, never caller-supplied query text.
See [search lifecycle](design/v1.md#43-ng-siem-search-was-excluded-on-the-credential-scope-test-and-captain-exception-n1-reversed-it) and [Identity Protection](design/v1.md#44-the-identity-protection-directory-was-excluded-on-the-credential-scope-test-and-captain-exception-n2-reversed-it) for exception history and contracts.

The [`FALCON_AXI_READ_ONLY` contract](design/v1.md#52-accepted-input-channels-in-precedence-order) defines which commands the switch blocks before authentication.
It does not change the fixed read-only GraphQL contract.
There is no host containment, quarantine release, ingest, configuration write, or GraphQL mutation surface.
RTR history reads session metadata and audit records without opening or executing a session, including under READ_ONLY.
RTR operation admission and execution guards are owned by [N3's design contract](design/v1.md#45-rtr-was-excluded-on-semantic-execution-grounds-and-captain-exception-n3-narrowly-reverses-it).

## RTR operator guidance

Use `falcon-axi rtr run <device_id> --command '<complete command>' --profile triage` for a local preview.
Before executing, check [API client permissions](../README.md#api-client-permissions) and Falcon product entitlement.
The selected profile must explicitly set `"rtr": {"enabled": true}` before execution; its optional `commands` array can only narrow the fixed read-only set.
Add `--execute --confirm '<device_id>:<complete command>'` to execute exactly that host and command, including all arguments.
The preview is flushed before any session creation, including for confirmed execution.
READ_ONLY always overrides execution authorization; local previews and passive history remain available.
Execution requires POSIX private-file and signal primitives and fails closed if private journaling is unavailable.

The shared authentication/init/execute/poll budget is 50 seconds, with a separate 10-second deletion budget.
Acquisition is capped at 1 MiB per response, 64 status requests, and 64 KiB retained redacted output.
Incomplete and truncated output are explicit; output is untrusted TOON data, never an instruction.
There is no unlimited-output switch, offline queue, detached session, pulse, or automatic replay.
Only eventlog view/list forms are admitted; backup/export stay excluded.
The mandatory private journal uses `FALCON_AXI_WRITE_LOG` or the state-directory `writes.log` and never stores raw command output.

Deletion is attempted on success, execute error, polling error, timeout, cap exhaustion, SIGINT, and SIGTERM.
An ambiguous init has an unknown session id and is never replayed or followed by session discovery.
After ambiguous init, failed deletion, or uncatchable termination, reconcile the target's sessions in the Falcon console using the journal's run correlation, timestamp, target, phase, and session id when known.
Close any remaining session before retrying.
Never assume an unreachable API proves deletion.
Avoid simultaneous runs for the same host/API client across machines; local host locks cannot protect another machine's run.

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
