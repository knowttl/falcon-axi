# TypeScript S02-S11 candidate

The [approved settlement amendment](s01-primitive-amendment.md#dns-deadline-settlement) owns the DNS resolver and process settlement contract.
The installed-artifact regression uses a three-second local DNS blackhole and requires WAIT_TIMEOUT and process settlement within the inherited one-second budget plus startup allowance.

The migration branch preserves the released Python implementation while evaluating a Node 24 TypeScript replacement.
The private npm candidate is `@knowttl/falcon-axi@0.0.0-s02.0` with the executable name `falcon-axi`.
The candidate delivers local configuration diagnostics, token-checking `auth status`, `scopes`, and passive detection investigation and host, IOC, process, FileVantage and RTR history reads.
S04 adds account, asset, application, login, host-group, IoT, weekly sensor usage and Identity sensor reads.
S05 adds Spotlight vulnerabilities, CVE intelligence, cloud assets and misconfigurations, aggregated cloud risks, containers, images, serverless SARIF and Shield checks.
S06 adds actors, reports and JSON MITRE mappings, marker-paginated intelligence indicators, malware families, Recon rules/notifications/exposed-data records, and existing sandbox report summaries.
S07 adds all six policy inventories and their members, Device Control detail, identity policy rules, firewall/IOA/correlation rules, cases, four exclusion types, quarantine metadata, classifications and Data Protection policies.
S08 adds search start/status/stop, fixed identity activity and host USB searches.
S09 adds the six canonical Identity Protection GraphQL documents behind identity list/show/timeline/assessment.
S10 adds bounded literal MalQuery exact/fuzzy searches and passive metadata/status/quota reads.
Creation is sent at most once for every NG-SIEM creation command, with or without a wait.
This approved replay correction differs from the Python origin's generic response retry loop: 429, retryable 5xx, lost responses, and missing job identifiers never trigger another creation send.
An unknown job identifier leaves the creation outcome unknown; it does not prove that no job exists.
OAuth, passive status, and search stop retain their separate three-attempt response policies.
MalQuery submissions likewise never replay.
READ_ONLY refuses lifecycle changes and MalQuery submissions before authentication, while passive status and fixed GraphQL reads remain available.
Search waits include authentication, creation, polling, response acquisition and retry delays under one invocation deadline.
Expiry before a job identifier is known reports WAIT_TIMEOUT; expiry after it is known returns the recoverable running job and repository-aware suggestions.
GraphQL text comes only from the frozen canonical documents; variables travel separately and both GraphQL and MalQuery bodies are checked again by the network sink.
Relay cursors bind identity filters, credentials, region and tenant; timeline cursors also retain their original window start.
Policy and exclusion scopes are selected by the required type selector.
Sandbox lookup requires exactly one hash or FQL selector and projects only report metadata; it admits no submissions or downloads.
Recon entity reads and Device Control details accept their documented direct arrays as well as resources envelopes.
Firewall continuation prefers a server token over numeric offsets, while intelligence indicators retain the entire advancing marker.
These slices preserve the Python projections, scope distinctions and signed continuation contexts.
Among S04/S05 inventories, Discover assets/applications/IoT and Spotlight use opaque `after` values, cloud assets use `meta.next`, and the remaining inventories use offsets.
Account offsets remain unbounded; container/image inventory caps its window at 10000 records, while SARIF advances by source-record budget rather than run count.
`src/metadata.ts` owns the delivered TypeScript command and flag surface.
The released Python implementation remains present as the frozen comparison and rollback origin.
The earlier representative `search status synthetic-job --wait 1` budget probe now uses the delivered lifecycle and retains its shared authentication deadline.
The remaining Python command surface remains the behaviour origin for later slices.
No npm publication, Python release change, workflow edit or host deployment is included.

## Build and offline verification

Development pins Node 24.14.0, npm 11.9.0 and exact locked dependencies.
The runtime floor is Node 24.11.0; native Windows controller refusal, preview and reads, and other Node versions remain unproved in this slice.
Run `npm ci --offline --ignore-scripts` and `npm run verify`.
The latter repeats the S10 native carrier, the native S11 lifecycle, compiled filesystem primitives, and frozen safety ownership checks.
The S06/S07 carrier repeats the S01-S05 native checks and adds enrichment/configuration golden parity, selector-specific scope and malformed-response refusals, continuation replay, ordered batch hydration, and redaction before detail previews.
Native S06/S07 retained scenarios compare exact output bytes and exit codes, including signed cursors and suggestions.
S06 restores the original detection-process sandbox suggestions, and S07 restores Identity rule navigation in the existing discovery scenarios.
Managed comparisons retain data and exits while the host owns command prefixes and connection-specific cursor encodings.
The frozen slice contracts in `tests/fixtures/migration/S02/contracts.json` through `S11/contracts.json` retain the owned operation, case, command and golden scenario identities.
`tests/migration/coverage-s06-s07.json` retains source identities and parameter selections for the additional safety groups.
`tests/migration/coverage-s08-s10.json` adds search, GraphQL and MalQuery ownership with executable replacement bindings.
The S08-S10 carrier repeats the earlier suites and adds retained output comparisons, CQL vectors from the Python origin, non-replay response/failure matrices, bounded waits, shell continuation and authority-boundary refusals.
The GraphQL parser is a development dependency used to verify the fixed documents' operation, root and variable contracts; it is excluded from the runtime package.
The response-diagnostic replacements exercise bounded shapes at the candidate's validation boundary; Python validator-library issue annotations have no runtime producer in the hand-validated candidate.
The installed check packs an explicit compiled-source allowlist, installs outside the checkout and executes the npm bin from a directory containing spaces.
Linux user/network/mount namespaces and iproute2 are required for that check.
Only loopback is enabled; an actual external connect is required to fail with ENETUNREACH.
Synthetic TLS delivery is injected only by the unpackaged test launcher after production origin and operation checks.
The CLI contains no fake-origin flag, config field, environment selector or recorded transport.
The separate compiled primitive gate also requires `cc` to build its test-only network-denial launcher and fault-injection library.

The optional hosted path requires a separately built frozen local Artium fixture containing the reviewed S01 host delta.
Set `S01_ARTIUM_ROOT` to that fixture and run `npm run check:slice -- --slice S10 --paths native,artium --offline`.
Missing fixtures and unknown or empty selections fail.
The host delta launches the candidate with its Node runtime rather than either Python launch condition, retaining Node heap limits and the existing termination grace.
The real client, server, public credential API, private profile writer and runner execute the same installed artifact.
The configured no-mistakes test deliberately requires only the native offline path.
Final hosted evidence is bound separately to the frozen fixture and final candidate revision.

## Authority and output

The registry retains all 114 canonical operation tuples and their official scope and corroboration citations.
A pinned canonical digest, own-key checks and recursive freezing seal the registry before networking.
This carrier enables the 110 operations owned by S03-S10 after method, registry and body validation.
ThreatGraph summaries always use the fixed `processes` path component.
RTR session metadata and audit reads cannot reach session initialization, command execution, status polling or deletion.
S11 separately admits its four guarded RTR operations through one-use sink grants.
OAuth has its own fixed POST/form route and no persistent token cache.
Only the private HTTPS sink accepts invocation-local frozen request permits.
Lexical origin checks precede URL normalization, so explicit ports, dot segments, userinfo and other unsafe syntax cannot disappear before validation.
No redirect Location is followed.
One verified-region re-mint is separate from each mint's three-attempt response policy.
Transport exceptions are terminal, and acquisition includes response bytes within a 30-second total cap.
Response buffers are capped at 16 MiB for this read path.
Signals and inherited token budgets cancel acquisition and retry waits.
Proxy configuration uses FALCON_AXI_PROXY_URL and CONNECT, preserving target TLS verification.

The public TOON encoder is pinned to 4.1.1 and the public AXI fast-version subpath to 0.1.13.
Falcon retains raw lines, omission and always-quoted help entries at its rendering boundary.
Response JSON integer lexemes beyond Number's exact domain become bigint before rounding can occur.
The encoder emits those values as exact quoted decimal strings, its documented lossless representation.
Other numeric lexemes beyond that domain retain their exact decimal or exponent text as strings.
IDs remain strings, and truncation counts Unicode scalar values.
The [S02/S03 verification amendment](s02-s03-plan-amendment.md) owns the deferred test assignments and temporary discovery differences, including their restoration requirements.
Subcommand help is seeded from the frozen Python origin in `src/help.json` and `src/search-help.json`.
Errors use the Python origin's top-level error and code fields rather than S01's nested envelope.
Opaque cursors retain the origin's signed context and exact serialization.
No existing Python golden document is rewritten.

## Native primitive proof

The [approved S01 amendment](s01-primitive-amendment.md) owns the deferred primitive proof, required native-addon guarantees, and remaining STOP gates.
The original negative probe reproduced an append reaching a replacement ancestor despite path-based O_NOFOLLOW.
`npm run probe:primitive -- --slice S01 --paths native --offline` now exercises the compiled adapter and must pass as part of `npm run verify`.
This proves primitives, not the S11 lifecycle or full AC-RTR-FS acceptance.
The approved DNS settlement boundary remains unchanged.

`native/rtr_fs.c` is the single native dependency, implemented directly in C with N-API 8 and no third-party native library.
`src/rtr-filesystem.ts` loads it only when opening an execution journal or lock, verifies its SHA-256, and rejects unsupported controllers before loading any binary.
Current prebuilds target Linux x64 with glibc 2.33 or newer and Windows x64.
The Windows prebuild has no POSIX entry points; controller execution refuses while ordinary reads remain independent of native loading.
S11 preview does not load the native adapter.

The adapter exposes open, append and close over opaque retained handles.
It traverses absolute paths using openat with O_NOFOLLOW and directory descriptors, retaining the Python origin's ownership, sticky-ancestor, permission, regular-file and single-link policy.
Missing directories are created privately and their parent is flushed.
Files are opened append-only and nonblocking with close-on-exec descriptors.
Lock handles take nonblocking flock on the retained inode, stay empty and are never unlinked.
Journal appends recheck the retained file, finish short writes, retry EINTR, and flush the file and directory before returning success.
An unsuccessful write or flush poisons that handle and reports CONFIG_INSECURE without replaying the record.
Close releases descriptors deterministically; garbage collection is only a fallback.
S11 owns serialization, redaction, bounded records and lifecycle authority.

## Guarded RTR candidate

`rtr run` restores local preview and the N3 execution surface without changing its four canonical operation descriptors.
The selected file profile must opt in, and exact host/command confirmation remains mandatory.
The state-local retained lock is acquired before authentication and held through final journaling.
The journal durably records intent, cleanup-unknown before init, and the returned session before either derived listing or selected execution.
Opaque invocation-local grants are consumed at the HTTPS sink and bind method, route, token and serialized body.
Only this lifecycle can mint grants; passive request entry points continue to refuse these operations.
Every lifecycle request is sent once, with a 1 MiB acquisition cap, 64 shared status requests and 64 KiB retained output.
The shared authentication/execution budget is 50 seconds; known-session deletion has its own 10-second budget and ignores repeated catchable interrupts.
Unknown init outcomes require manual reconciliation; a failed final journal write preserves command and deletion outcomes while failing the invocation.
The command grammar and conservative same-session `cat` size comparison retain the Python origin's behavior.
Discovery and scope output deliberately gain `rtr run`; the Python goldens remain unchanged.
Top-level help restores the retained N3 authorization sentence alongside the delivered search and MalQuery guidance.
Unsupported controllers refuse execution before authentication while preview stays local.
The S11 installed checks preserve real filesystem ownership under the inherited process-level socket deny and deliver synthetic HTTPS over a test-owned Unix socket.
`tests/migration/coverage-s11.json` pins the twelve retained safety groups and their public source symbols.
`npm run check:slice -- --slice S11 --paths native --offline` requires no host fixture.
The additional `native,artium` path requires a frozen local fixture containing the reviewed host delta.
The hosted fixture applies the same socket-deny launcher to the actual Falcon child while its public API remains on loopback.
Its stable host-owned lock is keyed only by the normalized device ID, spans isolated call directories and users, and remains held through final journaling and process-group settlement.
Region retargeting, tenant selection, profile identity and client identity cannot partition that lock.
The hosted disconnect check measures the separate ten-second cleanup inside the unchanged twelve-second termination grace and verifies retained recovery evidence and released custody.
The host delta remains a separate local review artifact and does not authorize deployment.
Redaction also covers unfinished PEM material when bounded acquisition ends before its closing marker.

Both prebuilds ship inside the package with checksums; no install script, compiler download or runtime compilation is used.
`npm run build:native` is a maintainer-only rebuild using pinned GCC versions and SHA-256-pinned Node 24.14.0 headers.
`native/provenance.json` records compiler flags, header pins and input hashes.
Ordinary builds check those input and binary hashes without a compiler.
The compiled-interface probe uses an inherited Linux seccomp IP socket deny, preserving actual filesystem ownership rather than remapping root ownership in a user namespace.
It proves the deny in IPv4/IPv6 child processes, retained-ancestor writes, unsafe-target and ancestor refusals, cross-process lock contention and release, and injected short-write, EINTR and file/directory fsync outcomes.
An outside-source install proves compiled appends, binary-integrity refusal, and read/help plus Windows controller refusal with the binaries removed.
Neither fs-ext nor fs-native-extensions was adopted.
