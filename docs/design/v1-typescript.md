# TypeScript implementation

The [approved settlement amendment](s01-primitive-amendment.md#dns-deadline-settlement) owns the DNS resolver and process settlement contract.
The installed-artifact regression uses a three-second local DNS blackhole and requires WAIT_TIMEOUT and process settlement within the inherited one-second budget plus startup allowance.

This tree prepares the reviewed Node 24 TypeScript cutover; the Python implementation is preserved in release history rather than shipped alongside it.
The package provides the `falcon-axi` and `falcon-axi-hook` executables.
`1.0.0-rc.1` was published manually; later releases publish from `.github/workflows/release-please.yml`, with prereleases on `next` and stable releases on `latest`.
The release configuration targets `1.0.0`; remove its `release-as` override after that release is cut.
The [cutover record](../distribution/typescript-cutover.md) owns the imported migration tree, preservation tag, reviewable revert, and publication gates.
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
Frozen Python test sources remain as non-executable provenance for the safety ledger; release history and retained artifacts own Python rollback.
The earlier representative `search status synthetic-job --wait 1` budget probe now uses the delivered lifecycle and retains its shared authentication deadline.
The complete Python command surface remains the behaviour origin for parity and rollback.
The cutover replaces CI verification with the Node offline gate and disables release automation; no npm publication, PyPI release change, or host deployment is included.

## Build and offline verification

Development uses pnpm, pinned by `packageManager` and provided through Corepack, with exact locked dependencies in `pnpm-lock.yaml`.
Node 25 and later do not bundle Corepack, so install it first with `npm install --global corepack`.
The runtime and development floor is Node 22.18.0 with no upper bound, the first Node 22 release that runs the TypeScript build scripts without a flag; native Windows evidence remains pending.
Run `corepack pnpm install --frozen-lockfile --ignore-scripts --config.confirm-modules-purge=false` and `corepack pnpm run verify`.
The pipeline wraps both in `scripts/isolated-home.mjs`, which gives each run an empty throwaway home directory and removes `FALCON_AXI_*` variables.
The verification command runs the cumulative S13 native gate, including the S10 carrier, S11 lifecycle, compiled filesystem primitives, S12 installation and hook checks, generated freshness, all 350 goldens, and reconciliation of all 210 retained safety groups.
It also runs a standalone package-contract check after building: the packed allowlist must contain the bin, admission metadata, parser, credential schema, README, license and native prebuilds, without tests, source maps, local paths or recognizable secret material.
The check unpacks the tarball outside the checkout, copies its declared dependencies and their dependency closure from the checkout's pnpm installation, probes the installed bin with `--help` and `--version`, and imports the admission metadata and CLI entry point under the inherited kernel IP socket deny.
Run `node .typescript-build/scripts/typescript/package-contract.js` after `corepack pnpm run build` for a focused check; it needs no hosted fixture and requires Linux seccomp support and `/usr/bin/gcc` to compile the socket-denial launcher.
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

The optional hosted path requires a separately built frozen local Artium fixture containing the candidate's host delta.
Set `S01_ARTIUM_ROOT` to that fixture and run `corepack pnpm run check:slice --slice S13 --paths native,artium --offline`.
Missing fixtures and unknown or empty selections fail.
The host delta launches the candidate with its Node runtime rather than either Python launch condition, retaining Node heap limits and the existing termination grace.
The real client, server, public credential API, private profile writer and runner execute the same installed artifact.
The configured no-mistakes test deliberately requires only the native offline path.
Slices merge on their repository gate, including the package-contract and network-denial checks; hosted Artium proof runs once per release or in one nightly batch rather than per slice.
Final hosted evidence is bound separately to the frozen fixture and final candidate revision.
Artium hosted proof and the package switch fold once per release candidate rather than per slice.
The recorded source-only `artium-delta` is held for the next release-candidate fold; this carrier makes no hosted acceptance claim.

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
Response JSON numeric preservation compares the original lexeme's exact magnitude against `9007199254740991`, without using the rounded Number supplied by `JSON.parse`.
Integer lexemes beyond that boundary become bigint.
The encoder emits those values as exact quoted decimal strings, its documented lossless representation.
Decimal and exponent lexemes beyond that boundary retain their exact source text as strings, including their sign.
Values at or within the boundary remain numbers with normal Number rounding, including decimal and exponent forms of the boundary itself.
IDs remain strings, and truncation counts Unicode scalar values.
The [S02/S03 verification amendment](s02-s03-plan-amendment.md) owns the deferred test assignments and temporary discovery differences, including their restoration requirements.
Subcommand help is seeded from the frozen Python origin in `src/help.json` and `src/search-help.json`.
Errors use the Python origin's top-level error and code fields rather than S01's nested envelope.
Opaque cursors retain the origin's signed context and exact serialization.
S12/S13 retain the original golden output contract without a scope-label change.

## Native primitive proof

The [approved S01 amendment](s01-primitive-amendment.md) owns the deferred primitive proof, required native-addon guarantees, and remaining STOP gates.
The original negative probe reproduced an append reaching a replacement ancestor despite path-based O_NOFOLLOW.
`corepack pnpm run probe:primitive --slice S01 --paths native --offline` now exercises the compiled adapter and must pass as part of `corepack pnpm run verify`.
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

`corepack pnpm run check:slice --slice S11 --paths native --offline` requires no host fixture.
The additional `native,artium` path requires a frozen local fixture containing the reviewed host delta.
The hosted fixture applies the same socket-deny launcher to the actual Falcon child while its public API remains on loopback.
Its stable host-owned lock is keyed only by the normalized device ID, spans isolated call directories and users, and remains held through final journaling and process-group settlement.
Region retargeting, tenant selection, profile identity and client identity cannot partition that lock.
The hosted disconnect check measures the separate ten-second cleanup inside the unchanged twelve-second termination grace and verifies retained recovery evidence and released custody.
The host delta remains a separate local review artifact and does not authorize deployment.
Redaction also covers unfinished PEM material when bounded acquisition ends before its closing marker.

Both prebuilds ship inside the package with checksums; no install script, compiler download or runtime compilation is used.
`corepack pnpm run build:native` is a maintainer-only rebuild using pinned GCC versions and SHA-256-pinned Node 24.14.0 headers.
`native/provenance.json` records compiler flags, header pins and input hashes.
Ordinary builds check those input and binary hashes without a compiler.
The compiled-interface probe uses an inherited Linux seccomp IP socket deny, preserving actual filesystem ownership rather than remapping root ownership in a user namespace.
It proves the deny in IPv4/IPv6 child processes, retained-ancestor writes, unsafe-target and ancestor refusals, cross-process lock contention and release, and injected short-write, EINTR and file/directory fsync outcomes.
An outside-source install proves compiled appends, binary-integrity refusal, and read/help plus Windows controller refusal with the binaries removed.
Neither fs-ext nor fs-native-extensions was adopted.

## Raw API

`src/raw.ts` implements `raw get` and `raw write` (captain exception N5, `v1.md` §4.7) outside the operation registry.
`src/transport/raw-authority.ts` owns the route syntax rules and the 4 MiB response ceiling; the HTTPS sink revalidates the route for every raw request.
Any syntactically valid Falcon path is available for GET or gated writes, subject to Falcon authorization.
A non-GET raw request is accepted only with a single-use grant minted in `src/raw.ts` after the profile, confirmation and journal gates, bound to origin, method, path with query, and body; read-only mode is checked again at consumption.
Raw writes are never replayed and reuse the RTR journal adapter, so execution needs Linux x64; previews stay local.
Query input and secret restrictions are specified in `v1.md` §4.7.
Successful bodies are parsed as JSON when possible, redacted with the shared redactor, and encoded as TOON; non-JSON text is printed as a redacted string and binary bodies are refused.
Upstream failures keep their status and redacted body under `upstream_status` and `upstream_body`.
`tests/typescript/raw.test.ts` covers the gates, the journal, the route rules and the redaction extension.

## Installation and full parity candidate

S12 adds the separate `falcon-axi-hook` npm executable and the offline `setup` and `setup hooks` commands.
The hook resolves local credentials and trusted region information, prints one safe line, and exits successfully without authentication or network access.
Explicit setup preserves the four existing agent configuration targets, owned-entry repair, malformed-file refusal, comments, and unchanged bytes and modification times on repeat installation.
[v1.md §12.2](v1.md#122-session-hook-and-skill) owns session integration executable paths and repair requirements.
Ordinary commands do not install integrations, capture transcripts, or update software.
Build and pack with `corepack pnpm run build` and `npm pack --pack-destination <directory>`.
Install that tarball into a durable prefix with `npm install --ignore-scripts --prefix <prefix> <tarball>`.
Run either executable from `<prefix>/node_modules/.bin`, or use the installed Node runtime with its compiled entry point on Windows.
The generated skill's `npx -y @knowttl/falcon-axi` examples use the `latest` channel; until stable publication, substitute the executable from this installed tarball.

S13 restores complete discovery comparisons against the retained command references and all 350 golden scenarios, removing temporary discovery filtering.
The `scopes` posture, scope rows, provisioning guidance, and exit code retain exact origin parity, including all four original exception labels and guarded RTR host execution disclosure.
All golden comparisons retain the existing release-version substitutions and byte-for-byte output contract.
The post-cutover fixes for issues #139 and #140 deliberately amend `search-stop` guidance and the synthetic identifiers in `host-show` and `host-show-not-found`.
Those scenario definitions carry the reasons; the golden corpus hashes and seal advance only for those three scenarios plus `help-host-show`, four scenarios in total.
The N5 raw API amendment also advances the `scopes` hashes and corpus seal for its revised provisioning guidance (§4.7 of `v1.md`).
The corpus provenance includes the already merged bounded hostname-history amendment from `eae2ba801a3bcf39b2b13b4fc3799e1ee3e05e44` and §1.8 of `v1.md`.
Its two host-history help documents precede this carrier and remain unchanged here.
Native Windows evidence remains pending.
