# TypeScript S01 candidate

The [approved settlement amendment](s01-primitive-amendment.md#dns-deadline-settlement) resolves the DNS deadline STOP through explicit process termination after flushing the safe result.
Request destruction alone leaves an OS DNS lookup pending, so the one-shot CLI and hosted worker terminate after the invocation result is flushed.
The installed-artifact regression uses a three-second local DNS blackhole and requires WAIT_TIMEOUT and process settlement within the inherited one-second budget plus startup allowance.
The system resolver retains files+dns NSS and hosts-file behaviour.
Transport and output feasibility remain STOP gates.

The migration branch preserves the released Python implementation while evaluating a Node 24 TypeScript replacement.
The private npm candidate is `@knowttl/falcon-axi@0.0.0-s01.0` with the executable name `falcon-axi`.
Only `detection list` is delivered here, with limit, FQL and opaque continuation support.
The rest of the Python command surface remains the behaviour origin for later slices.
No npm publication, Python release change, workflow edit or host deployment is included.

## Build and offline verification

Development pins Node 24.14.0, npm 11.9.0 and exact locked dependencies.
The runtime floor is Node 24.11.0; native Windows and other Node versions remain unproved in this slice.
Run `npm ci --offline --ignore-scripts`, `npm run verify` and `npm run check:slice -- --slice S01 --paths native --offline`.
The installed check packs an explicit compiled-source allowlist, installs outside the checkout and executes the npm bin from a directory containing spaces.
Linux user/network/mount namespaces and iproute2 are required for that check.
Only loopback is enabled; an actual external connect is required to fail with ENETUNREACH.
Synthetic TLS delivery is injected only by the unpackaged test launcher after production origin and operation checks.
The CLI contains no fake-origin flag, config field, environment selector or recorded transport.

The optional hosted path requires a separately built frozen local Artium fixture containing the reviewed S01 host delta.
Set `S01_ARTIUM_ROOT` to that fixture and run `npm run check:slice -- --slice S01 --paths native,artium --offline`.
Missing fixtures and unknown or empty selections fail.
The host delta launches the candidate with its Node runtime rather than either Python launch condition, retaining Node heap limits and the existing termination grace.
The real client, server, public credential API, private profile writer and runner execute the same installed artifact.
The configured no-mistakes test deliberately requires only the native offline path.
Final hosted evidence is bound separately to the frozen fixture and final candidate revision.

## Authority and output

The registry retains all 114 canonical operation tuples and their official scope and corroboration citations.
A pinned canonical digest, own-key checks and recursive freezing seal the registry before networking.
This slice enables only GetQueriesAlertsV2 and PostEntitiesAlertsV2 after body validation.
The remaining reads and every exception tier are unreachable until their owning slices supply their authority checks.
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
The S01 list omits the Python suggestion for the undelivered detection-show command.
No existing Python golden document is rewritten.

## Primitive negative evidence

The [approved S01 amendment](s01-primitive-amendment.md) moves the RTR primitive proof to a separate native-addon slice before S11.
Transport and output feasibility remain STOP gates.
The retained `npm run probe:primitive -- --slice S01 --paths native --offline` is negative evidence and exits 1 deliberately.
It does not participate in the S01 passing check.
The probe demonstrates that path-based O_NOFOLLOW cannot preserve a retained ancestor descriptor after pathname replacement.
Neither fs-ext nor fs-native-extensions was adopted.
A compiled descriptor-relative adapter, retained-inode flock and interrupted durable append remain unproved.
A Linux-only /proc workaround is excluded, and no existing RTR safety guarantee is weakened.
