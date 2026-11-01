# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## v1 read-only invariant

**`docs/design/v1.md` §0 owns the captain-confirmed, binding read-only invariant and its closed exceptions.**
The generated command reference in `docs/commands.md` owns delivery status.
Relaxing the invariant further is a captain decision, never an agent's; its exceptions are not precedents to extend, and if a
task seems to require any other mutation, stop and escalate.

Three consequences that catch people out:

- **Read-only is semantic, not method-based.**
  Falcon reads are routinely POSTs (`PostEntitiesAlertsV2`, `PostDeviceDetailsV2`), and Falcon has read-scoped
  operations with real side effects (`RTR_InitSession` is scoped `Real time response:read` and opens a session
  on a live endpoint).
  So neither the HTTP verb nor the scope name proves safety.
- **An endpoint may be added only with two citations**: official CrowdStrike documentation stating its required
  scope, and falcon-mcp's treatment of it as corroboration, or, when falcon-mcp has no tool for the operation,
  falconpy's generated endpoint table plus PSFalcon wrapping it (`docs/design/v1.md` §2.2).
  The transport's operation registry carries that evidence as a required field and the local required-check
  set asserts it, per tier as defined in `docs/design/v1.md` §2.2.
- **The exceptions are closed by id allowlists, not by discipline.**
  The `search-lifecycle` allowlist in `src/transport/operations.ts` is exactly `StartSearchV1` and `StopSearchV1`,
  and registry sealing rejects any other descriptor claiming `effect: "search-lifecycle"`, any scope other than
  `NGSIEM:write` on one, and any `:write` scope on a `read` descriptor.
  The `graphql-query` allowlist is exactly `api_preempt_proxy_post_graphql`, sealed the same way to
  `Identity Protection GraphQL:write`, and GraphQL text reaches it only as a registered document from
  `src/transport/documents.json`, never as caller input.
  N4 seals `malquery-search` to exactly `PostMalQueryExactSearchV1` and `PostMalQueryFuzzySearchV1`,
  with `MalQuery:write`, canonical POST routes, validated literal patterns, and bounded results rechecked at the sink.
  N3 separately seals its guarded RTR lifecycle (§4.5); N4 admits no hunt, multidownload, or sample download.
  Admitting a further state-changing operation requires editing its closed allowlist (§3.3), which is the reviewable diff §1.6 demands.

See `docs/design/v1.md` §0 (the invariant), §1.5 (excluded capability classes), §2.2 (the two-citation rule),
§3 (transport enforcement), §4.3-§4.6 (captain exceptions N1-N4 and their boundaries), §5.7
(provisioning), and §15 (live-test boundary).

## The v1 design is authoritative

`docs/design/v1.md` is the committed design: command surface, auth and credential rules, region and Flight
Control tenancy, pagination and rate limits, error envelope, TOON output, fixtures, live-test boundaries, and
the API-client evaluation.
Read it before adding or changing any command surface, and update it in the same change when the surface moves.
Its §17 records closed decisions; check there before re-deriving a decision that was already argued, and its §18
cites every source, so a claim can be re-verified rather than trusted.

`docs/design/v1-typescript.md` owns the current Node 24 TypeScript implementation under `src/`, sealed transport, npm packaging, and offline verification.
Read it and v1.md before changing implementation structure; v1.md still owns behavior.
`docs/design/v1-python.md` preserves the Python v0.9.0 implementation and golden-comparison history.
The current package has no Python runtime, MCP process, falconpy, or `falcon-mcp` dependency.

The implemented surface includes the package foundation, the sealed transport and its closed registry,
AXI credential profiles with `auth status`, `profile list`, and `config path`, the read domains (`detection list`, `detection show`,
`detection summary`, `host list`, `host show`, `host logins`, `host network`, `account list`, `account show`, `asset list`, `asset show`, `application list`, `login list`, `vuln list`, `vuln show`, `cve list`, `cve show`,
`actor list`, `actor show`, `report list`, `report show`, `indicator list`, `indicator show`),
the NG-SIEM search lifecycle (`search start`, `search status`,
`search stop`), the Identity Protection GraphQL reads (`identity list`, `identity show`, `identity timeline`, `identity assessment`),
the REST sensor inventory (`identity sensor list`, `identity sensor show`),
the container and serverless reads (`container list`, `image list`, `image vulnerabilities`, `serverless list`),
the Data Protection configuration reads (`classification list`, `classification show`, `data-policy list`, `data-policy show`),
the firewall rule list/show and group list, IOA group list, correlation-rule list, and case list/show,
plus the `scopes` matrix and the home view.
The exclusion inventories (`exclusion list|show` with `--type`) and quarantined file metadata
(`quarantine list|show`) also ship as read-only commands.
Malware family reads (`malware list`, `malware show`), Identity Protection policy-rule reads
(`identity rule list`, `identity rule show`), and Discover IoT inventory (`iot list`) also ship.
The generated command reference in `docs/commands.md` is the authoritative list of shipped commands, and
no help text, suggestion, or skill may advertise an unshipped command.
`npm run verify` is the single local entry point for the complete offline required-check set.
It runs TypeScript compilation, formatting, architecture and generated checks, clean package installation, and the cumulative native suite with network isolation.
The Python test files remain frozen safety-ledger provenance and are read as bytes, never executed by this gate.
`tests/golden/` is the recorded-invocation gate; `docs/design/v1-python.md` §5 owns its comparison contract and release-version exception.
Its stage 1 scenarios are also the cross-language parity gate, because the TypeScript stage 1 this port
replaced generated their expected documents.
Changing any output means regenerating nothing; it means the change is a deliberate behavior change that must
be argued in the design first, as stage 2's four changed stage 1 documents and stage 3's eight were.
`tests/golden/history.json` preserves the historical document-change explanations; new explanations belong in
the affected `tests/golden/scenarios/<name>.json`.

The implementation seams are documented in `docs/design/v1-typescript.md`:

- `src/transport/https.ts` owns HTTPS acquisition and consumes invocation-local sealed permits.
  `scripts/typescript/architecture.ts` checks network authority and bypass seeds.
  Synthetic delivery is supplied only by unpackaged test launchers after production origin and operation validation.
- Query/hydrate reads retain totals and query order in `src/investigation.ts` and `src/inventory.ts`; `src/cursor.ts` retains one cursor vocabulary across pagination models.
  `src/search.ts` owns bounded query-job waits and fixed repository paths; ThreatGraph fixes its vertex type to `processes` at the transport boundary.

## Credential rules

- Secrets reach falcon-axi through the environment or an env/file SecretRef in `config.json`, **never** through `argv`.
  POSIX secret files permit 0400 or 0600; config files prohibit group/world writes.
  A flag-registration guard rejects any flag whose name looks like a secret.
- Redaction covers `access_token`, `client_id`, `client_secret`, `member_cid`, `token`, `Authorization`, `cid`, and `#repo.cid`,
  on stdout and on stderr.
  CrowdStrike treats the tenant CID as sensitive, and so do we.
  Alerts v2 composite detection ids contain the own-tenant or selected child CID and are printed as-is, including
  when passed to `detection show`.
  Standalone member-CID values, including those in auth status, suggestions, URLs, and logs, stay masked or
  unprinted; the documented `--member-cid` flag remains allowed.
  NG-SIEM search event CID fields (`cid`, `#repo.cid`) are redacted in output.
- No credential, token, CID, captured live data, or personal data belongs in this repository, including fixtures, docs, and pull-request text.
  Clean it out before it is committed.
  See `docs/design/v1.md` §5 and §14.4.
  Every fixture under `tests/fixtures/` is wholly synthetic and carries a provenance header that an offline test
  asserts.

The automation is `.github/workflows/ci.yml`, which runs `npm run verify` with no secrets, and `.github/workflows/release-please.yml`, whose release and publish jobs are disabled during cutover.
The final-coverage check allows exactly those two workflow files and rejects `FALCON_AXI_LIVE`, both credential environment names, and their deprecated aliases in decoded workflow settings.

## Build to the AXI skill

Every agent-facing surface in this repo follows the AXI standard (TOON on stdout, minimal schemas, structured
errors on stdout, content-first home view, fail-loud on unknown flags).
Read the `axi` skill at `~/.agents/skills/axi/SKILL.md` and the TOON spec it points to before building or
reviewing any CLI behavior here.
`azure-axi` and `awx-axi` are the sibling references for these patterns; `docs/design/v1.md` §18 lists where
their assumptions do **not** transfer to Falcon.
`skills/falcon-axi/SKILL.md` and its per-command `references/` are this repo's generated agent-facing skill;
regenerate them with `npm run generate`.
Its drift check runs in `npm run verify`, and it must never name a command the CLI does not ship (`docs/design/v1.md` §12.2).

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
The Markdown sentence rule means each sentence starts on its own physical line; a sentence may wrap across
following lines, but two sentences must not share one physical line.
