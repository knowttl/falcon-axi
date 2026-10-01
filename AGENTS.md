# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## v1 is read-only, with exactly one captain-granted exception

**falcon-axi v1 changes no state in a Falcon tenant and implements no write, create, update, delete, execute,
containment, quarantine, release, or response operation, apart from starting and stopping an NG-SIEM search
job under captain exception N1.**
This is a captain-confirmed, binding architectural invariant.
Relaxing it further is a captain decision, never an agent's; N1 is not a precedent to extend, and if a task
seems to require any other mutation, stop and escalate.

Three consequences that catch people out:

- **Read-only is semantic, not method-based.**
  Falcon reads are routinely POSTs (`PostEntitiesAlertsV2`, `PostDeviceDetailsV2`), and Falcon has read-scoped
  operations with real side effects (`RTR_InitSession` is scoped `Real time response:read` and opens a session
  on a live endpoint).
  So neither the HTTP verb nor the scope name proves safety.
- **An endpoint may be added only with two citations**: official CrowdStrike documentation stating its required
  scope, and falcon-mcp's treatment of it as corroboration, or, when falcon-mcp has no tool, falconpy's
  generated endpoint table plus another first-party CrowdStrike SDK (§2.2).
  The transport's operation registry carries that evidence as a required field and the local required-check
  set asserts it, per tier: a `: READ` doc scope for a read, a `: WRITE` one for the exception.
- **The exception is closed by an id allowlist, not by discipline.**
  `SEARCH_LIFECYCLE_IDS` in `falcon_axi/transport/operations.py` is exactly `StartSearchV1` and `StopSearchV1`,
  and registry sealing rejects any other descriptor claiming `effect: "search-lifecycle"`, any scope other than
  `NGSIEM:write` on one, and any `:write` scope on a `read` descriptor.
  Admitting a third write operation means editing that allowlist, which is the reviewable diff §1.6 demands.

See `docs/design/v1.md` §0 (the invariant), §1.5 (excluded capability classes), §2.2 (the two-citation rule),
§3 (transport enforcement), §4.3 (captain exception N1 and its boundary), §5.7 (provisioning), and §15
(live-test boundary).

## The v1 design is authoritative

`docs/design/v1.md` is the committed design: command surface, auth and credential rules, region and Flight
Control tenancy, pagination and rate limits, error envelope, TOON output, fixtures, live-test boundaries, and
the API-client evaluation.
Read it before adding or changing any command surface, and update it in the same change when the surface moves.
Its §17 records open questions; check there before re-deriving a decision that was already argued, and its §18
cites every source, so a claim can be re-verified rather than trusted.

`docs/design/v1-python.md` is the committed amendment that made falcon-axi a pure Python CLI on
`crowdstrike-falconpy`: language and runtime, falconpy confinement, packaging with uv, and the pytest layout.
Read both before changing implementation structure; v1.md still owns behavior, v1-python.md owns how it is
built.
There is no Node runtime, no MCP process, and no `falcon-mcp` dependency anywhere in the tree.

The implemented surface includes the package foundation, the sealed transport and its closed registry,
credential resolution with `auth status`, the read domains (`detection list`, `detection show`,
`host list`, `host show`, `vuln list`, `cve show`), the NG-SIEM search lifecycle (`search start`, `search status`,
`search stop`), plus the `scopes` matrix and the home view.
The README's status section is the authoritative list of what is shipped and what is deliberately absent, and
no help text, suggestion, or skill may advertise an unshipped command.
`uv run scripts/verify.py` is the single local entry point for the complete offline required-check set
(§14.5, §15.4); it runs ruff, `mypy --strict`, `scripts/architecture_check.py`, and the `tests/offline/` suite,
and it must stay offline: a pytest fixture refuses every socket.
`tests/golden/` is the recorded-invocation gate: every scenario in `scenarios.json` must reproduce its
expected document byte for byte.
Its stage 1 scenarios are also the cross-language parity gate, because the TypeScript stage 1 this port
replaced generated their expected documents.
Changing any output means regenerating nothing; it means the change is a deliberate behavior change that must
be argued in the design first, as stage 2's four changed stage 1 documents and stage 3's eight were.
`tests/golden/scenarios.json`'s `comment` records which documents changed and why.

Two seams are worth knowing before changing them:

- Commands are pure functions over a `Transport`, and `falcon_axi/cli.py`'s `run()` defaults to the sealed
  `http_transport`.
  Offline tests pass `RecordedTransport` from `tests/support/recorded.py` as an argument.
  That is the only substitution point, and it is code-level only: no flag, environment variable, or config key
  can reach the recorded transport in a released build (§14.2).
- Falcon's list endpoints are two requests, not one: a query step returns ids and an entity step hydrates
  them, losing both the sort order and the pagination metadata, so `detection.py` and `host.py` capture the
  total before hydrating and reapply the query order after (§2.3).
  `vuln.py` is the exception, a single combined request paginated by an opaque `after` token rather than an
  offset; `cursor.py` carries both models behind one `--cursor` vocabulary.
  `search.py` is a third shape again: an NG-SIEM query job carries no pagination metadata at all, so it has
  neither `--limit` nor `--cursor`, and the caller owns the polling loop rather than the CLI blocking on it.
  Its three routes are also the only ones with `{path}` variables, which `path_arguments()` validates against
  separators and dot segments before a request is prepared; `RecordedTransport` runs the same check so the
  test seam is never more permissive than the sealed transport.
- `falcon_axi/transport/harness.py` is the one file allowed to touch the network and the one file allowed to
  import `falconpy`, from which only `APIHarnessV2` may be named; `send_permitted_request` is the one function
  in it allowed to reach the network.
  falconpy's `command()` accepts every Falcon operation id, mutating ones included, so the closed registry is
  checked before falconpy is ever constructed.
  falcon-axi also mints the OAuth token itself with `allow_redirects=False` (decision D2) rather than letting
  falconpy log in, because falconpy allows redirects on the token path and `requests` replays a POST body on a
  307 or 308.
  `scripts/architecture_check.py` enforces all of that and also rejects any automation configuration path
  appearing in the repository.
- falconpy folds transport exceptions into a synthetic 500 and returns raw bytes for a body-less redirect, so
  the sink reads status, headers, and body from the `requests.Response` it recorded rather than from falconpy's
  container.
  Keep that seam if you touch `harness.py`, or TLS_UNTRUSTED, NETWORK_UNREACHABLE, and the redirect refusal
  silently become UPSTREAM_ERROR.

## Credential rules

- Secrets reach falcon-axi through the environment or a `0600` file, **never** through `argv`.
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

The project has no GitHub Actions workflow by captain directive.
Validation is local, and adding a GitHub Actions workflow requires the captain to lift that directive.

## Build to the AXI skill

Every agent-facing surface in this repo follows the AXI standard (TOON on stdout, minimal schemas, structured
errors on stdout, content-first home view, fail-loud on unknown flags).
Read the `axi` skill at `~/.pi/agent/skills/axi/SKILL.md` and the TOON spec it points to before building or
reviewing any CLI behavior here.
`azure-axi` and `awx-axi` are the sibling references for these patterns; `docs/design/v1.md` §18 lists where
their assumptions do **not** transfer to Falcon.
`skills/falcon-axi/SKILL.md` is this repo's agent-facing skill; it is hand-written until `setup` generation
lands and must never name a command the CLI does not ship (`docs/design/v1.md` §12.2).

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
The Markdown sentence rule means each sentence starts on its own physical line; a sentence may wrap across
following lines, but two sentences must not share one physical line.
