# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## v1 is read-only, and this is not negotiable

**falcon-axi v1 requires only CrowdStrike read permissions and implements no write, create, update, delete,
execute, containment, quarantine, release, response, or otherwise mutating operation.**
This is a captain-confirmed, binding architectural invariant.
Relaxing it is a captain decision, never an agent's; if a task seems to require a mutation, stop and escalate.

Two consequences that catch people out:

- **Read-only is semantic, not method-based.**
  Falcon reads are routinely POSTs (`PostEntitiesAlertsV2`, `PostDeviceDetailsV2`), and Falcon has read-scoped
  operations with real side effects (`RTR_InitSession` is scoped `Real time response:read` and opens a session
  on a live endpoint).
  So neither the HTTP verb nor the scope name proves safety.
- **An endpoint may be added only with two citations**: official CrowdStrike documentation showing its required
  scope is a read permission, and falcon-mcp's treatment of it as corroboration.
  The transport's operation registry carries that evidence as a required field and the local required-check
  set asserts it.

See `docs/design/v1.md` §0 (the invariant), §1.5 (excluded capability classes), §2.2 (the two-citation rule),
§3 (transport enforcement), §5.7 (read-scopes-only provisioning), and §15 (live-test boundary).

## The v1 design is authoritative

`docs/design/v1.md` is the committed design: command surface, auth and credential rules, region and Flight
Control tenancy, pagination and rate limits, error envelope, TOON output, fixtures, live-test boundaries, and
the API-client evaluation.
Read it before adding or changing any command surface, and update it in the same change when the surface moves.
Its §17 records open questions; check there before re-deriving a decision that was already argued, and its §18
cites every source, so a claim can be re-verified rather than trusted.

Nothing is implemented yet.
The repository is design-stage: no `src/`, no runtime dependencies, no build pipeline.
The project has no GitHub Actions workflow by captain directive.
Validation is local, and adding a GitHub Actions workflow requires the captain to lift that directive.
Once implementation begins, `npm run verify` is the single entry point for the complete local required-check
set described in `docs/design/v1.md` §14.5 and §15.4.

## Credential rules

- Secrets reach falcon-axi through the environment or a `0600` file, **never** through `argv`.
  A flag-registration guard rejects any flag whose name looks like a secret.
- Redaction covers `access_token`, `client_id`, `client_secret`, `member_cid`, `token`, and `Authorization`,
  on stdout and on stderr.
  CrowdStrike treats the tenant CID as sensitive, and so do we.
- No credential, token, CID, or captured live data belongs in this repository, including fixtures.
  See `docs/design/v1.md` §5 and §14.4.

## Build to the AXI skill

Every agent-facing surface in this repo follows the AXI standard (TOON on stdout, minimal schemas, structured
errors on stdout, content-first home view, fail-loud on unknown flags).
Read the `axi` skill at `~/.pi/agent/skills/axi/SKILL.md` and the TOON spec it points to before building or
reviewing any CLI behavior here.
`azure-axi` and `awx-axi` are the sibling references for these patterns; `docs/design/v1.md` §18 lists where
their assumptions do **not** transfer to Falcon.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
The Markdown sentence rule means each sentence starts on its own physical line; a sentence may wrap across
following lines, but two sentences must not share one physical line.
