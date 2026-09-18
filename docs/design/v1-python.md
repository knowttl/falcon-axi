# falcon-axi C1 design: the Python implementation of the v1 design

Status: commissioned; stage 1 (P1), stage 2 (P2), and the NG-SIEM search surface admitted by captain exception N1 (v1.md §4.3) are implemented.
Written 2026-09-18 by the `falcon-axi-mcp-vs-cli-review` scout after the captain chose path C1 in the Lavish review, and committed here when the captain commissioned the build.
The captain locked four defaults at commissioning: MIT license, the repository stays private for now, the package name is `falcon-axi`, and decision D2 is accepted.
§9.1's ship brief is the contract stage 1 was built to; §10's open decisions are answered by those locked defaults.

## 0. What this document is, and what it is not

`docs/design/v1.md` remains the authoritative v1 design for everything it covers: Invariant R, the command surface, credentials, regions and Flight Control, pagination and rate limits, the error envelope, TOON output, command discovery, fixtures, and live-test boundaries.
This document changes the implementation language and the HTTP client underneath that design.
It amends v1.md §2 (backend), §3.3 (transport enforcement, restated for Python), §14 (test layout, restated for pytest), and §16 (API client evaluation, now adopting falconpy), and it adds packaging and distribution, which v1.md never specified.
Every section of v1.md not named here carries over unchanged, and a commissioned build must not narrow or widen the v1 command surface while porting.

Invariant R is binding and carries over from v1.md §0: falcon-axi changes no tenant state and implements no mutating operation, with the single captain exception N1 (v1.md §4.3), starting and stopping an NG-SIEM search job.
Nothing in a Python rewrite relaxes it further, and §3 below shows how the guarantee is rebuilt in Python.

## 1. Decision record

The captain's words, from the Lavish session on 2026-09-18, are recorded in the backlog task `falcon-axi-mcp-vs-cli-review` through the captain-hold answer path.
In sequence: "I like option C the best. Would it make sense to have another node wrapper around the python? or should we just stick with python?"; then "okay lets proceed with your recommendation. What would the install look like then? where would I publish the package?"; then "proceed with your recommendation for the remaining items then write the design and report and hand it back to the captain so he can commission the build."

Resulting decisions:

| Item | Decision |
| --- | --- |
| Primary path | C1: falcon-axi becomes a pure Python CLI on `crowdstrike-falconpy`, porting falcon-mcp patterns as reference code |
| Rejected | E (stay TypeScript), B (drive a local falcon-mcp over MCP), C2 (Node front end over a Python helper), D (generate commands from MCP schemas), archive |
| Distribution | Signed git tags on the private repo, installed with uv from git; PyPI deferred until a license is chosen and the repo is public |
| falcon-mcp reference check | Yes, as an opt-in script pinned to an upstream commit |
| MCP bridge | Not in v1 |
| Next ship task | Port stage 1 to Python with a parity gate, then stage 2 |

The report `report.md` in this directory carries the comparison that led here.

## 2. Language, runtime, and dependencies

**Python 3.11 or newer.**
falconpy supports 3.8 and up, but 3.11 is the floor falcon-mcp uses and gives `tomllib`, modern typing, and exception groups without backports.
uv provisions the interpreter on demand, so the operator never needs a system Python (§8).

**Runtime dependencies, exactly two.**

| Package | Pin | Why | License |
| --- | --- | --- | --- |
| `crowdstrike-falconpy` | `>=1.6.5,<2` | Operation-ID routing, request execution, proxy, User-Agent, timeout; only `requests` and `urllib3` underneath | Unlicense |
| `toon-format` | Spike first (§9 P0), then pin | The TOON encoder for stdout; the community Python implementation under the `toon-format` org, with spec-fixture tests in `tests/test_spec_fixtures.py` | MIT |

**Explicit non-dependencies.**

- Not `falcon-mcp`.
  Its module files import `mcp.server`, `mcp.types`, and `pydantic`, so importing any of them installs the whole server stack: `mcp` 2.2.0 pulls starlette, uvicorn, sse-starlette, opentelemetry-api, pyjwt, httpx2, jsonschema, and more.
  falcon-mcp is ported from, never imported (§6).
- Not `mcp`, not `pydantic`, not a CLI framework.
  Argument parsing is hand-written as in stage 1, because the AXI fail-loud rules (unknown flag by name, per-subcommand flag sets, secret-shaped flag guard) are easier to guarantee in forty lines than to coax out of argparse or click.
- Not any Node package.
  There is no npm shim and no Node process anywhere in C1.

**falconpy usage is confined to one class.**
Only `APIHarnessV2` is imported, and only inside the network sink (§3.2).
falconpy's Service Classes cover every Falcon mutation, and the architecture check forbids importing any other name from `falconpy`.

## 3. Transport enforcement in Python (amends v1.md §3.3)

v1.md §3.3 states seven properties of the sealed transport.
They hold in Python as follows.

### 3.1 The closed registry

`falcon_axi/transport/operations.py` holds the same five descriptors as stage 1, as frozen dataclasses with `effect: Literal["read"]`, the scopes, and the required two-citation `evidence` block.
`OperationId` is a `Literal[...]` union, so an unknown ID is a type error at check time and a `READ_ONLY_VIOLATION` at run time, exactly as `operation()` behaves today.
`MUTATION_ROUTE_PATTERNS` and the `seal()` checks port verbatim.
Registry growth still requires both citations in the same change (v1.md §2.2).

### 3.2 The single network sink, and why falconpy needs the gate in front of it

falconpy's `APIHarnessV2.command(operation_id, ...)` accepts any of Falcon's operation IDs, including every containment, deletion, and RTR operation.
That is why the registry check must happen before falconpy is ever called, and why falconpy must be reachable from exactly one module.

`falcon_axi/transport/harness.py` is that module.
It is the only file that imports `falconpy`, it exposes one function, `send_permitted_request(prepared, permit)`, and it refuses any call that does not carry the module-private permit sentinel, which only the sealed `request()` and `request_oauth_token()` entry points mint after their checks pass.
`scripts/architecture_check.py` asserts all of this by scanning the tree: `falconpy` appears in no other import, `.command(` appears in no other file, and no `from falconpy import` names anything but `APIHarnessV2`.

### 3.3 Redirects and the token endpoint

falconpy sets `allow_redirects=False` on every operation request and `True` only for `/oauth2/token` and `/oauth2/revoke` (`src/falconpy/_util/_functions.py:426-431`).
The operation side therefore matches v1.md §6.3 out of the box.
The token side does not: `requests` re-sends a POST body on a 307 or 308, so a redirected token request would replay the client secret to the redirect target.

**Decision D2: falcon-axi mints the token itself and hands it to falconpy.**
The thirty-line client-credentials request in stage 1's `auth.ts` is ported to `requests` with `allow_redirects=False`, reading `access_token`, `expires_in`, and `X-Cs-Region` exactly as today, and the result is passed to `APIHarnessV2(access_token=..., base_url=...)`.
This preserves §6.3 (no credential ever follows a redirect), §6.4 (autodiscovery stays in falcon-axi's hands), and §5.4 (no token cache; a token minted with `access_token=` is marked non-refreshable by falconpy, which is correct for a process that lives for one command).
The cost is that falconpy's own login and refresh code goes unused; that is one function falcon-axi already has.

The alternative, letting falconpy log in, was rejected only for the redirect property.
If falconpy later exposes a redirect switch on the token path, D2 can be revisited.

### 3.4 What else stays falcon-axi's

- **Trusted origins.** `base_url` is validated against the region table and `--allow-unknown-origin` before it reaches falconpy (v1.md §6.3).
- **429 and retry.** No retry or rate-limit handling exists in falconpy's request path (grep over `src/falconpy` for `429`, `retry`, `ratelimit` finds only an unrelated report-execution endpoint), so `transport/retry.py` ports as is, honoring `X-RateLimit-RetryAfter` (v1.md §7.4).
- **Error translation.** falconpy returns the raw envelope dict (`status_code`, `headers`, `body`); `falcon_error.py` translates it into the v1.md §9 envelope, never passing it through.
- **User-Agent.** `APIHarnessV2(user_agent="falcon-axi/<version>")`, matching §3.4.
- **Proxy.** `APIHarnessV2(proxy={"https": url})` from `FALCON_PROXY_URL`, the same variable name falcon-mcp uses, so an operator's environment works for both.
- **Timeout.** `APIHarnessV2(timeout=30)`, matching the 30-second `AbortSignal` in stage 1.

### 3.5 The test seam

The `Transport` protocol keeps its two methods, `request(id, args)` and `request_oauth_token(args)`.
`HttpTransport` delegates to `harness.py`; `RecordedTransport` lives in `tests/support/` and serves fixtures by operation ID plus an argument hash, with no network.
The substitution is by constructor argument in `run()`, exactly as stage 1 does it, and no flag, environment variable, or config key can select the recorded transport in a release (v1.md §14.2).
falconpy's `session=` parameter is not used as a seam; the seam stays above falconpy so that a fixture describes a Falcon response, not a `requests` interaction.

## 4. Package layout

```
pyproject.toml                 name falcon-axi, console script falcon-axi = falcon_axi.cli:main
falcon_axi/
  __init__.py
  __main__.py                  python -m falcon_axi
  version.py                   leaf module, no imports beyond the stdlib (AXI §10 fast path)
  cli.py                       argv parsing, flag guard, dispatch, exit codes
  core.py                      CliError and the error envelope
  credentials.py               env and 0600-file resolution, redaction set
  origin.py                    region table, trusted-origin check, autodiscovery retarget
  auth.py                      token mint (D2), session dataclass, rate-limit headers
  fql.py, cursor.py            filter shorthands per domain; the opaque cursor, offset and token models
  domain.py                    response reading shared by the three domain modules
  render.py                    the TOON boundary; raw lines and help block hand-formatted
  falcon_error.py              Falcon envelope to v1 §9 codes
  detection.py, host.py, vuln.py   pure functions: args to request descriptors, responses to rows
  scopes.py                    the §8.3 command-to-scope matrix, projected from the registry
  transport/
    __init__.py                sealed request() and request_oauth_token(); mints permits
    operations.py              the closed registry with evidence
    harness.py                 the only falconpy import; send_permitted_request
    retry.py                   429 and RetryAfter
    types.py                   Transport protocol, FalconResponse, request args
scripts/
  architecture_check.py        the boundary assertions of §3.2, plus the secret-shaped-flag and
                               automation-config-path checks stage 1 already runs
  reference_check.py           opt-in: clone falcon-mcp at the pinned commit, parse
                               falcon_mcp/common/api_scopes.py, assert every registered operation
                               still maps to a read scope and none has gained a :write mapping
  verify.py                    the single offline entry point (§7)
tests/
  fixtures/                    carried over byte-for-byte from stage 1, provenance headers intact
  offline/                     pytest, one file per seam and per domain
  live/                        opt-in smoke suite (v1.md §15), unchanged boundary
  support/recorded.py          RecordedTransport and fixture loaders
THIRD_PARTY_NOTICES.md         attribution for code ported from falcon-mcp (§6)
```

The module names mirror stage 1's `src/` one for one, so a reviewer can diff the port file by file.

### 4.1 Stage 1 contract map: TypeScript module to Python module to falconpy role

| Stage 1 (TypeScript) | Python | What changes | falconpy's role |
| --- | --- | --- | --- |
| `src/cli.ts` parse, flag guard, dispatch, exit codes | `falcon_axi/cli.py` | Hand-written argv loop ports as is; version flags handled before any heavy import | none |
| `src/core.ts` `CliError`, envelope | `falcon_axi/core.py` | Dataclass exception with `code`, `message`, `help`, `detail` | none |
| `src/credentials.ts` env and 0600 file, redaction set | `falcon_axi/credentials.py` | `os.stat` mode check replaces `fs.statSync`; same precedence and same refusal messages | none |
| `src/origin.ts` regions, trusted origin, retarget | `falcon_axi/origin.py` | Verbatim | none; `base_url` is validated before falconpy sees it |
| `src/auth.ts` token mint, `Session`, rate-limit headers | `falcon_axi/auth.py` | Token mint stays ours (D2) using `requests` with `allow_redirects=False`; `X-Cs-Region` read here | receives the minted token through `APIHarnessV2(access_token=...)` |
| `src/transport/operations.ts` closed registry, evidence, `seal()` | `falcon_axi/transport/operations.py` | Frozen dataclasses; `OperationId` is a `Literal` union | none; falconpy never decides what is allowed |
| `src/transport/index.ts` sealed `request()`, `requestOAuthToken()`, permits | `falcon_axi/transport/__init__.py` | Verbatim; permit is a module-private sentinel | none |
| `src/transport/network-sink.ts` the one `fetch` | `falcon_axi/transport/harness.py` | The one `falconpy` import; `send_permitted_request` calls `APIHarnessV2.command(op.id, parameters=..., body=...)`; TLS and network errors translated from `requests` exceptions | executes the permitted operation by ID with proxy, User-Agent, timeout, `allow_redirects=False` |
| `src/transport/retry.ts` 429, RetryAfter | `falcon_axi/transport/retry.py` | Verbatim; falconpy has no retry of its own | none |
| `src/transport/types.ts` `Transport`, `FalconResponse` | `falcon_axi/transport/types.py` | `typing.Protocol` and frozen dataclasses; falconpy's `{status_code, headers, body}` dict is normalized into `FalconResponse` here | none |
| `src/detection.ts`, `src/fql.ts`, `src/cursor.ts` | `falcon_axi/detection.py`, `fql.py`, `cursor.py` | Verbatim logic; cursor stays an opaque base64 wrapper | none |
| `src/render.ts` TOON boundary, raw lines, help block | `falcon_axi/render.py` | `toon_format.encode` replaces `@toon-format/toon` `encode`; raw and help lines stay hand-formatted (v1.md §10.1) | none |
| `src/falcon-error.ts` | `falcon_axi/falcon_error.py` | Verbatim; input is the normalized `FalconResponse` | none |
| `src/version.ts` | `falcon_axi/version.py` | Leaf module; `pyproject.toml` static version mirrored, with a test asserting they match | none |
| `test/support/recorded.ts` | `tests/support/recorded.py` | Same operation-ID plus argument-hash keying; constructor-argument substitution only | none |
| `scripts/architecture-check.mjs` | `scripts/architecture_check.py` | Adds the falconpy-confinement assertions of §3.2 | none |
| `npm run verify` | `uv run scripts/verify.py` | ruff, mypy, architecture check, pytest offline; socket guard | none |

## 5. Behavior that must not change during the port

The port is a refactor across languages, and v1.md's contract is the test.

- The command surface stays exactly what stage 1 ships **for the duration of the port**: home view, `detection list`, `detection show`, `auth status`; `--profile` still refused by name; nothing unshipped advertised (README status section rule).
  Stage 2 widens it to §1.2's three read domains plus `scopes`, and stage 3 adds the `search` noun captain exception N1 admits (v1.md §4.3); both are the design's own surface rather than port decisions.
- Every flag name, error code, help line, and TOON schema stays identical.
- **Parity gate.** Before any TypeScript is deleted, the ship task generates golden outputs from the TypeScript stage 1 for every offline test scenario (each fixture set plus argv), commits them under `tests/golden/`, and the Python port must reproduce them byte for byte.
  The golden files are derived from synthetic fixtures, so they contain no tenant data and may be committed.
  A later stage may change one of those documents only as a deliberate surface change argued in v1.md first, and `tests/golden/scenarios.json` records which documents changed and why.
- The redaction set (`access_token`, `client_id`, `client_secret`, `member_cid`, `token`, `Authorization`) applies to stdout and stderr, including anything falconpy logs; falconpy's `debug` stays off and `sanitize_log` on.
- No secret through argv: the flag-registration guard ports verbatim.

## 6. Porting from falcon-mcp, and the license mechanics

falcon-mcp is MIT.
Porting its logic into falcon-axi is permitted provided the copyright and permission notice travel with the ported code.

**What to port, per domain.**

| falcon-axi | Port from | What is taken |
| --- | --- | --- |
| `host list`, `host show` | `falcon_mcp/modules/hosts.py`, `modules/base.py` | Query-then-hydrate, `_reorder_by_ids`, the 5000-ID hydrate cap, FQL field guidance |
| `vuln list` | `falcon_mcp/modules/spotlight.py`, `modules/base.py` | `after`-token extraction, the filter-required rule, field guidance |
| pagination helpers | `modules/base.py` `_extract_pagination`, `_build_pagination_envelope` | The three cursor locations and the "total may be absent" rule |
| FQL guides for `--help` | `falcon_mcp/resources/*.py` | Field lists and operator rules, condensed to the v1.md §11.3 shape |

**What not to port.**
The Pydantic `Field` tool signatures, the MCP tool envelopes, the `offload_to_thread` wrapper, resource registration, and anything under `mcp.`.
falcon-axi's domain modules stay pure functions from arguments to request descriptors and from responses to TOON rows.

**Mechanics.**
Each file containing ported code carries a header naming the falcon-mcp source file and commit, and `THIRD_PARTY_NOTICES.md` reproduces the falcon-mcp MIT notice.
falconpy is Unlicense and needs no notice, but it is a dependency, not ported code.
The falcon-axi repository's own license is still "not yet chosen" per the README; MIT would be the natural match and is a captain decision (§10).

**Reference check.**
`scripts/reference_check.py` records the falcon-mcp commit the port was made from and asserts the registry's scope evidence against upstream `api_scopes.py` at that commit or a newer one.
It reaches the network, so it is opt-in and never part of `verify`.

## 7. Testing (amends v1.md §14 layout only)

- **Runner.** pytest, invoked through `uv run scripts/verify.py`, which runs in order: `ruff check`, `mypy --strict falcon_axi`, `python scripts/architecture_check.py`, and `pytest tests/offline`.
  It must stay offline and must fail if any test opens a socket; a pytest fixture that monkeypatches `socket.socket` to raise enforces that.
- **Fixtures.** The existing JSON files move unchanged.
  The two hygiene tests (provenance header present; no credential, token, CID, or realistic tenant-data pattern) port as is.
- **Coverage of the design.** Every test named in v1.md §14.5 is re-expressed; the 67 stage 1 tests are the floor, and the parity gate of §5 adds the golden comparisons.
- **Fast `--version`.** A test measures `falcon-axi --version` against the `python -c pass` floor in the same process and fails on a relative regression, as AXI §10 asks; `cli.py` handles version flags before importing `falconpy` or `toon_format`.
- **Live suite.** `tests/live/` keeps v1.md §15's boundary word for word: credentials provisioned per §5.7, shape assertions only, nothing persisted, any search job it starts also stopped, never in the required set.

## 8. Packaging and distribution

**Build.** `pyproject.toml` with the `hatchling` backend, static version, `[project.scripts] falcon-axi = "falcon_axi.cli:main"`.
`uv build` produces the wheel and sdist; `uv lock` pins the two dependencies and their transitive closure for reproducible installs.

**Install from the private repository, available on day one.**

```sh
# Linux, WSL, macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install git+https://github.com/knowttl/falcon-axi@v0.2.0
```

```powershell
# Windows
winget install --id astral-sh.uv
uv tool install git+https://github.com/knowttl/falcon-axi@v0.2.0
```

Then `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` in the environment or the 0600 credentials file, and `falcon-axi auth status`.
The install uses the operator's existing GitHub credentials, needs no registry account or publish token, and pins by tag; `uv tool upgrade falcon-axi` moves to a newer tag.
For agents without a global install, `uvx --from git+https://github.com/knowttl/falcon-axi falcon-axi ...` is the Python analog of `npx -y` and is the form the generated skill uses (v1.md §12.2).

**Publishing, in order.**

1. Now: signed git tags `vX.Y.Z` on the private repository.
2. Later, gated on a license choice and the repository going public: PyPI as `falcon-axi` (unclaimed as of 2026-09-18).
   Manual, from an operator machine: `uv build` then `uv publish --token <project-scoped PyPI token>`.
   Trusted publishing is unavailable because it requires GitHub Actions, which the captain's directive prohibits.
   Install then becomes `uv tool install falcon-axi` or `uvx falcon-axi`.
3. Optional after 2: the AXI community catalog, which requires independent source review at a pinned public release.
4. Never npm, never a container image.

**Session hook and skill (v1.md §12.2).**
`falcon-axi setup` writes the Claude Code, Codex, and OpenCode integrations with a PATH-verified `falcon-axi` binary name and the absolute uv tool path as fallback, exactly as AXI §7 asks; the skill examples use the `uvx --from git+...` form.

## 9. Commissioning plan

Each stage is one ship task with its own PR through no-mistakes.

**P0. Spike, one day, no product code.**
Answer four questions with evidence and stop:

1. Does `toon-format` (0.9.0b1 or newer) encode the exact TOON stage 1 emits?
   Method: run its spec-fixture suite, then encode the stage 1 golden rows and diff against `@toon-format/toon` 4.1.1 output.
   If it fails, the fallback is a vendored encoder of roughly 150 lines covering the subset falcon-axi prints (tabular arrays, nested objects, scalars, quoting), with the spec fixtures as its tests.
2. Does `APIHarnessV2(access_token=..., base_url=...)` execute `GetQueriesAlertsV2` and `PostEntitiesAlertsV2` with `parameters=` and `body=` as expected, offline, against a `requests` mock?
3. Does `uv tool install git+https://github.com/knowttl/falcon-axi@<tag>` work on Windows and on WSL with the operator's GitHub credentials, and what does the first-run latency look like?
4. What is the `falcon-axi --version` floor in Python versus the Node stage 1?

**P1. Port stage 1 with the parity gate. Implemented.**
Generate `tests/golden/` from TypeScript stage 1; build the Python package per §4; reach byte-for-byte parity; port all 67 tests plus the golden comparisons; add `scripts/verify.py` and `scripts/architecture_check.py`; update README, AGENTS.md, and v1.md's status lines; then delete `src/`, `test/`, `package.json`, `tsconfig.json`, and `scripts/architecture-check.mjs` in the same PR so `main` never carries two implementations.
Tag `v0.2.0`.

**P2. Stage 2 domains. Implemented.**
`host list`, `host show`, `vuln list`, `scopes`, written against the documented collections rather than copied from falcon-mcp, so no `THIRD_PARTY_NOTICES.md` is owed and `scripts/reference_check.py` is still unwritten; v1.md's §8.3 matrix and §13 cost table already described this surface and needed no change.
The golden set keeps the stage 1 scenarios as the cross-language parity gate and adds stage 2 scenarios as regression pins from this implementation.
Tag `v0.3.0`.

**P3. Stage 3 surface: NG-SIEM search under captain exception N1. Implemented.**
`search start`, `search status`, `search stop`, the three lifecycle operations captain exception N1 admits (v1.md §0, §4.3), with `NGSIEM:write` required on `search start` and `search stop` alone.
The golden set adds stage 3 scenarios as regression pins, including the forbidden-write registry gate.
Stage 2 and stage 3 both shipped without cutting a tag, so the next release tag covers all three stages.

**P4. Setup and delivery surface.**
`setup` with hook and skill, `--all`, `--max-rows`, `--fields`, profile configuration, and the opt-in live smoke suite.
Tag `v0.4.0`, and v1.md moves from "partially implemented" to "implemented".

### 9.1 First ship brief, copy-ready

This is the brief for the first ship task after the captain commissions the build.
It folds the P0 spike into the task as its first, stop-and-report step so that a negative spike result ends the task before any port work.

```
Task: falcon-axi-c1-p1-port-stage1  (repo: falcon-axi, kind: ship)

Goal
  Port falcon-axi stage 1 from TypeScript to Python per docs/design/v1-python.md (the C1 design),
  with byte-for-byte output parity, and remove the TypeScript implementation in the same PR.
  Invariant R (docs/design/v1.md §0) is binding and unchanged. No MCP process, no Node code,
  no falcon-mcp dependency.

Step 0, spike, stop and report before touching product code
  1. Install toon-format (0.9.0b1 or newer) in a scratch venv; run its spec-fixture tests; encode the
     rows stage 1 prints for every offline scenario and diff against the TypeScript output.
     Report pass/fail. On fail, propose the vendored-encoder fallback (design §9 P0.1) and wait.
  2. Confirm APIHarnessV2(access_token=..., base_url=...).command("GetQueriesAlertsV2", parameters=...)
     and .command("PostEntitiesAlertsV2", body=...) issue the expected method, path, query, and body
     against a requests mock, with allow_redirects=False. Report the observed request shapes.
  3. Confirm `uv tool install git+https://github.com/knowttl/falcon-axi@<tag>` works on WSL and on
     Windows with the operator's GitHub credentials; record first-run latency.
  4. Measure `python -c pass` versus the ported `falcon-axi --version` floor.
  Append `working: spike complete` with the four results, then continue only if 1 and 2 passed.

Scope
  - Generate tests/golden/ from the TypeScript stage 1 for every offline scenario (fixtures plus argv),
    before writing Python. Golden files derive from synthetic fixtures only.
  - Create pyproject.toml (hatchling, Python >=3.11, deps: crowdstrike-falconpy>=1.6.5,<2 and
    toon-format pinned per the spike), uv.lock, and the falcon_axi/ package per design §4 and §4.1.
  - Implement D2: falcon-axi mints the OAuth token with requests and allow_redirects=False and hands
    it to APIHarnessV2; falconpy is imported only in falcon_axi/transport/harness.py.
  - Port all 67 offline tests to pytest plus the golden comparisons; port both fixture hygiene tests;
    add the socket guard; add scripts/architecture_check.py and scripts/verify.py.
  - Update README (install from git with uv, status section, relationship to falcon-mcp stating no
    runtime dependency), AGENTS.md (verify entry point, seams, credential rules), and v1.md status
    lines; add docs/design/v1-python.md from the scout's design.
  - Delete src/, test/, package.json, package-lock.json, tsconfig.json, scripts/architecture-check.mjs,
    dist/ in the same PR.

Acceptance
  - `uv run scripts/verify.py` passes offline: ruff, mypy --strict, architecture check, pytest with
    the socket guard, golden parity for every scenario.
  - `grep -rn falconpy falcon_axi | grep -v transport/harness.py` is empty.
  - `grep -rln "mcp\|falcon_mcp" pyproject.toml uv.lock falcon_axi` is empty.
  - `falcon-axi --version`, `falcon-axi --help`, and `falcon-axi detection list --help` match the
    stage 1 text; `falcon-axi` with no credential produces the same error envelope as stage 1.
  - README advertises nothing unshipped; no secret-shaped flag exists; no automation config path
    appears in the repository.

Out of scope
  host, vuln, scopes, setup, --all, --max-rows, --fields, profiles, live suite, reference_check.py,
  any PyPI publish. Tag v0.2.0 is cut by the captain after merge.

Decisions assumed (design §10); stop with needs-decision if any is contradicted
  license not yet chosen (no publish); repo stays private; package name falcon-axi; D2 accepted.
```

## 10. Captain decisions still open

All four were answered by the captain at commissioning and are recorded in the status line above.

1. **License for falcon-axi.** MIT, in `LICENSE`.
2. **Repository visibility.** Private for now, so install is from git with uv and PyPI stays deferred.
3. **Package name.** `falcon-axi`.
4. **D2 acceptance.** Accepted: falcon-axi mints the token with redirects refused and hands it to falconpy (§3.3).

What the stage 1 build learned that this design did not predict:

- `toon-format` 0.9.0b1 matches `@toon-format/toon` 4.1.1 on every shape falcon-axi prints, so the vendored-encoder fallback of §9 P0.1 was not needed. The one divergence is the empty array (`key: []` against `key[0]:`), which no falcon-axi document reaches; `tests/offline/test_toon_parity.py` pins that. The encoder exposes no supported single-value escape helper, so the hand-formatted help block carries the TOON §7.1 escaping itself, in `falcon_axi/render.py`.
- falconpy folds every `requests` exception into a synthetic `500` envelope, which would erase the TLS_UNTRUSTED and NETWORK_UNREACHABLE codes §9.2 owes the caller, and it returns raw bytes rather than a status for a body-less redirect. `falcon_axi/transport/harness.py` therefore passes falconpy a recording `requests.Session` and reads the status, headers, and body from the response falconpy issued rather than from falconpy's own container. falconpy still resolves and executes the operation.
- The parity gate lives in `tests/golden/`: `scenarios.json` declares 52 offline invocations, each `<name>.txt` is the exact document TypeScript stage 1 printed, and `exit-codes.json` its exit code.

## 11. Sources

- `knowttl/falcon-axi` `c8b6500`: `src/transport/*.ts`, `src/auth.ts`, `src/render.ts`, `test/support/recorded.ts`, `docs/design/v1.md`.
- `crowdstrike/falconpy` `30823f0` (2026-08-17): `src/falconpy/_util/_functions.py:415-440` (redirect policy, User-Agent), `src/falconpy/_auth_object/_uber_interface.py:67-84` (constructor), grep for retry handling; PyPI `crowdstrike-falconpy` 1.6.5 `requires_dist`; GitHub license `Unlicense`.
- `crowdstrike/falcon-mcp` `9bc0efe` (0.19.0): `falcon_mcp/modules/base.py`, `hosts.py`, `spotlight.py`, `detections.py`, `resources/`, `common/api_scopes.py`; `modules/hosts.py:10-13` imports; MIT.
- PyPI `mcp` 2.2.0 `requires_dist`.
- `toon-format/toon-python`: MIT, `tests/test_spec_fixtures.py`, PyPI `toon-format` releases 0.1.0 and 0.9.0b1.
- `kunchenguid/axi` `058bc36`: `.agents/skills/axi/SKILL.md` §6, §7, §10; `VISION.md` catalog admission rules.
