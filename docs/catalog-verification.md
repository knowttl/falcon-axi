# Offline AXI catalog verification

Verified on 2026-10-31 for issue #95 using locally built falcon-axi **0.8.4** artifacts from source revision `5a4f626e580687e943b698d648bb6991b1644f5b`.
This change adds verification only; package source, authority, safety gates, and output contracts are unchanged.
The environment was Linux x86_64, CPython 3.12.3, uv 0.13.1, Node 24.14.0, and the cached `skills` installer 1.7.4.
Dependencies came from the committed `uv.lock` (SHA-256 `1614fee3a5f12b2e4fe84c91f723e7b9c02a290483a8b8031a1d84fe0a760372`).
One missing locked dependency was fetched from PyPI during environment preparation; building, installation of the sdist, and verification then ran offline.

| Artifact | SHA-256 |
| --- | --- |
| `falcon_axi-0.8.4-py3-none-any.whl` | `49861cde5239b914e3c1f09dc4df315f3bbf0b0338c85b3a65f89ad9f04e5e33` |
| `falcon_axi-0.8.4.tar.gz` | `c51462b6bfcdd72aa5ad5c6144b9d33e27d38ed1d0716c01dc58ad5115043202` |

## Repeat the artifact checks

Run from the checkout containing these tests.
Choose a new absolute proof directory outside the checkout, `/tmp`, and git worktrees: hook setup deliberately refuses temporary or worktree executable locations.
Use a cached `skills` 1.7.4 CLI for the local skill-install check; obtaining that external installer is a separate prerequisite, not part of offline verification.
The dependency cache must contain the locked packages and Hatchling before disconnecting.
The exported requirements include test tools so the isolated interpreter can use `requests-mock`; neither environment installs the checkout or an editable package.

```sh
repo=$(git rev-parse --show-toplevel)
proof=/absolute/durable/path/catalog-proof
skills_cli=/absolute/path/to/cached/skills/bin/cli.mjs
uv --directory "$repo" sync --locked --offline
uv --directory "$repo" build --offline --out-dir "$proof/dist"
uv --directory "$repo" export --locked --offline --no-emit-project --output-file "$proof/requirements.txt"
uv venv "$proof/wheel-env"
uv pip install --offline --python "$proof/wheel-env/bin/python" -r "$proof/requirements.txt" "$proof/dist/falcon_axi-0.8.4-py3-none-any.whl"
uv venv "$proof/sdist-env"
uv pip install --offline --python "$proof/sdist-env/bin/python" -r "$proof/requirements.txt" "$proof/dist/falcon_axi-0.8.4.tar.gz"
env CATALOG_TEST_BIN="$proof/wheel-env/bin/falcon-axi" CATALOG_SKILLS_CLI="$skills_cli" uv --directory "$repo" run --offline pytest "$repo/tests/packaged" -q --basetemp "$proof/wheel-tests"
env CATALOG_TEST_BIN="$proof/sdist-env/bin/falcon-axi" CATALOG_SKILLS_CLI="$skills_cli" uv --directory "$repo" run --offline pytest "$repo/tests/packaged" -q --basetemp "$proof/sdist-tests"
uv --directory "$repo" run --offline scripts/verify.py
sha256sum "$proof/dist/"* "$repo/uv.lock"
```

`tests/packaged` is an explicit artifact gate rather than part of the default source-only offline suite.
`CATALOG_TEST_BIN` and `CATALOG_SKILLS_CLI` configure tests only; the released CLI accepts neither as a transport override.
The three version probes execute the installed console script directly.
Other CLI probes run that same console script through `runpy` under its installed interpreter with `-I`, replacing only the HTTP boundary using `requests-mock`.
The worker asserts that `falcon_axi` loads from that environment's prefix, refuses sockets, rejects unmatched HTTP requests, and records requests separately from CLI stdout.
It leaves credential resolution, sealed operation admission, Falcon SDK request construction, response translation, rendering, exit status, and executable identity intact.
All credentials, tokens, identifiers, and response data used by these checks are synthetic.
The existing fixture provenance and global source-suite socket refusal remain intact.

## Results

| Contract | Evidence and observed result |
| --- | --- |
| Clean wheel and sdist install | Separate environments, no editable source; both installed entry points pass the same artifact suite. |
| Version and command discovery | All three bare version flags return only `0.8.4`; every registered command has installed-artifact help matching the command declaration. |
| Input validation | Every registered command rejects an unknown flag and an extra positional with exit 2, structured stdout, recovery guidance, empty stderr, and zero authentication/service calls. |
| Configured home | Synthetic OAuth -> Alerts query -> POST hydration; absolute executable path, one-sentence description, five detections out of 384, a query limit of five, and actionable next steps. |
| Missing, failed, denied | `PROFILE_REQUIRED`, `AUTH_FAILED`, and `SCOPE_DENIED` are distinct nonzero results; none contains a zero-result dashboard. |
| Successful empty | A successful empty query prints `detections: 0 detections in this tenant` and does not hydrate. |
| Partial data and totals | Hydration retaining one or zero of two queried IDs still prints `384 total` and a continuation cursor; following it queries offset 2, preserving consumed query positions. |
| Text truncation | Detection command-line preview includes the truncation notice and `--full` recovery command; `--full` returns the exact complete synthetic string. |
| Opt-in integration | `setup` gives guidance and writes nothing; only `setup hooks` creates the four Claude Code, Codex, and OpenCode integration files. |
| Repeat and relocation | Repeated setup preserves file bytes and mtimes; moved console scripts repair both native hook commands and the OpenCode plugin path. |
| Hook consumers and failures | Installed native hook commands return one local status line; Node executes the installed OpenCode plugin's context callback and preserves existing context; a missing hook fails open with a repair hint. Malformed JSON/TOML and an unmanaged plugin fail before writes. |
| Skill installation | The advertised `skills add ... --skill falcon-axi` installer is exercised against the local repository with all three agent targets, isolated home, copying, telemetry disabled, and Node socket/fetch guards; installed Markdown matches the generated skill and references byte for byte. |
| Search repeat behavior | Controlled `search stop` sends one DELETE; a repeat receiving upstream 404 returns structured `NOT_FOUND`, with no job creation or implicit replay. |
| RTR safety | Installed preview makes zero requests; missing exact confirmation and missing profile opt-in refuse before authentication; the full offline suite exercises exact authorization, READ_ONLY precedence, allowlists, mandatory cleanup, interruption, caps, and no replay. |
| Other controlled lifecycle coverage | Existing `test_search.py`, `test_malquery_search.py`, `test_registry.py`, and `test_rtr_execute.py` exercise synthetic start/status/stop, read-only refusals, bounded literal searches, sealed exceptions, and replay restrictions; no live operation is run. |
| Broader list semantics | Existing golden scenarios and `test_pagination_empty.py`, `test_pagination_advance.py`, `test_walk.py`, and `test_response_diagnostics.py` cover other list families, unknown totals, empty terminal pages, partial walks, bounded recovery, and incomplete/error responses. |

Final results: **327 passed** against the wheel (41.54 seconds), **327 passed** against the independently installed sdist (41.89 seconds), and **2,792 passed** in the source offline suite (37.62 seconds).
`scripts/verify.py` also passed Ruff lint and formatting, strict mypy, the architecture boundary, generated skill drift, and generated command-documentation drift checks.
No product defect was confirmed during this verification.

## Remaining catalog exceptions and pending checks

- **Remote installation pending:** the exact network route `npx skills add knowttl/falcon-axi --skill falcon-axi`, npm discovery, and GitHub download were not run offline.
  Local repository discovery, agent installation, and installed content were verified using the same installer.
  The skill lives in the repository and is intentionally installed separately from the Python wheel/sdist.
- **Agent host commissioning pending:** native hook commands and the OpenCode callback were executed in isolation, but interactive Claude Code, Codex, and OpenCode sessions were not launched.
  The hook deliberately reports local profile resolution only, rather than fetching live detections on every session start; it captures no session-end transcript ([design §12.2](design/v1.md#122-session-hook-and-skill)).
- **Repeat-stop exception:** an upstream 404 cannot distinguish an expired job from an incorrect ID/repository, so the current contract returns `NOT_FOUND` rather than claiming a successful no-op.
  This is recorded as a catalog idempotence exception, not relaxed by this verification change.
  Search creation and RTR execution must not be made replayable to satisfy mutation idempotence advice.
- **Live commissioning pending:** tenant authentication, licensed scopes, regional behavior, actual totals, real GraphQL documents, search lifecycle, MalQuery, and RTR availability were not checked.
  Offline fixtures establish client behavior, not vendor acceptance or permission availability.
  This record authorizes no live calls, especially RTR or other lifecycle operations.
- **Platform coverage:** this run adds Linux artifact evidence; it does not extend the issue's Windows baseline to configured service behavior or hooks on Windows/macOS.
  Alerts retain the documented defensive 10,000-result ceiling and filtering guidance; offline evidence does not validate that upstream boundary.

No product behavior or safety authority changed, and no release was created.
