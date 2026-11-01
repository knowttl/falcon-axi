# TypeScript distribution and rollback rehearsal

This is the S14 Phase A review record.
The approved delivery split places the rollback rehearsal and inert release preparation in a Phase A PR targeting `migration/typescript`.
Cutover tree preparation, Python removal, and publishing-workflow deactivation belong to a separate Phase B PR targeting `main`, only after Phase A merges.
The Phase A PR body must record this approved split and its separate Phase B dependency.
The migration branch remains an unpublished private candidate.
The released Python implementation remains on `main` until a separately reviewed cutover.
No registry publication, registry tag change, host rollout, or release workflow activation is part of Phase A.
Native Windows certification remains pending for both implementations.

## Rehearsal inputs and results

On 2026-11-01, GitHub reported Python `main` at `dd9fa40569912587794223f3042513eec1f61ff6`, also the `v0.9.0` release commit.
The migration head was `26196efb30d3b7905c0bcc7e93126fdb49c27be4`.
The frozen Python implementation and golden corpus in that migration head match Python `main`.
The approved comparison origin was `v0.8.4`; S13's complete golden corpus already includes the subsequent bounded hostname-history amendment and Python 0.9.0 behavior.
The TypeScript design amendments own intentional differences, including search-creation non-replay.
Recapture both branch heads and reconcile further drift before cutover.

The Python wheel and sdist were built offline from the `v0.9.0` release source using `uv build --offline`.
No retained published 0.9.0 artifact was available for a byte-for-byte comparison with PyPI.
The hashes below identify the rebuilt artifacts actually exercised; they are not claims about PyPI artifact hashes.
The Python runtime used CPython 3.12.3 and dependencies exported from the release's frozen `uv.lock`.

The pre-switch local Artium source was `f250c46fe177ddaa85b2a9cdc7fe6e9e41f234f9`, which originally pinned Python 0.8.4.
A separate local clone was repinned to the actual last Python release, 0.9.0, with regenerated inventory, hashed Python requirements, and the installed release credential schema.
Its Python adapter and Python runner launch conditions were retained together.
That coherent rollback source is frozen as commit `d7c90dcad3614f6e1ab8a4fbe9981acfe2810767` in the retained rehearsal bundle.
The shared fixture was unchanged.

| Input | SHA-256 |
| --- | --- |
| Rebuilt `falcon_axi-0.9.0-py3-none-any.whl` | `f1d83f7302709fc0f5ead3c4688c3ce956fa03536cec4566925b760e3ee09ac6` |
| Rebuilt `falcon_axi-0.9.0.tar.gz` | `002e55b1642bf4b59259f00cfa03072fdf3db7e2586ff540443c20c005afd4ba` |
| Python release `uv.lock` | `1614fee3a5f12b2e4fe84c91f723e7b9c02a290483a8b8031a1d84fe0a760372` |
| Installed Python credential schema | `1bed07d864a0a9b769b039ea4cb67454126d13046144a34258ab1a8a88821098` |
| CPython 3.12.3 executable | `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f` |
| Node 24.14.0 executable | `e237a2839d0cbdc9a9a2adda1a184afc0f5b20306ffbe923af5686550472d8a8` |
| Artium `pnpm-lock.yaml` | `5e68cc0a77d345352aa2785541d95ce6cbf9b314d7ebcbfb8bb224c30768a435` |
| Artium `tools/pnpm-lock.yaml` | `def625ea9551bf0afed17e4b6b5f14f13c8425774f939d9de49addd0ecf7937c` |
| Artium Python requirements | `5a87c722e28eeb50dc530d8ca800a043418ff5af9f84a38e8415adbaa7193883` |
| Artium generated Falcon inventory | `bb634534ca047a4684da50f65e6f1ecec5365d47c495fabd843b52cb88c9d791` |
| Artium Falcon source pin | `8e871cb52d0ddeb34863e73af9bfb6846902ec036428da545966f65a29265012` |
| Retained Artium rollback Git bundle | `b350077d36cc12d7d8d9105133d03ae871d6c4679c6964faef934a04a6d3e29f` |
| Retained Python runtime/artifact archive | `f5551900cdf7060c324be75e1e1a36379fc4316b07f48628ceb1ee429751d40c` |
| Retained Artium source/build/dependency archive | `9bb9990d6e201b821e8bfd7a0deeaf51f02aed46fbfef9c7feddeac5b1c61292` |

The rehearsal installed the npm tarball into an isolated global prefix alongside the Python executable, then installed each implementation's hooks into the same isolated agent configuration.
It preserved an unrelated existing SessionStart hook.
`command -v falcon-axi` first selected the npm prefix.
After the npm uninstall and Python wheel reinstall, the same check selected the Python runtime and `falcon-axi --version` printed `0.9.0`.
The restored Python implementation repaired the emitted hook, which executed successfully with synthetic environment credentials and emitted no credential values.

Real local Artium then executed `artium-axi falcon-axi detection list --limit 1` using the restored installed Python artifact, release schema, Python adapter, private credential writer, and real process runner.
The synthetic HTTPS service observed exactly one OAuth request, one alert-ID query, and one hydration request.
The CLI returned this synthetic result with exit code 0 and empty stderr:

```text
count: 1 of 1 total
detections[1]{id,severity,tactic,hostname}:
  synthetic-s14-detection,Low,Discovery,SYNTHETIC-S14
help[1]: "Run `artium-axi falcon-axi detection show <id>` for the full detection"
```

All private call directories settled after the read.
The entire rehearsal ran in a Linux network namespace with only loopback enabled; an external connection probe returned `ENETUNREACH`.
An unpackaged Python delivery bootstrap redirected the validated logical API hostname to local TLS delivery without changing the installed package or transport validation.
No live tenant calls occurred.
Raw command transcripts, package inventories, tarballs, bundle, source checkout, and runtime inputs are retained outside the repository.

The complete Phase A `npm run verify` gate passed with 1,503 tests across its cumulative suites: 1,345 ordinary-read tests, 18 native primitive tests, 87 guarded lifecycle tests, and 53 installation/discovery tests.
There were zero failures, skips, or cancellations.
Formatting, package-contract offline installation, architecture, generated freshness, 350 golden inputs, and 210 retained safety groups also passed their configured checks.
The inert release/CI examples were parsed separately to verify their tag namespace, disabled job, read-only workflow permissions, and absence of publishing jobs.
These results do not certify native Windows or replace the final TypeScript hosted release fold.

## Package-manager handover and rollback

The following are the exercised commands with rehearsal-local paths expressed as shell variables.
`NPM_PREFIX` is the isolated npm global prefix, `PYTHON_RUNTIME` the Python virtual environment, `CANDIDATE_TARBALL` the packed candidate, and `PYTHON_WHEEL` the retained wheel whose hash is above.
Use durable absolute paths when assigning those variables locally.

```sh
npm install --global --prefix "$NPM_PREFIX" --offline --ignore-scripts --no-audit --no-fund "$CANDIDATE_TARBALL"
export PATH="$NPM_PREFIX/bin:$PYTHON_RUNTIME/bin:$PATH"
command -v falcon-axi
falcon-axi setup hooks
npm uninstall --global --prefix "$NPM_PREFIX" --offline --ignore-scripts @knowttl/falcon-axi
uv pip uninstall --offline --python "$PYTHON_RUNTIME/bin/python" falcon-axi
uv pip install --offline --no-deps --python "$PYTHON_RUNTIME/bin/python" "$PYTHON_WHEEL"
command -v falcon-axi
falcon-axi --version
falcon-axi setup hooks
```

The retained runtime already contains the dependencies installed from the frozen Python requirements.
`--no-deps` restores only the exact wheel into that runtime, not an arbitrary fresh environment.
Restore Artium's matching lockfiles, Python runtime, schema, source pin, and generated inventory together before routing calls to it.
Verify the emitted hook by executing the command actually present in the agent settings.
Existing config, SecretRefs, and RTR journal formats are unchanged by this transition.

An installation managed by `uv tool` instead uses `uv tool uninstall falcon-axi` during handover and `uv tool install --offline "$PYTHON_WHEEL"` for restoration with the retained dependency cache.
Those `uv tool` commands are operational guidance, not the package-manager path exercised in this Linux rehearsal.
Native Windows still needs separate installation, `Get-Command falcon-axi -All`, emitted-hook, and real local Artium evidence against the exact preserved layout.
The known old Python executable-discovery issue is not claimed fixed by TypeScript changes.
No Windows workaround is certified by the POSIX evidence.

## Inert release proposal

The proposed first TypeScript prerelease is `@knowttl/falcon-axi@1.0.0-rc.1` on a distinct `next` channel, followed by a separately reviewed `1.0.0` default-channel transition.
The package remains `private: true` at the existing candidate version during Phase A.
Version, channel, package-name availability, and publishing authority must be confirmed before preparing the publishable Phase B artifact.
No npm tag is created here.
The compiled package allowlist, native prebuild provenance, clean offline installation, bin entry points, credential schema, and admission metadata remain enforced by `npm run verify`.
`npm pack --dry-run --offline --ignore-scripts --json` inspects the proposed contents without publishing.
The Phase B handoff must retain the final full source SHA, runtime and lock hashes, exact `npm pack` SHA-512 integrity and SHA-1 shasum, and complete file list after its final metadata changes.

The adjacent [release-please example](release-please-config.example.json) proposes a Node release strategy with a distinct `npm-v` tag namespace.
The adjacent [CI example](typescript-ci.example.yml) proposes the offline verification job, with its job explicitly disabled.
Both examples live outside `.github/workflows` and are inert review material.
The existing Python release workflow is unchanged on the migration branch and Python `main`.
The cutover must disable its publishing jobs before merging, and must not enable any npm publishing workflow.
Synchronizing the leaf `src/version.ts` with the package version and regenerated metadata is required in any future release change.

## Separate cutover review

After Phase A merges into `migration/typescript`, prepare a new branch from the then-current Python `main` for the separate Phase B PR.
Create a normal commit whose tree equals the reviewed migration tree after its reviewed cutover preparation, including removal of the Python implementation and inactive publishing automation.
Do not force-push `main`, delete branches, or rewrite existing tags.
Before opening that PR, create and push one new annotated tag `python-final-v0.9.0` on the last Python main commit, provided that the version is still 0.9.0 and the tag does not already exist.
If either has changed, recapture the version and choose a fresh matching tag for review; never move or reuse a tag.
The PR body must record the Python commit, reviewed migration commit/tree, new tag, tree equality check, and validation evidence.
Use `--base-branch main` for that separate no-mistakes run, with one review round and the offline verification plan.

Merge the cutover with a merge commit so that a reviewed `git revert -m 1 <cutover-merge>` can restore the Python tree while preserving history.
Do not execute that revert or change registry tags as part of preparation.
Stop with the ready-to-publish handoff after the cutover PR is green.
The first npm publication is performed manually from merged `main`.

Only after that publication is confirmed, prepare the final notice-only PyPI release from the preserved Python lineage through its existing Python release-please and Trusted Publishing path.
That release changes the version and README/notice to point to `@knowttl/falcon-axi`, without code changes or an automatic Node installer.
If its existing workflow cannot run from the preserved lineage, report the required release-branch/workflow authorization before proceeding.
Existing PyPI releases remain installable, and no support end date is invented.
