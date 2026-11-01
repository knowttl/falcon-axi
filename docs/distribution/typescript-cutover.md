# TypeScript cutover review

This Phase B tree replaces the Python implementation with the reviewed TypeScript implementation from merged migration commit `060cead47e49b19e27cbe83dd6c0811ff73be11a`.
Phase A was reviewed in [the distribution preparation PR](https://github.com/knowttl/falcon-axi/pull/136).
The imported tree initially matched that commit exactly: `0dd4d00fa375a115d080c2dbc38e1ec6865be182`.
The cutover preparation then removes `falcon_axi`, Python packaging and build scripts, updates distribution guidance, and deactivates publishing automation.
The final cutover tree is reviewed by the separate PR into `main`.

The cutover branch starts from Python `main` commit `dd9fa40569912587794223f3042513eec1f61ff6`, the 0.9.0 release.
It uses a normal tree-replacement commit, without force-pushing `main` or deleting the migration branch.
Before opening the cutover PR, preserve that Python commit with a new annotated `python-final-v0.9.0` tag.
Never move or reuse an existing tag.
Merge the cutover with a merge commit so that a separately reviewed `git revert -m 1 <cutover-merge>` restores the Python tree and preserves history.

## Package and automation

The proposed npm artifact is `@knowttl/falcon-axi@1.0.0-rc.1`, exposing `falcon-axi` and `falcon-axi-hook`, with Node 24.11.0 or newer within Node 24.
`publishConfig` selects public access and the distinct `next` prerelease channel.
The package is prepared for a manual publication, and this change performs no publication or npm tag operation.
The version leaf, package metadata and lockfile agree; generated agent examples use `@next` until a separate reviewed stable transition.
The existing Python release tags and PyPI artifacts remain installable.

CI installs the locked npm dependency graph and runs `npm run verify` with synthetic network isolation.
Both the release-please and publish jobs have unconditional false guards.
The inactive Node release-please proposal uses the `npm-v` namespace; no automation can create a release or publish a package in this tree.
The retained release manifest still records the last Python release; it is inert until a separate release-automation review reconciles it with the manual npm release.
The dormant PyPI publishing steps are preserved as historical workflow content; the runnable Python release path remains in the preserved Python lineage.

The `.py` files under `tests/offline`, `tests/packaged`, and `tests/support` are frozen comparison sources.
The TypeScript ledger reads their pinned bytes and source symbols to retain the 210 safety requirements.
They are not executed, are not included in the npm tarball, and do not require a Python runtime.
All 350 golden definitions and expected documents remain unchanged, with the existing release-version substitution applying to version output.
The runtime package contains compiled JavaScript, the schema and admission metadata, native prebuilds with provenance, the skill, README, and license.

## Evidence and remaining gates

The [Phase A rollback record](typescript-transition.md) owns the immutable Python artifact, matched Artium lock/runtime/schema/inventory hashes, restored hook, command-name selection, and real local Artium synthetic read.
The configured native gate and affected cutover checks must pass before requesting cutover approval.
The complete native `npm run verify` gate passed at `74cac754ebed02a6c2a7e81937292fcd3f25c845`: 1,507 tests passed with zero failures, skips or cancellations, including package installation, architecture, generated freshness, 350 goldens and 210 retained safety groups.
The seven focused S13 hosted release-candidate cases passed against the exact `1.0.0-rc.1` tarball with SHA-256 `5e15efd970a47d7257717fe0cef19f576e5e728e6ab34bac3bab845f23cfe48a`.
They exercise PATCH same-identity secret retention and changed-identity refusal, concurrent private profiles, bounded stdin and upload refusal, the 30-second native deadline, the 65-second host budget, and disconnect cleanup.
Audit assertions correlate completed requests with the public response request identifier, rather than selecting unrelated background health events.
The frozen local Artium fixture is `fc38f47ae671334ed8c6eef043fd6f1c41fb7312`, with the package lock, Node inventory and schema matching the installed artifact.
Its unpackaged launcher adds child-PID observation for process-group settlement; no production Artium behavior or deployed host was changed.
The schema SHA-256 is `adb248794413a7b853e36a4a75b4a53bd7f9e6dade8be040d39165f4d926ee30` and the Node 24.14.0 runtime SHA-256 is `e237a2839d0cbdc9a9a2adda1a184afc0f5b20306ffbe923af5686550472d8a8`.
This focused hosted result does not claim the complete cumulative hosted suite was rerun.
Native Windows certification remains pending.
The hosted TypeScript release-candidate fold is separate from the recorded Python rollback proof; any unexecuted host scenarios remain explicitly pending rather than inferred from native results.
No live tenant calls are authorized or performed.

Stop after the cutover PR is ready, with its full head SHA, exact tarball SHA-512 integrity and SHA-1 shasum, and complete file inventory.
The first npm publication is a manual action from merged `main`, after the separate merge decision and package permission check.
Only after that publication is confirmed may the notice-only final PyPI release be prepared from the preserved Python lineage through its existing release path.
No Python code changes, automatic Node installer, release deletion, or invented support end date are part of that notice.
If the existing Python workflow requires a release branch or credentials unavailable to the worker, report the exact requirement before proceeding.
