# Contributing

Install [uv](https://docs.astral.sh/uv/), then run the complete local verification gate:

```sh
uv sync
uv run scripts/verify.py
```

The gate runs Ruff, strict mypy, architecture checks, generated skill and documentation drift checks, and the offline pytest suite.
GitHub CI runs the same offline gate on pull requests and pushes to `main`.
The release workflow builds and publishes packages using PyPI Trusted Publishing.

## Tests and fixtures

All automated fixtures are wholly synthetic and carry provenance headers.
A pytest fixture refuses sockets, so the suite cannot contact Falcon.
Never commit credentials, tenant identifiers, captured responses, or personal data.
Commands accept a recorded transport only through the code-level test interface.

Run a focused check with `uv run pytest tests/offline/<test_file>.py -q`.
The recorded-invocation gate in `tests/golden/` preserves the output contract described in [the Python design](docs/design/v1-python.md#5-behavior-that-must-not-change-during-the-port).
Do not regenerate expected output to make a failure disappear.
Intentional behavior changes need a design explanation and a comment in the affected scenario.
Offline fixtures prove deterministic behavior; they do not establish tenant validation.

Canonical source: knowttl/bstack revision feeccb1e6f1ae119bf4c74277c8bad328b05afe8, skills/verification/references/testing.md.
<!-- BEGIN canonical test-quality rules -->
**Test quality.** Write and review every test against these rules.
Tests are never required first; a change is verified end to end against the behaviour the user expects.

1. Trust upstream invariants: do not test states that types, schemas or database constraints already rule out.
   Test invalid input only at the boundary that validates it.
2. Assert outcomes from an agreed source (spec, domain rule, ground-truth fixture), never values copied from what the code returns today.
3. Mock only true external boundaries, with schema-valid or recorded payloads.
   Never mock in-process code.
   Delete tests that only check how a mock was set up or called, unless that call is the requirement.
4. Test through the public interface: no private helpers, internal state or internal call counts.
5. Every assertion must be able to fail when the behaviour breaks: no existence-, type- or constant-only assertions.

Exempt: validation-boundary tests, contract tests against an agreed schema or recording, and regression tests that cite the bug they reproduce.
<!-- END canonical test-quality rules -->

## Generated documentation

```sh
uv run scripts/skill.py
uv run scripts/docs.py
uv run scripts/verify.py
```

Command declarations own the full command reference and generated skill references; the README summarizes command groups.
Edit their sources rather than generated content.
Every shipped command must appear in `docs/commands.md`, and every advertised command must exist.

## Architecture and review

Read the [design index](docs/design/README.md) before changing command behavior or implementation structure.
Preserve the [read-only boundary](docs/read-only.md), closed operation registry, and single network sink.
Each new endpoint needs the documented scope and first-party corroborating evidence in its registry entry.
Use conventional commit titles and keep pull requests focused on a reviewable behavior change.
Do not hand-edit the generated changelog.

## Releases

The release workflow uses release-please to prepare version and changelog updates.
Publishing a release builds the package and uploads it to PyPI using Trusted Publishing.
Keep release mechanics in the workflow and package metadata; install examples should not pin release versions.
