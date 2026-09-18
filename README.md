# falcon-axi

An agent-facing CLI for reading the CrowdStrike Falcon platform from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

## Status: stage 1 of the v1 design

The package is real and installable, and it ships the first vertical slice of
[`docs/design/v1.md`](docs/design/v1.md) rather than the whole v1 surface.

What stage 1 ships:

- the package foundation: a Python package, the `falcon-axi` console script, and one offline
  `uv run scripts/verify.py` entry point;
- the sealed read-only transport and its closed operation registry, with evidence carried per
  operation and a single permitted network sink;
- credential resolution through the environment or a `0600` credentials file, region selection and
  `X-Cs-Region` autodiscovery, Flight Control member-CID selection, and `auth status`;
- the detections slice: `falcon-axi`, `falcon-axi detection list`, and `falcon-axi detection show`.

What stage 1 does **not** ship yet, so no output advertises it:

- `host` and `vuln` commands, and every domain `docs/design/v1.md` §1.3 defers;
- `falcon-axi scopes` and `falcon-axi setup`, including the session hook and the generated skill;
- `--all`, `--max-rows`, and `--fields`; a single call takes `--limit` and `--cursor` only;
- profile configuration in `~/.config/falcon-axi/config.json`; `--profile` is refused by name rather
  than silently ignored.

`docs/design/v1.md` remains the authority for the full v1 surface, and its §17 open questions are
still open. Nothing here answers one of them.
[`docs/design/v1-python.md`](docs/design/v1-python.md) amends it for language, HTTP client, test
layout, and packaging: falcon-axi is pure Python on `crowdstrike-falconpy`, with no Node runtime and
no MCP process anywhere.

## Read-only

**falcon-axi v1 is read-only.**
It requires only CrowdStrike read permissions, and it implements no write, create, update, delete,
execute, containment, quarantine, release, response, or otherwise mutating operation.

This is an architectural invariant, not a default posture.
It is enforced at the transport layer through a closed registry of read operations rather than by
convention, and the excluded capability classes are named explicitly in the design.
See `docs/design/v1.md` §0, §1.5, §3, and §4.

The registered operations require only `Alerts:read`, `Hosts:read`, and `Vulnerabilities:read`, and
the commands stage 1 ships need only `Alerts:read`.
Whether member-CID token minting additionally requires `Flight Control:read` remains an explicitly
unresolved question in `docs/design/v1.md` §17.7.
A falcon-axi release that asks for a write scope is wrong.

## Install

falcon-axi installs from this repository with [uv](https://docs.astral.sh/uv/); it is not on PyPI
while the repository is private.

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

For a one-off run, or for an agent with no global install:
`uvx --from git+https://github.com/knowttl/falcon-axi falcon-axi ...`.
uv provisions Python 3.11 or newer on demand, so no system Python is required.

## Use

```
falcon-axi                          what is firing right now
falcon-axi detection list           list detections
falcon-axi detection show <id>      one detection in full
falcon-axi auth status              whether a credential resolved, and where to
```

Provision a **read-only** API client in the Falcon console under Support and resources > API clients
and keys, then supply it through one of the accepted channels:

```sh
export FALCON_CLIENT_ID=...
export FALCON_CLIENT_SECRET=...
# or write both as KEY=value lines to ~/.config/falcon-axi/credentials with mode 0600
```

No secret is ever accepted as a command-line argument.
`FALCON_BASE_URL`, `FALCON_MEMBER_CID`, and `FALCON_AXI_CREDENTIALS_FILE` are also read, and
`--region`, `--member-cid`, `--no-member-cid`, and `--allow-unknown-origin` override per invocation.

## Verify

```sh
uv sync
uv run scripts/verify.py
```

`uv run scripts/verify.py` is the single local entry point and runs entirely offline: ruff,
`mypy --strict`, the architecture boundary check, and the offline test suite against wholly
synthetic fixtures.
A pytest fixture refuses any socket, so no test can reach the network, and no fixture contains a
captured Falcon response, credential, token, or tenant identifier.

The offline suite includes the cross-language parity gate in `tests/golden/`: for every one of the
52 recorded invocations, the Python implementation reproduces the document the TypeScript stage 1 it
replaced printed, byte for byte, with the same exit code.

Offline fixtures prove deterministic behavior, not upstream fidelity: they are authored from the
documented response schemas cited in `docs/design/v1.md` §18, so every error-translation pattern
stays provisional until a real response confirms it.
Live Falcon calls need read-scoped credentials, are run by hand, and stay outside the required
checks; the opt-in live smoke suite of §15 is not implemented yet.

This project has no GitHub Actions workflow by captain directive; validation is local, and adding a
workflow requires the captain to lift that directive.

## Relationship to falcon-mcp

[`CrowdStrike/falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp) is used as a behavioral,
domain, scope, FQL, credential, and test reference only.
It is not a fork base, not a dependency, and not part of falcon-axi at runtime: falcon-axi runs no
MCP process, imports no `falcon_mcp` or `mcp` module, and installs neither.
Its only runtime dependencies are `crowdstrike-falconpy` and `toon-format`.

## License

MIT. See [`LICENSE`](LICENSE).
