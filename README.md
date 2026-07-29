# falcon-axi

An agent-facing CLI for reading the CrowdStrike Falcon platform from the shell, built to the
[AXI](https://agentskills.io) standard for CLI tools that autonomous agents drive through shell execution.

## Status: design stage

**No implementation exists yet.**
This repository currently contains the v1 design and nothing else.
There is no `src/`, no published package, and no runnable command.

The design is at [`docs/design/v1.md`](docs/design/v1.md).
It is the authority for the command surface, the security boundary, auth and tenancy, output shape, and the
API-client decision, and every factual claim in it is cited to a source.

The planned local required-check set is offline-only and uses wholly synthetic fixtures.
Once implementation begins, one local `npm run verify` entry point will run that full set.
Manual live smoke tests require a read-scoped Falcon credential, never persist responses, stay outside the
required check, and never run automatically.
This project has no GitHub Actions workflow by captain directive; validation is local, and adding a workflow
requires the captain to lift that directive.

## Read-only

**falcon-axi v1 is read-only.**
It requires only CrowdStrike read permissions, and it implements no write, create, update, delete, execute,
containment, quarantine, release, response, or otherwise mutating operation.

This is an architectural invariant, not a default posture.
It is enforced at the transport layer through a closed registry of read operations rather than by convention,
and the excluded capability classes are named explicitly in the design.
See `docs/design/v1.md` §0, §1.5, §3, and §4.

The registered operations require only `Alerts:read`, `Hosts:read`, and `Vulnerabilities:read`.
Whether member-CID token minting additionally requires `Flight Control:read` remains an explicitly unresolved
question in `docs/design/v1.md` §17.7.
A falcon-axi release that asks for a write scope is wrong.

## Planned v1 surface

Three read domains: detections, hosts, and vulnerabilities, plus auth, scope, and setup helpers.
See `docs/design/v1.md` §1 for what ships, what is deferred, and why.

## Relationship to falcon-mcp

[`CrowdStrike/falcon-mcp`](https://github.com/CrowdStrike/falcon-mcp) is used as a behavioral, domain, scope,
FQL, credential, and test reference only.
It is not a fork base, not a dependency, and not part of falcon-axi at runtime.

## License

Not yet chosen.
