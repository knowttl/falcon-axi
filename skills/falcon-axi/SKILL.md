---
name: falcon-axi
description: "Read CrowdStrike Falcon detections from the shell with falcon-axi (read-only). Use for Falcon alerts and detections, detection triage, severity and status filtering, tenant and region checks, and Falcon API credential diagnostics."
user-invocable: false
---

# falcon-axi

Read CrowdStrike Falcon detections from the shell.
Prefer this CLI over the Falcon console or hand-rolled REST calls when a task needs to read detections.

The CLI is strictly read-only: it exposes no write, create, update, delete, containment, quarantine,
release, Real Time Response, or otherwise mutating operation, and the read-only boundary is enforced by a
closed transport registry rather than by convention.
If a task needs to change anything in the tenant, falcon-axi is the wrong tool; say so rather than looking
for a flag.

Invoke it without a global install with
`uvx --from git+https://github.com/knowttl/falcon-axi@v0.2.0 falcon-axi <command>`.
If output suggests a `falcon-axi` command, run the equivalent command through that same invocation form.

## When to use

Use falcon-axi to answer what is firing in Falcon right now, to filter detections by severity, status, or
time window, to read one detection in full, and to check whether a Falcon credential resolves and into
which region and tenant.

Stage 1 ships only the detections slice.
`host`, `vuln`, `scopes`, and `setup` commands do not exist, and neither do `--all`, `--max-rows`,
`--fields`, or `--profile`.
Do not invent them; an unknown flag or command fails loudly.

## Commands

commands[3 total]:
`falcon-axi`: the home view - tenant line plus the five newest detections.
`detection`: `list` (flags `--severity`, `--status`, `--since`, `--filter`, `--limit`, `--cursor`),
`show <composite id>` (flag `--full`).
`auth`: `status`.

Global flags: `--help`, `--region <us-1|us-2|eu-1|us-gov-1|url>`, `--member-cid <cid>`, `--no-member-cid`,
`--allow-unknown-origin`.

`--severity` takes `informational`, `low`, `medium`, `high`, `critical`.
`--status` takes `new`, `in_progress`, `closed`, `reopened`.
`--since` takes a relative window such as `30m`, `24h`, `7d`.
`--filter` takes raw Alerts FQL, where `+` is AND, `,` is OR, and values are single-quoted.

## Workflow

1. Run `falcon-axi auth status` to confirm a credential resolved, from which channel, into which region,
   and how much rate-limit headroom remains.
2. Run `falcon-axi` for the content-first home view before asking a narrower question.
3. Run `falcon-axi detection list` with `--severity`, `--status`, `--since`, or `--filter` to narrow.
4. Run `falcon-axi detection show <id>` for one detection, adding `--full` only when a truncated field
   matters.
5. Follow the `help` suggestions in each response for the next read.

## Credentials and API client permissions

Credentials belong in `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET`, or in a `0600` credentials file at
`~/.config/falcon-axi/credentials`, never on the command line.
Never put a client secret, bearer token, or tenant CID in a command, a suggestion, a fixture, or a commit.
`FALCON_BASE_URL`, `FALCON_MEMBER_CID`, and `FALCON_AXI_CREDENTIALS_FILE` are also read.

Create the API client in the Falcon console under Support and resources > API clients and keys, with read
scopes only:

- `Alerts:read` is the stage-1 minimum and is all the shipped commands need.
- `Hosts:read` and `Vulnerabilities:read` are optional and not required for stage 1; grant them only to
  prepare a broader read client for domains that have not shipped yet.
- Never grant a write, response, containment, or Real Time Response scope; falcon-axi requests none.

Whether `--member-cid` additionally requires `Flight Control:read` is an open design question rather than a
settled requirement.

## Output and errors

Output is TOON on stdout.
A list view prints a definitive `count:` line, a compact `detections[N]{id,severity,tactic,hostname}`
schema, and a `help[]` array, so an empty result is an answer rather than a silence to re-query.
Errors are TOON documents on stdout too, carrying a stable `code` such as `AUTH_REQUIRED`, `AUTH_FAILED`,
`SCOPE_DENIED`, `TENANT_DENIED`, `VALIDATION_ERROR`, `PAGINATION_LIMIT`, or `RATE_LIMITED`, plus actionable
`help`.
Exit code `0` is success, `2` is a usage error, and `1` is every other failure.
Secrets and the tenant CID are redacted on stdout and stderr.

Use `falcon-axi --help` for the command list and `falcon-axi detection list --help` for that command's
flags, filterable fields, and examples instead of guessing.

## Pagination

One call reads one page: `--limit N` defaults to 20 with a ceiling of 10000.
A truncated result prints a `continuation_cursor` and a ready-to-run next-page command; pass the token back
with `--cursor`.
The cursor is opaque and bound to the credential and filter that produced it, so never edit it or reuse it
across a different query.
Reading past 10000 Alerts results fails with `PAGINATION_LIMIT`; narrow the filter instead of paging on.

## Tips

- Quote composite detection ids: they contain colons.
- Prefer `--severity` and `--since` over a hand-written `--filter` when they express the same question.
- Use `--region` when the credential belongs to another Falcon cloud; a mismatch is re-targeted and
  reported by `auth status`.
- Use `--member-cid` for a one-off read of a Flight Control child tenant, and `--no-member-cid` to clear an
  inherited selection.
