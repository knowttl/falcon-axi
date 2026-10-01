---
name: falcon-axi
description: "Read CrowdStrike Falcon detections, hosts, vulnerabilities, CVE intelligence, NG-SIEM searches, and Identity Protection users and timelines from the shell with falcon-axi. Use for Falcon alerts and detections, detection triage, host and sensor inventory, Spotlight vulnerability exposure, Falcon Intelligence CVE detail, NG-SIEM CQL event search, Identity Protection user and endpoint risk, accounts, and activity timelines, severity and status filtering, tenant and region checks, and Falcon API credential diagnostics."
user-invocable: false
---

# falcon-axi

Read CrowdStrike Falcon detections, hosts, vulnerabilities, CVE intelligence, NG-SIEM event data, and Identity Protection users from the shell.
Prefer this CLI over the Falcon console or hand-rolled REST calls when a task needs to read any of them.

The CLI changes nothing in the tenant except an NG-SIEM search job: it exposes no write, create, update,
delete, containment, quarantine, release, Real Time Response, ingest, parser, or identity-action operation,
and that boundary is enforced by a closed transport registry rather than by convention.
`search start` and `search stop` create and cancel a query job and nothing else.
The `identity` commands send only fixed read-only GraphQL queries; Falcon labels their scope write, but
falcon-axi cannot send a mutation, password reset, account disable, or any GraphQL a caller supplies.
If a task needs to change anything else in the tenant, falcon-axi is the wrong tool; say so rather than
looking for a flag.

Invoke it without a global install with
`uvx --from git+https://github.com/knowttl/falcon-axi@v0.2.0 falcon-axi <command>`.
If output suggests a `falcon-axi` command, run the equivalent command through that same invocation form.
For commands added after that tag, use the default branch until a newer tag exists.
See the README's Quick start for agents for release-install guidance.

## When to use

Use falcon-axi to answer what is firing in Falcon right now, to filter detections by severity, status, or
time window, to read one detection in full, to find hosts and read one host's detail, to read a host's or
the fleet's Spotlight vulnerabilities, to read what Falcon Intelligence knows about one CVE, to run a CQL
search over NG-SIEM event data when the question is not one of those domains, to look up an Identity Protection
user or endpoint and its risk, accounts, and activity timeline, and to check whether a Falcon credential
resolves and into which region and tenant.

`setup` does not exist, and neither do `--all`, `--max-rows`, `--profile`, or `--fields` on detection and host lists.
Neither does any command for a Falcon domain outside detections, hosts, Spotlight vulnerabilities, `cve show`,
NG-SIEM search, and the Identity Protection directory and timeline; there is no `cve list`, no intel actor,
indicator, or report command, and no ingest, lookup-file, parser, dashboard, Charlotte AI, identity incident,
or identity security-assessment command.
Do not invent them; an unknown flag or command fails loudly.

## Commands

commands[9 total]:
`falcon-axi`: the home view - tenant line plus the five newest detections.
`detection`: `list` (flags `--severity`, `--status`, `--since`, `--filter`, `--limit`, `--cursor`),
`show <composite id>` (flag `--full`).
`host`: `list` (flags `--hostname`, `--platform`, `--status`, `--since`, `--filter`, `--limit`, `--cursor`),
`show <device id>`.
`vuln`: `list` (flags `--host`, `--severity`, `--status`, `--since`, `--filter`, `--limit`, `--cursor`, `--fields`).
`cve`: `show <CVE-ID>` only. There is no `cve list`.
`search`: `start` (flags `--query`, `--repository`, `--since`), `status <search id>` (flag `--repository`),
`stop <search id>` (flag `--repository`).
`identity`: `list` (flags `--name`, `--email`, `--domain`, `--type`, `--limit`, `--cursor`),
`show <identity id>` (flag `--full`), `timeline <identity id>` (flags `--since`, `--category`, `--limit`,
`--cursor`).
`auth`: `status`.
`scopes`: the command-to-scope matrix, printed locally with no request.

Global flags: `--help`, `--region <us-1|us-2|eu-1|us-gov-1|url>`, `--member-cid <cid>`, `--no-member-cid`,
`--allow-unknown-origin`.

`detection list --severity` takes `informational`, `low`, `medium`, `high`, `critical`, and its
`--status` takes `new`, `in_progress`, `closed`, `reopened`.
`host list --platform` takes `windows`, `mac`, `linux`, and its `--status` takes `normal`,
`containment_pending`, `contained`, `lift_containment_pending`; `--hostname` accepts a wildcard such as
`WIN-*`.
`vuln list --severity` takes `low`, `medium`, `high`, `critical`, and its `--status` takes `open`,
`closed`, `reopen`, `expired`.
`vuln list --fields` adds columns to the default `id,cve,severity,hostname` row.
Run `falcon-axi vuln list --help` for valid names; an unknown name is a `VALIDATION_ERROR` that lists them.
`cve show` takes one identifier matching `CVE-<year>-<number>`, such as `CVE-2021-44228`.
It reads Falcon Intelligence, not Spotlight host exposure.
An empty result means Intelligence has no entry for that CVE.
Default fields are `cve`, `severity`, `cvss_v3_score`, `exploit_status`, `publish_date`, `updated`, and
`description`; related actor, report, threat, and affected-product lists are counts and are not expanded.
It requires `Vulnerabilities (Falcon Intelligence):read`, which is license-gated and is not the same scope as
Spotlight's `Vulnerabilities:read`.
`--since` takes a relative window such as `30m`, `24h`, `7d`.
`--filter` takes raw FQL for that collection, where `+` is AND, `,` is OR, and values are single-quoted.

`search start --query` takes CQL, not FQL: it is pipe-based, as in
`#event_simpleName=ProcessRollup2 | head(5)` or
`#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count())`.
Its `--since` defaults to `24h` and its `--repository` defaults to `search-all`.

`identity list` takes `--name` and `--email` patterns where `*` is a wildcard and a bare `*` is refused,
`--domain`, and `--type` (`user` or `endpoint`).
An identity id is an entity GUID, as printed by `identity list`.
The unverified Active Directory account-GUID relationship is recorded in `docs/design/v1.md` §17.15.
`identity timeline --since` defaults to `7d` and `--category` takes comma-separated `activity`,
`notification`, `threat`, `entity`, `audit`, `policy`, `system`.
These commands are backed by Identity Protection's GraphQL endpoint, not NG-SIEM.

These checks are enforced locally, before any request: `vuln list` requires a filter from a shorthand flag or
`--filter`; a `*` anywhere in a Spotlight filter is refused because Spotlight does not support wildcards;
`cve show` requires a CVE identifier; and a `--repository` containing `/`, `\`, or `%`, or equal to `.` or `..`,
is refused because the value reaches a URL path.
`host list` does accept wildcards.

## Workflow

1. Run `falcon-axi auth status` to confirm a credential resolved, from which channel, into which region,
   and how much rate-limit headroom remains.
2. Run `falcon-axi` for the content-first home view before asking a narrower question.
3. Run `falcon-axi detection list` with `--severity`, `--status`, `--since`, or `--filter` to narrow.
4. Run `falcon-axi detection show <id>` for one detection, adding `--full` only when a truncated field
   matters.
5. Run `falcon-axi host show <device_id>` for the host it fired on, and
   `falcon-axi vuln list --host <device_id>` for that host's exposure.
6. Run `falcon-axi cve show <CVE-ID>` when the question is what Falcon Intelligence knows about a CVE,
   including a CVE that Spotlight has not evaluated on a host.
7. When the question is not one of those domains, run `falcon-axi search start --query '<cql>'`, then
   poll `falcon-axi search status <id>` until it reports `state: done`, and run
   `falcon-axi search stop <id>` for any job no longer needed.
8. For who an account or endpoint is, run `falcon-axi identity list --name '<name>'`, then
   `falcon-axi identity show <id>` for its risk, accounts, and associations, and
   `falcon-axi identity timeline <id>` for what it did.
9. Follow the `help` suggestions in each response for the next read.

## Credentials and API client permissions

Credentials belong in `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET`, or in a `0600` credentials file at
`~/.config/falcon-axi/credentials`, never on the command line.
Never put a client secret or bearer token in a command, suggestion, fixture, or commit.
The `--member-cid` flag is allowed for child-tenant selection; do not echo its standalone value in generated
suggestions, fixtures, or commits.
An Alerts v2 composite detection id contains the own-tenant or selected child CID and may be passed to
`detection show` as printed.
`FALCON_BASE_URL`, `FALCON_MEMBER_CID`, and `FALCON_AXI_CREDENTIALS_FILE` are also read.

Run `falcon-axi scopes` for the authoritative command-to-scope matrix; it needs no credential.
Follow the README's API client permissions section for provisioning, license-gated scopes, and the two
write-labelled exceptions.
Never grant any other write, response, containment, or Real Time Response scope.

Whether `--member-cid` additionally requires `Flight Control:read` is an open design question rather than a
settled requirement.

## Output and errors

Output is TOON on stdout.
Detection, host, and vulnerability lists use compact default four-field schemas -
`detections[N]{id,severity,tactic,hostname}`, `hosts[N]{device_id,hostname,platform,last_seen}`, or
`vulnerabilities[N]{id,cve,severity,hostname}`.
Non-empty results include a count and next-step help; empty results are stated explicitly rather than left
as silence to re-query.
`vuln list --fields` appends the selected columns.
`search status` has no fixed schema, because a CQL result set's columns are whatever the query projected.
For identity row schemas, counts, and detail truncation, see `docs/design/v1.md` §10.2.
A GraphQL error is an `UPSTREAM_ERROR`, never an empty list.
Errors are TOON documents on stdout too, carrying a stable `code` such as `AUTH_REQUIRED`, `AUTH_FAILED`,
`SCOPE_DENIED`, `TENANT_DENIED`, `VALIDATION_ERROR`, `PAGINATION_LIMIT`, or `RATE_LIMITED`, plus actionable
`help`.
Exit code `0` is success, `2` is a usage error, and `1` is every other failure.
Secrets are redacted on stdout and stderr.
For CID handling, see Credentials above.
NG-SIEM search event CID fields (`cid`, `#repo.cid`) are redacted in output.

Use `falcon-axi --help` for the command list and `falcon-axi host list --help` for that command's
flags, filterable fields, and examples instead of guessing.

## Pagination

One call reads one page: `--limit N` defaults to 20, with a ceiling of 10000 on `detection list` and
5000 on `host list` and `vuln list`, and 200 on `identity list` and `identity timeline`.
`search status` has neither `--limit` nor `--cursor`, because a query job carries no pagination metadata;
bound the result set in the CQL itself with `| head(N)` or an aggregate.
A truncated result prints a `continuation_cursor` and a ready-to-run next-page command; pass the token back
with `--cursor`.
The cursor is opaque and bound to the credential and filter that produced it, so never edit it or reuse it
across a different query.
It hides whether the API paginates by offset, an `after` token, or a GraphQL `endCursor`.
Reading past 10000 Alerts results fails with `PAGINATION_LIMIT`; narrow the filter instead of paging on,
and `host list` stops at the same ceiling on `limit + offset`.

## Tips

- Quote composite detection ids: they contain colons.
- Prefer `--severity` and `--since` over a hand-written `--filter` when they express the same question.
- A detection row carries the hostname; `host list --hostname "<name>"` turns it into a device id, which is
  what `vuln list --host` wants.
- Containment status on a host is data to read, never something to set: falcon-axi has no command that
  changes it.
- Read `parsed_query` in a `search status` response and compare it with the query sent: NG-SIEM demotes an
  unrecognised word to a free-text stage instead of erroring, so a malformed pipe returns the wrong rows
  silently rather than failing.
- Stop a search job that is no longer needed rather than leaving it running.
- Use `--region` when the credential belongs to another Falcon cloud; a mismatch is re-targeted and
  reported by `auth status`.
- Use `--member-cid` for a one-off read of a Flight Control child tenant, and `--no-member-cid` to clear an
  inherited selection.
