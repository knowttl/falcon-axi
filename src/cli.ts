#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { authenticate, type Session } from "./auth.js";
import { CliError } from "./core.js";
import { resolveCredential, setupHelp, type Credential } from "./credentials.js";
import { DEFAULT_LIMIT, QUERY_CEILING, listDetections, showDetection } from "./detection.js";
import { SEVERITIES, STATUSES, type DetectionQuery } from "./fql.js";
import { assertTrustedOrigin, REGIONS, resolveBaseUrl } from "./origin.js";
import { maskCid, raw, render } from "./render.js";
import { httpTransport } from "./transport/index.js";
import type { Transport } from "./transport/types.js";
import { VERSION } from "./version.js";

const DESCRIPTION = "Read CrowdStrike Falcon detections from the shell (read-only)";
const HOME_ROWS = 5;

type Command = "home" | "detection list" | "detection show" | "auth status";

type Flags = Readonly<Record<string, string | boolean>>;

type Parsed = Readonly<{ command: Command; flags: Flags; positionals: readonly string[] }>;

const GLOBAL_FLAGS = ["help", "region", "allow-unknown-origin", "member-cid", "no-member-cid"] as const;

const COMMAND_FLAGS: Readonly<Record<Command, readonly string[]>> = {
  home: [],
  "detection list": ["filter", "severity", "status", "since", "limit", "cursor"],
  "detection show": ["full"],
  "auth status": [],
};

const VALUE_FLAGS = new Set(["region", "member-cid", "filter", "severity", "status", "since", "limit", "cursor"]);

/**
 * No secret ever travels through argv (docs/design/v1.md §5.3).
 * The member CID is a documented exception to this guard because it is an identifier rather than a
 * credential, and the guard pattern deliberately does not match it.
 */
function flagGuard(name: string): void {
  if (/(secret|password|token|key|passphrase)/i.test(name)) throw new Error(`secret-shaped flag --${name} is forbidden`);
}
for (const name of [...GLOBAL_FLAGS, ...Object.values(COMMAND_FLAGS).flat()]) flagGuard(name);

function validFlags(command: Command): string[] {
  return [...GLOBAL_FLAGS, ...COMMAND_FLAGS[command]].map(name => `--${name}`);
}

function unknownFlag(name: string, command: Command): CliError {
  const valid = validFlags(command);
  const guess = valid.find(candidate => candidate.slice(2).startsWith(name) || name.startsWith(candidate.slice(2, 5)));
  return new CliError("VALIDATION_ERROR", `unknown flag --${name} for \`${command}\``, [
    ...(guess ? [`Did you mean ${guess}?`] : []),
    `valid flags for \`${command}\`: ${valid.join(", ")}`,
  ]);
}

export function parse(argv: readonly string[]): Parsed {
  let command: Command = "home";
  let index = 0;
  if (argv[0] === "detection") {
    if (argv[1] === "list" || argv[1] === "show") {
      command = `detection ${argv[1]}` as Command;
      index = 2;
    } else {
      throw new CliError("VALIDATION_ERROR", `unknown detection subcommand ${argv[1] ?? ""}`.trim(), [
        "valid detection subcommands: list, show",
      ]);
    }
  } else if (argv[0] === "auth") {
    if (argv[1] === "status") {
      command = "auth status";
      index = 2;
    } else {
      throw new CliError("VALIDATION_ERROR", `unknown auth subcommand ${argv[1] ?? ""}`.trim(), ["valid auth subcommands: status"]);
    }
  } else if (argv[0] !== undefined && !argv[0].startsWith("-")) {
    throw new CliError("VALIDATION_ERROR", `unknown command ${argv[0]}`, [
      "valid commands: detection list, detection show, auth status",
      "Run `falcon-axi --help` for the command list",
    ]);
  }

  const flags: Record<string, string | boolean> = {};
  const positionals: string[] = [];
  for (; index < argv.length; index++) {
    const token = argv[index] as string;
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const [name, inline] = token.slice(2).split(/=(.*)/s, 2) as [string, string | undefined];
    if (name === "profile") {
      throw new CliError("VALIDATION_ERROR", "profile configuration is not implemented in stage 1", [
        "Select a region with `--region` and a tenant with `--member-cid` or FALCON_MEMBER_CID",
      ]);
    }
    if (!(GLOBAL_FLAGS as readonly string[]).includes(name) && !COMMAND_FLAGS[command].includes(name)) throw unknownFlag(name, command);
    if (VALUE_FLAGS.has(name)) {
      const value = inline ?? argv[++index];
      if (value === undefined || value === "" || value.startsWith("--")) throw new CliError("VALIDATION_ERROR", `--${name} requires a value`);
      flags[name] = value;
    } else {
      flags[name] = true;
    }
  }
  if (flags.help) return { command, flags, positionals };
  if (flags["member-cid"] && flags["no-member-cid"]) {
    throw new CliError("VALIDATION_ERROR", "--member-cid and --no-member-cid cannot be combined", [
      "Use `--member-cid <cid>` to select a child tenant or `--no-member-cid` to clear an inherited selection",
    ]);
  }
  if (command === "detection show" && positionals.length !== 1) {
    throw new CliError("VALIDATION_ERROR", "detection show requires exactly one detection identifier", [
      "Run `falcon-axi detection list` to see current detection identifiers",
    ]);
  }
  if (command !== "detection show" && positionals.length) {
    throw new CliError("VALIDATION_ERROR", `\`${command}\` accepts no positional arguments`, [`valid flags for \`${command}\`: ${validFlags(command).join(", ")}`]);
  }
  if (flags.limit !== undefined) limitOf(flags);
  return { command, flags, positionals };
}

function limitOf(flags: Flags): number {
  if (flags.limit === undefined) return DEFAULT_LIMIT;
  const value = Number(flags.limit);
  if (!Number.isInteger(value) || value < 1 || value > QUERY_CEILING) {
    throw new CliError("VALIDATION_ERROR", `--limit must be an integer from 1 to ${QUERY_CEILING}`, [
      `${QUERY_CEILING} is the documented Alerts query ceiling`,
      `Run \`falcon-axi detection list --limit ${DEFAULT_LIMIT}\` for the default page`,
    ]);
  }
  return value;
}

function str(value: string | boolean | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function queryOf(flags: Flags): DetectionQuery {
  return { filter: str(flags.filter), severity: str(flags.severity), status: str(flags.status), since: str(flags.since) };
}

/** Replays every non-sensitive flag of this invocation into a next-page suggestion (§7.2). */
function suggestionFor(command: Command, flags: Flags): string {
  const parts = [`falcon-axi ${command}`];
  for (const name of ["region", "filter", "severity", "status", "since", "limit"]) {
    const value = flags[name];
    if (typeof value === "string") parts.push(`--${name} ${/\s/.test(value) ? `"${value}"` : value}`);
  }
  if (flags["allow-unknown-origin"]) parts.push("--allow-unknown-origin");
  return parts.join(" ");
}

function memberCidOf(flags: Flags, env: NodeJS.ProcessEnv): string | undefined {
  if (flags["no-member-cid"]) return undefined;
  return str(flags["member-cid"]) ?? env.FALCON_MEMBER_CID ?? undefined;
}

function help(command: Command): string {
  if (command === "detection list") {
    return [
      "falcon-axi detection list [--severity <name>] [--status <name>] [--since <window>] [--filter <FQL>] [--limit N] [--cursor <token>]",
      "",
      `--severity   one of ${SEVERITIES.join(", ")}`,
      `--status     one of ${STATUSES.join(", ")}`,
      "--since      relative window such as 24h or 7d",
      "--filter     raw FQL; + is AND, `,` is OR, values are single-quoted, relative dates are lowercase",
      `--limit      rows in this call (default ${DEFAULT_LIMIT}, ceiling ${QUERY_CEILING})`,
      "--cursor     opaque continuation token from a previous call",
      "",
      "Filterable fields include severity_name, status, tactic, technique, created_timestamp, and device.hostname.",
      "Examples:",
      "  falcon-axi detection list --severity high --since 24h",
      "  falcon-axi detection list --filter \"severity_name:'Critical'+status:'new'\"",
      "",
      "This command is read-only and requires only Alerts:read.",
    ].join("\n");
  }
  if (command === "detection show") {
    return [
      "falcon-axi detection show <composite id> [--full]",
      "",
      "--full       print long fields such as the command line without truncation",
      "",
      "Example: falcon-axi detection show \"ldt:aid:1234\"",
      "",
      "This command is read-only and requires only Alerts:read.",
    ].join("\n");
  }
  if (command === "auth status") {
    return [
      "falcon-axi auth status",
      "",
      "Reports whether a credential resolved, from which channel, and which region it resolved to.",
      "No credential value, bearer token, or tenant CID is ever printed.",
    ].join("\n");
  }
  return [
    `falcon-axi ${VERSION} - ${DESCRIPTION}`,
    "",
    "Commands:",
    "  detection list            list detections from the Falcon Alerts collection",
    "  detection show <id>       the full detail for one detection",
    "  auth status               whether a credential resolved, and where to",
    "",
    "Global flags:",
    "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
    "",
    `Regions: ${Object.keys(REGIONS).join(", ")}`,
    "",
    "falcon-axi is read-only: it lists no mutating command and requires only Alerts:read for the",
    "commands stage 1 ships. Host and vulnerability domains are not implemented yet.",
  ].join("\n");
}

type Resolved = Readonly<{ session: Session; credential: Credential }>;

async function session(transport: Transport, flags: Flags, env: NodeJS.ProcessEnv): Promise<Resolved> {
  const credential = await resolveCredential(env);
  if (!credential) throw new CliError("AUTH_REQUIRED", "no Falcon credential found", setupHelp(env));
  const allowUnknownOrigin = Boolean(flags["allow-unknown-origin"]);
  const baseUrl = resolveBaseUrl({ region: str(flags.region), envBaseUrl: env.FALCON_BASE_URL });
  assertTrustedOrigin(baseUrl, allowUnknownOrigin);
  return {
    credential,
    session: await authenticate(transport, {
      credential,
      baseUrl,
      memberCid: memberCidOf(flags, env),
      allowUnknownOrigin,
    }),
  };
}

function tenantLine(active: Session): string {
  const region = active.region ?? "an unlisted Falcon cloud";
  const retarget = active.retargetedFrom ? ` (re-targeted from ${active.retargetedFrom})` : "";
  return active.memberCid
    ? `${region}${retarget} member CID ${maskCid(active.memberCid)}`
    : `${region}${retarget} (own CID unavailable)`;
}

async function authStatus(transport: Transport, flags: Flags, env: NodeJS.ProcessEnv): Promise<{ value: Record<string, unknown>; help: string[] }> {
  const credential = await resolveCredential(env);
  if (!credential) {
    return { value: { credential_resolved: false }, help: [...setupHelp(env)] };
  }
  const resolved = await session(transport, flags, env);
  const { limit, remaining } = resolved.session.rateLimit;
  return {
    value: {
      credential_resolved: true,
      credential_channel: credential.channel,
      ...(credential.path ? { credential_path: credential.path } : {}),
      tenant: raw(tenantLine(resolved.session)),
      scopes: raw("read-only client recommended; falcon-axi requests no write scope"),
      ...(limit !== undefined && remaining !== undefined ? { rate_limit: raw(`${remaining} of ${limit} requests remaining`) } : {}),
    },
    help: ["Run `falcon-axi detection list` to read detections with this credential"],
  };
}

async function homeView(transport: Transport, flags: Flags, env: NodeJS.ProcessEnv): Promise<{ stdout: string; exitCode: number }> {
  const head: Record<string, unknown> = { bin: process.argv[1] ?? "falcon-axi", description: DESCRIPTION };
  let resolved: Resolved;
  try {
    resolved = await session(transport, flags, env);
  } catch (error) {
    const known = error instanceof CliError ? error : new CliError("UNKNOWN", "an unexpected error occurred");
    return { stdout: render({ ...head, error: known.message, code: known.code, ...known.details }, known.help), exitCode: known.exitCode };
  }
  head.tenant = raw(tenantLine(resolved.session));
  const listed = await listDetections(transport, resolved.session, {
    query: {},
    limit: HOME_ROWS,
    credential: resolved.credential,
    suggestion: "falcon-axi detection list",
  });
  return {
    stdout: render({ ...head, ...listed.value }, [
      ...listed.help,
      "Run `falcon-axi detection list` to see more detections",
      "Run `falcon-axi auth status` to check the credential and region",
    ]),
    exitCode: 0,
  };
}

export async function run(
  argv: readonly string[],
  transport: Transport = httpTransport,
  env: NodeJS.ProcessEnv = process.env,
): Promise<{ stdout: string; exitCode: number }> {
  try {
    const parsed = parse(argv);
    if (parsed.flags.help) return { stdout: `${help(parsed.command)}\n`, exitCode: 0 };
    if (parsed.command === "home") return homeView(transport, parsed.flags, env);
    if (parsed.command === "auth status") {
      const status = await authStatus(transport, parsed.flags, env);
      return { stdout: render(status.value, status.help), exitCode: 0 };
    }
    const resolved = await session(transport, parsed.flags, env);
    const output =
      parsed.command === "detection list"
        ? await listDetections(transport, resolved.session, {
            query: queryOf(parsed.flags),
            limit: limitOf(parsed.flags),
            cursor: str(parsed.flags.cursor),
            credential: resolved.credential,
            suggestion: suggestionFor("detection list", parsed.flags),
          })
        : await showDetection(transport, resolved.session, parsed.positionals[0] as string, Boolean(parsed.flags.full));
    return { stdout: render(output.value, output.help), exitCode: 0 };
  } catch (error) {
    const known = error instanceof CliError ? error : new CliError("UNKNOWN", "an unexpected error occurred");
    return { stdout: render({ error: known.message, code: known.code, ...known.details }, known.help), exitCode: known.exitCode };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  run(process.argv.slice(2)).then(result => {
    process.stdout.write(result.stdout);
    process.exitCode = result.exitCode;
  });
}
