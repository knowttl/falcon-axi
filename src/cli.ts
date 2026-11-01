import { CliError } from "./core.js";
import {
  configPath,
  writeLogPath,
  loadProfiles,
  normalizeEnvironment,
  resolveCredential,
} from "./credentials.js";
import { authenticate } from "./auth.js";
import { resolveOrigin, REGIONS } from "./origin.js";
import { render, Raw, registerMemberCid } from "./render.js";
import { commands, DESCRIPTION } from "./metadata.js";
import { operation } from "./transport/operations.js";
import { parse, filterOf } from "./parser.js";
import { investigate } from "./investigation.js";
import { Domain, quote } from "./domain.js";
import { inventory } from "./inventory.js";
import { exposure } from "./exposure.js";
import { inspection } from "./inspection.js";
import inspectionCommands from "./inspection-commands.json" with { type: "json" };
import { homedir } from "node:os";
import { executableCommand, shellArgument } from "./executable.js";
import helpText from "./help.json" with { type: "json" };
import { VERSION } from "./version.js";
import { search } from "./search.js";
import { identity } from "./identity.js";
import { malquery } from "./malquery.js";
import searchHelp from "./search-help.json" with { type: "json" };
import { document } from "./transport/search-authority.js";
import { rtrRun, validateRtrInvocation } from "./rtr.js";
import { installHooks } from "./setup.js";
import { HOME_GUIDANCE, skillHint } from "./skill.js";
import { readOnly } from "./rtr-policy.js";

const description = DESCRIPTION;

export async function main(argv: string[], bin?: string): Promise<number> {
  if (argv.length === 1 && ["-v", "-V", "--version"].includes(argv[0]!)) {
    process.stdout.write(VERSION + "\n");
    return 0;
  }
  const started = performance.now();
  const controller = new AbortController();
  const cancel = (): void => controller.abort();
  process.once("SIGTERM", cancel);
  process.once("SIGINT", cancel);
  let activeFlags = new Map<string, string>();
  let memberCid: string | undefined;
  let home = false;
  let hostnameDeadline: AbortSignal | undefined;
  const homeHead = (): Record<string, unknown> => {
    const executable = executableCommand()
      .map((argument) =>
        process.platform !== "win32" && argument.startsWith(homedir() + "/")
          ? "~/" + shellArgument(argument.slice(homedir().length + 1))
          : shellArgument(argument),
      )
      .join(" ");
    return {
      bin: bin ?? executable,
      description,
    };
  };
  const contextualHelp = (help: readonly string[]): string[] => {
    const suffix =
      ["region", "config", "profile"]
        .flatMap((name) =>
          activeFlags.has(`--${name}`)
            ? [` --${name} ${quote(activeFlags.get(`--${name}`)!)}`]
            : [],
        )
        .join("") +
      ["allow-unknown-origin", "no-member-cid"]
        .filter((name) => activeFlags.has(`--${name}`))
        .map((name) => ` --${name}`)
        .join("");
    const result = help.map((item) =>
      item.replace(
        /`(falcon-axi .*)`/s,
        (_, command: string) => `\`${command}${suffix}\``,
      ),
    );
    if (memberCid && help.some((item) => /`falcon-axi /.test(item)))
      result.push(
        "Supply the same tenant selection used for this invocation when following these suggestions",
      );
    return result;
  };
  try {
    const invocation = parse(argv);
    const { command, flags } = invocation;
    activeFlags = flags;
    home = command.name === "home";
    memberCid = flags.get("--member-cid");
    if (flags.has("--help")) {
      if (command.name === "setup") {
        process.stdout.write(
          commands
            .filter((spec) => spec.name.startsWith("setup "))
            .map((spec) => spec.summary)
            .join("\n") + "\n",
        );
        return 0;
      }
      if (Object.hasOwn(searchHelp, command.name)) {
        process.stdout.write(
          searchHelp[command.name as keyof typeof searchHelp] + "\n",
        );
        return 0;
      }
      if (Object.hasOwn(helpText, command.name)) {
        process.stdout.write(
          helpText[command.name as keyof typeof helpText] + "\n",
        );
        return 0;
      }
      const lines = [
        `falcon-axi ${command.name === "home" ? `${VERSION} - ${description}` : command.name}`,
        "",
        "Commands:",
        ...commands
          .filter(
            (spec) =>
              command.name === "home" ||
              spec.name.startsWith(`${command.name} `),
          )
          .map((spec) => spec.summary),
        "",
        "Global flags:",
        "  --help, --region <name|url>, --allow-unknown-origin, --member-cid <cid>, --no-member-cid",
        "  --config <path>, --profile <name>",
        "",
        `Regions: ${Object.keys(REGIONS).join(", ")}`,
        ...(command.name === "home"
          ? [
              "",
              "RTR execution requires profile opt-in, --execute, and exact host:command --confirm (N3). It",
              "requires Alerts:read, Hosts:read, Vulnerabilities:read, Vulnerabilities (Falcon Intelligence):read,",
              "NGSIEM:read, Identity Protection Entities:read, Identity Protection Timeline:read, and",
              "Identity Protection Assessment:read, plus three",
              "write-labelled scopes: NGSIEM:write for `search start`, `search stop`, and `identity activity`, and",
              "Identity Protection GraphQL:write for the fixed Identity Protection query commands,",
              "which Falcon requires even for read-only queries, and MalQuery:write for bounded exact/fuzzy searches (N4).",
              "The `account`, `asset`, `application`, and `login` commands need license-gated Assets:read.",
              "The `indicator` commands require the license-gated Indicators (Falcon Intelligence):read scope.",
            ]
          : []),
      ];
      process.stdout.write(lines.join("\n") + "\n");
      return 0;
    }
    const filter = filterOf(invocation);
    if (flags.has("--region"))
      resolveOrigin(flags.get("--region"), flags.has("--allow-unknown-origin"));
    for (const warning of normalizeEnvironment())
      process.stderr.write(warning + "\n");
    if (command.name === "setup") {
      process.stdout.write(
        render(
          {
            setup:
              "Install falcon-axi in a durable location before registering session integrations",
          },
          [
            "Run `falcon-axi setup hooks` to install or repair Claude Code, Codex, and OpenCode integrations",
            "Set FALCON_AXI_CLIENT_ID and FALCON_AXI_CLIENT_SECRET, or configure a profile with a SecretRef",
            "Run `npx skills add knowttl/falcon-axi --skill falcon-axi` to install the agent skill separately",
          ],
        ),
      );
      return 0;
    }
    if (command.name === "setup hooks") {
      process.stdout.write(render(await installHooks()));
      return 0;
    }
    if (
      readOnly() &&
      [
        "search start",
        "search stop",
        "host usb",
        "identity activity",
        "malquery search",
      ].includes(command.name)
    )
      throw new CliError(
        "READ_ONLY_VIOLATION",
        "FALCON_AXI_READ_ONLY forbids search lifecycle changes",
      );
    if (command.name === "rtr run") validateRtrInvocation(invocation);
    if (command.name === "config path") {
      process.stdout.write(
        render({
          config: configPath(flags.get("--config")),
          write_log: writeLogPath(),
        }),
      );
      return 0;
    }
    if (command.name === "profile list") {
      const document = await loadProfiles(flags.get("--config"));
      process.stdout.write(
        render({
          profiles: Object.keys(document.profiles),
          default_profile: document.defaultProfile,
        }),
      );
      return 0;
    }
    if (command.name === "scopes") {
      const groups = new Map<string, string[]>();
      for (const spec of commands)
        for (const scope of new Set([
          ...spec.operations.flatMap((id) => operation(id).scopes),
          ...([
            "identity list",
            "identity show",
            "identity timeline",
            "identity assessment",
          ].includes(spec.name)
            ? document(
                spec.name === "identity list"
                  ? "identity_list"
                  : spec.name.replace(" ", "_"),
              ).readScopes
            : []),
        ])) {
          const names = groups.get(scope) ?? [];
          names.push(spec.name);
          groups.set(scope, names);
        }
      process.stdout.write(
        render(
          {
            posture: new Raw(
              "read-only except three write-labelled scopes: NGSIEM:write for NG-SIEM search start and stop and identity activity (captain exception N1), and Identity Protection GraphQL:write for fixed read-only identity queries (captain exception N2); Real time response:read also permits guarded host execution with profile opt-in and exact confirmation (captain exception N3); MalQuery:write permits bounded exact/fuzzy pattern searches (captain exception N4)",
            ),
            scopes: [...groups].map(([scope, names]) => ({
              scope,
              access: scope.endsWith(":write") ? "write" : "read",
              commands: names.join(", "),
              required: names.every((name) => /^(policy|exclusion) /.test(name))
                ? "selected --type"
                : "yes",
            })),
            member_cid_token_scope: new Raw(
              "unresolved (Flight Control read may be required; see design section 17.7)",
            ),
          },
          [
            "Grant these scopes in the Falcon console under Support and resources > API clients and keys",
            "Grant read access only, apart from NGSIEM:write, Identity Protection GraphQL:write, and MalQuery:write; falcon-axi needs no other write scope",
            "Identity Protection GraphQL:write is labelled write because Falcon requires it even for read-only queries; falcon-axi sends only its own fixed read queries, never caller-supplied GraphQL (captain exception N2)",
            "Omit NGSIEM:write and `search start`, `search stop`, and `identity activity` fail with SCOPE_DENIED",
            "Omit Identity Protection GraphQL:write and `identity list`, `identity show`, `identity timeline`, and `identity assessment` fail with SCOPE_DENIED",
            "MalQuery:write needs Falcon MalQuery licensing and admits only bounded exact/fuzzy search under N4; hunt and sample downloads remain excluded",
            "Assets:read is license-gated to Falcon Discover or Exposure Management; omit it and the `account`, `asset`, `application`, and `login` commands fail with SCOPE_DENIED",
          ],
        ),
      );
      return 0;
    }
    const credential = await resolveCredential(
      flags.get("--config"),
      flags.get("--profile"),
      command.name === "auth status",
    );
    if (flags.has("--no-member-cid")) delete credential.memberCid;
    else if (flags.has("--member-cid")) {
      credential.memberCid = flags.get("--member-cid")!;
      registerMemberCid(credential.memberCid);
    }
    memberCid = credential.memberCid;
    const allowUnknown = flags.has("--allow-unknown-origin");
    const base = resolveOrigin(
      flags.get("--region") ?? credential.region,
      allowUnknown,
    );
    if (command.name === "rtr run") {
      process.removeListener("SIGTERM", cancel);
      process.removeListener("SIGINT", cancel);
      process.on("SIGTERM", cancel);
      process.on("SIGINT", cancel);
      await rtrRun(invocation, credential, base, controller.signal);
      return 0;
    }
    if (
      flags.has("--hostname") &&
      ["host logins", "host network"].includes(command.name)
    )
      hostnameDeadline = AbortSignal.timeout(
        Math.max(0, Math.floor(60000 - (performance.now() - started))),
      );
    const signal = flags.has("--wait")
      ? AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(
            Math.max(
              0,
              Math.floor(
                Number(flags.get("--wait")) * 1000 -
                  (performance.now() - started),
              ),
            ),
          ),
        ])
      : hostnameDeadline
        ? AbortSignal.any([controller.signal, hostnameDeadline])
        : controller.signal;
    const session = await authenticate(credential, base, allowUnknown, signal);
    const region =
      Object.keys(REGIONS).find((key) => REGIONS[key] === session.base) ??
      "an unlisted Falcon cloud";
    const tenant = new Raw(
      `${region}${base !== session.base ? ` (re-targeted from ${Object.keys(REGIONS).find((key) => REGIONS[key] === base)})` : ""}${credential.memberCid ? ` member CID …${credential.memberCid.length <= 4 ? "" : credential.memberCid.slice(-4)}` : " (own CID unavailable)"}`,
    );
    if (command.name === "auth status") {
      process.stdout.write(
        render(
          {
            credential_resolved: true,
            credential_channel: credential.channel,
            profile: credential.profile,
            endpoint: session.base,
            client_secret_source: credential.secretSource,
            credential_path: credential.path,
            tenant,
            scopes: new Raw(
              "read scopes, plus NGSIEM:write for `search start`, `search stop`, and `identity activity`, Identity Protection GraphQL:write for the fixed Identity Protection query commands, and MalQuery:write for bounded exact/fuzzy searches (N4)",
            ),
            ...(session.rateLimit !== undefined &&
            session.remaining !== undefined
              ? {
                  rate_limit: new Raw(
                    `${session.remaining} of ${session.rateLimit} requests remaining`,
                  ),
                }
              : {}),
          },
          contextualHelp([
            "Run `falcon-axi detection list` to read detections with this credential",
          ]),
        ),
      );
      return 0;
    }
    const domain = new Domain(
      invocation,
      credential,
      session,
      allowUnknown,
      signal,
    );
    const result =
      command.name.startsWith("search ") ||
      ["host usb", "identity activity"].includes(command.name)
        ? await search(domain)
        : [
              "identity list",
              "identity show",
              "identity timeline",
              "identity assessment",
            ].includes(command.name)
          ? await identity(domain)
          : command.name.startsWith("malquery ")
            ? await malquery(domain)
            : inspectionCommands.some((entry) => entry.name === command.name)
              ? await inspection(domain, filter)
              : [
                    "account",
                    "asset",
                    "application",
                    "login",
                    "iot",
                    "host-group",
                    "sensor-usage",
                  ].includes(command.name.split(" ")[0]!) ||
                  command.name.startsWith("identity sensor ")
                ? await inventory(domain, filter)
                : [
                      "vuln",
                      "cve",
                      "cloud-asset",
                      "iom",
                      "cloud-risk",
                      "container",
                      "image",
                      "serverless",
                      "shield",
                    ].includes(command.name.split(" ")[0]!)
                  ? await exposure(domain, filter)
                  : await investigate(
                      invocation,
                      credential,
                      session,
                      filter,
                      allowUnknown,
                      signal,
                    );
    if (
      session.rateLimit &&
      session.remaining !== undefined &&
      session.remaining < session.rateLimit * 0.1
    ) {
      const note = `${session.remaining} of ${session.rateLimit} requests remaining in this rate limit window`;
      if (command.name.startsWith("file-change ")) result.help.push(note);
      else if (result.value.count || command.name === "process tree")
        result.value.rate_limit = new Raw(note);
    }
    if (command.name === "home") {
      result.value = {
        ...homeHead(),
        tenant,
        ...result.value,
      };
      result.help.push(
        ...HOME_GUIDANCE,
        ...(argv.length === 0 ? skillHint() : []),
      );
    }
    process.stdout.write(render(result.value, contextualHelp(result.help)));
    return 0;
  } catch (error) {
    const safe =
      hostnameDeadline?.aborted && !controller.signal.aborted
        ? new CliError(
            "WAIT_TIMEOUT",
            "authentication, hostname lookup and history exceeded the combined 60-second time budget",
            ["Retry shortly"],
            error instanceof CliError ? error.details : {},
          )
        : error instanceof CliError
          ? error
          : new CliError(
              "UNKNOWN",
              "falcon-axi could not complete this command",
              ["Retry shortly"],
            );
    process.stdout.write(
      render(
        {
          ...(home ? homeHead() : {}),
          error: safe.message,
          code: safe.code,
          ...safe.details,
        },
        contextualHelp([
          ...safe.help,
          ...(home && argv.length === 0 ? skillHint() : []),
        ]),
      ),
    );
    return safe.exitCode;
  } finally {
    process.removeListener("SIGTERM", cancel);
    process.removeListener("SIGINT", cancel);
  }
}
