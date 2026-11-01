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
import { commands } from "./metadata.js";
import { operation } from "./transport/operations.js";
import { parse, filterOf } from "./parser.js";
import { investigate } from "./investigation.js";
import { homedir } from "node:os";
import { resolve } from "node:path";
import helpText from "./help.json" with { type: "json" };
import { VERSION } from "./version.js";

const description =
  "Read CrowdStrike Falcon from the shell with compact, structured results for agents and the humans running them.";
const shellQuote = (value: string): string =>
  /^[\w@%+=:,./-]+$/.test(value)
    ? value
    : `'${value.replaceAll("'", `'"'"'`)}'`;

export async function main(argv: string[], bin?: string): Promise<number> {
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
    const executable = resolve(process.argv[1] ?? "falcon-axi");
    return {
      bin:
        bin ??
        (executable.startsWith(`${homedir()}/`)
          ? `~/${executable.slice(homedir().length + 1)}`
          : executable),
      description,
    };
  };
  const contextualHelp = (help: readonly string[]): string[] => {
    const suffix =
      ["region", "config", "profile"]
        .flatMap((name) =>
          activeFlags.has(`--${name}`)
            ? [` --${name} ${shellQuote(activeFlags.get(`--${name}`)!)}`]
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
    const budgetArgs = ["search", "status", "synthetic-job", "--wait", "1"];
    const searchSubset =
      argv.length === budgetArgs.length &&
      argv.every((value, index) => value === budgetArgs[index]);
    const invocation = parse(searchSubset ? ["detection", "list"] : argv);
    const { command, flags } = invocation;
    activeFlags = flags;
    home = command.name === "home";
    memberCid = flags.get("--member-cid");
    if (flags.has("--help")) {
      if (Object.hasOwn(helpText, command.name)) {
        process.stdout.write(
          helpText[command.name as keyof typeof helpText] + "\n",
        );
        return 0;
      }
      process.stdout.write(
        [
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
        ].join("\n") + "\n",
      );
      return 0;
    }
    const filter = filterOf(invocation);
    if (flags.has("--region"))
      resolveOrigin(flags.get("--region"), flags.has("--allow-unknown-origin"));
    normalizeEnvironment();
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
        for (const scope of new Set(
          spec.operations.flatMap((id) => operation(id).scopes),
        )) {
          const names = groups.get(scope) ?? [];
          names.push(spec.name);
          groups.set(scope, names);
        }
      process.stdout.write(
        render(
          {
            posture: new Raw("read-only"),
            scopes: [...groups].map(([scope, names]) => ({
              scope,
              access: "read",
              commands: names.join(", "),
              required: "yes",
            })),
            member_cid_token_scope: new Raw(
              "unresolved (Flight Control read may be required; see design section 17.7)",
            ),
          },
          [
            "Grant these scopes in the Falcon console under Support and resources > API clients and keys",
            "Grant read access only; falcon-axi needs no write scope",
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
    if (
      flags.has("--hostname") &&
      ["host logins", "host network"].includes(command.name)
    )
      hostnameDeadline = AbortSignal.timeout(
        Math.max(0, Math.floor(60000 - (performance.now() - started))),
      );
    const signal = searchSubset
      ? AbortSignal.any([controller.signal, AbortSignal.timeout(1000)])
      : hostnameDeadline
        ? AbortSignal.any([controller.signal, hostnameDeadline])
        : controller.signal;
    const session = await authenticate(credential, base, allowUnknown, signal);
    if (searchSubset)
      throw new CliError(
        "VALIDATION_ERROR",
        "search status is not delivered in S01",
      );
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
            scopes: new Raw("read scopes"),
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
    const result = await investigate(
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
        "Run `falcon-axi detection list` to see more detections",
        "Run `falcon-axi detection list --product idp` for Identity Protection detections",
        "Run `falcon-axi host list --filter \"hostname:'WIN-*'\"` to search hosts",
        "Run `falcon-axi scopes` to see what this API client needs",
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
        contextualHelp(safe.help),
      ),
    );
    return safe.exitCode;
  } finally {
    process.removeListener("SIGTERM", cancel);
    process.removeListener("SIGINT", cancel);
  }
}
