import { CliError } from "./core.js";
import { commands, valueFlags, boolFlags, recoveryHelp } from "./metadata.js";
import type { Command } from "./metadata.js";
import { applicationFields } from "./inventory.js";
import { shieldFilters } from "./exposure.js";
import { validateInspection } from "./inspection.js";
import { validateSearch } from "./search.js";
import { validateIdentity } from "./identity.js";

export interface Invocation {
  command: Command;
  flags: Map<string, string>;
  id: string | undefined;
  limit: number;
}
export function parse(argv: string[]): Invocation {
  const group = [
    ...new Set(
      commands.flatMap((command) => {
        const words = command.name.split(" ");
        return words
          .slice(1)
          .map((_, index) => words.slice(0, index + 1).join(" "));
      }),
    ),
  ]
    .sort((a, b) => b.length - a.length)
    .find((group) =>
      group.split(" ").every((word, index) => argv[index] === word),
    );
  if (
    group &&
    !commands.some((command) =>
      command.name.split(" ").every((word, index) => argv[index] === word),
    )
  ) {
    const child = argv[group.split(" ").length];
    if (child === "--help" && argv.length === group.split(" ").length + 1)
      return {
        command: {
          name: group,
          summary: "",
          order: 0,
          values: [],
          booleans: [],
          operations: [],
        },
        flags: new Map([["--help", "true"]]),
        id: undefined,
        limit: 20,
      };
    throw new CliError(
      "VALIDATION_ERROR",
      `unknown ${group} subcommand ${child ?? ""}`.trim(),
      [
        `valid ${group} subcommands: ${[...new Set(commands.filter((command) => command.name.startsWith(`${group} `)).map((command) => command.name.slice(group.length + 1).split(" ")[0]))].join(", ")}`,
      ],
    );
  }
  const command = [...commands]
    .sort((a, b) => b.name.length - a.name.length)
    .find((spec) =>
      spec.name.split(" ").every((word, index) => argv[index] === word),
    ) ?? {
    name: "home",
    summary: "",
    order: 0,
    values: [],
    booleans: [],
    operations: [],
  };
  const words = command.name === "home" ? 0 : command.name.split(" ").length;
  const values = [...valueFlags, ...command.values.map((name) => `--${name}`)];
  const booleans = [
    ...boolFlags,
    ...command.booleans.map((name) => `--${name}`),
  ];
  const valid = [
    `valid flags for \`${command.name}\`: ${["--help", "--region", "--allow-unknown-origin", "--member-cid", "--no-member-cid", "--config", "--profile", ...command.values.flatMap((name) => (name === "max-rows" ? ["--all", "--max-rows"] : [`--${name}`])), ...command.booleans.filter((name) => name !== "all").map((name) => `--${name}`)].join(", ")}`,
  ];
  const flags = new Map<string, string>();
  const positionals: string[] = [];
  for (let index = words; index < argv.length; index++) {
    const arg = argv[index]!;
    if (!arg.startsWith("-")) {
      positionals.push(arg);
      continue;
    }
    const split = arg.indexOf("=");
    const key = split < 0 ? arg : arg.slice(0, split);
    if (booleans.includes(key)) {
      if (split >= 0)
        throw new CliError(
          "VALIDATION_ERROR",
          `${key} does not accept a value`,
          valid,
        );
      flags.set(key, "true");
    } else if (values.includes(key)) {
      const value = split < 0 ? argv[++index] : arg.slice(split + 1);
      if (value === undefined || value === "" || value.startsWith("--"))
        throw new CliError("VALIDATION_ERROR", `${key} requires a value`);
      flags.set(key, value);
    } else {
      const matches = [...values, ...booleans].filter(
        (flag) => key.startsWith("--") && flag.startsWith(key),
      );
      throw new CliError(
        "VALIDATION_ERROR",
        `unknown flag ${key} for \`${command.name}\``,
        [
          ...(matches.length === 1 ? [`Did you mean ${matches[0]}?`] : []),
          ...valid,
        ],
      );
    }
  }
  if (flags.has("--help") && (command.name !== "home" || !positionals.length))
    return { command, flags, id: positionals[0], limit: 20 };
  if (command.name === "home" && positionals.length)
    throw new CliError(
      "VALIDATION_ERROR",
      `unknown command ${positionals[0]}`,
      [
        `valid commands: ${commands.map((command) => command.name).join(", ")}`,
        "Run `falcon-axi --help` for the command list",
      ],
    );
  if (!flags.has("--help")) {
    const hostname =
      ["host logins", "host network"].includes(command.name) &&
      flags.has("--hostname");
    if (
      command.positional &&
      (hostname ? positionals.length !== 0 : positionals.length !== 1)
    )
      throw new CliError(
        "VALIDATION_ERROR",
        `${command.name} requires exactly one ${command.positional}`,
        [
          command.name === "policy members"
            ? "Run `falcon-axi policy list --type prevention` to find policy ids"
            : command.name === "cve show"
              ? "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228"
              : command.name === "vuln show"
                ? "Run `falcon-axi vuln list --status open` to find Spotlight record identifiers"
                : command.name.startsWith("search ")
                  ? "A search identifier comes from `falcon-axi search start --query '<cql>'`"
                  : ["identity show", "identity timeline"].includes(
                        command.name,
                      )
                    ? "Run `falcon-axi identity list` to see current identity ids"
                    : command.name === "identity activity"
                      ? "Run `falcon-axi detection show <id>` for an identity detection's account_id"
                      : command.name === "identity sensor show"
                        ? "Run `falcon-axi identity sensor list` to see current sensor identifiers"
                        : recoveryHelp(
                            command.name,
                            flags,
                            command.name.startsWith("host ")
                              ? "device"
                              : command.name.split(" ")[0],
                          ),
        ],
      );
    if (!command.positional && positionals.length)
      throw new CliError(
        "VALIDATION_ERROR",
        `\`${command.name}\` accepts no positional arguments`,
        valid,
      );
  }
  if (
    flags.has("--member-cid") &&
    (!flags.get("--member-cid")!.trim() || flags.has("--no-member-cid"))
  )
    throw new CliError(
      "VALIDATION_ERROR",
      flags.has("--no-member-cid")
        ? "--member-cid and --no-member-cid cannot be combined"
        : "--member-cid requires a nonempty value",
      flags.has("--no-member-cid")
        ? [
            "Use `--member-cid <cid>` to select a child tenant or `--no-member-cid` to clear an inherited selection",
          ]
        : [],
    );
  const number = (name: string, fallback: number, ceiling: number): number => {
    const text = flags.get(name) ?? String(fallback);
    const value = Number(text);
    if (
      !/^\d+$/.test(text) ||
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > ceiling
    )
      throw new CliError(
        "VALIDATION_ERROR",
        `${name} must be an integer from 1 to ${ceiling}`,
        name === "--limit"
          ? [
              `${ceiling} is the documented ${command.name === "vuln list" ? "Spotlight query" : command.name.startsWith("host ") ? "Hosts query" : "Alerts query"} ceiling`,
              `Run \`falcon-axi ${command.name} --limit 20\` for the default page`,
            ]
          : [],
      );
    return value;
  };
  const limit = number("--limit", 20, command.ceiling ?? 10000);
  if (flags.has("--max-rows") && !flags.has("--all"))
    throw new CliError("VALIDATION_ERROR", "--max-rows requires --all");
  if (flags.has("--all")) {
    const budget = flags.get("--max-rows") ?? "1000";
    if (!/^\d+$/.test(budget) || BigInt(budget) < 1n)
      throw new CliError(
        "VALIDATION_ERROR",
        "--max-rows must be a positive integer",
      );
  }
  const id = positionals[0];
  if (
    command.name === "host show" &&
    id &&
    (!/^[a-fA-F0-9]{32}$/.test(id) || /^0{32}$/.test(id))
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "host show requires a nonzero 32-character hexadecimal device id (AID)",
      ["Run `falcon-axi host list` to see current device identifiers"],
    );
  if (!flags.has("--help")) validateInspection(command.name, flags, limit);
  if (command.name === "cve show" && id && !/^CVE-[0-9]{4}-[0-9]{4,}$/.test(id))
    throw new CliError(
      "VALIDATION_ERROR",
      "cve show requires a CVE identifier such as CVE-2021-44228",
      [
        "A CVE identifier matches CVE-<year>-<number>, for example CVE-2021-44228",
      ],
    );
  if (command.name === "serverless list" && !flags.get("--filter")?.trim())
    throw new CliError(
      "VALIDATION_ERROR",
      "serverless list requires --filter <FQL>",
    );
  if (command.name === "shield list") shieldFilters(flags);
  if (
    command.name === "process show" &&
    id &&
    !/^pid:[a-fA-F0-9]{32}:\d+$/.test(id)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "process identifier must be pid:<32 hex device ID>:<decimal ID>",
    );
  if (
    ["ioc hosts", "ioc processes"].includes(command.name) &&
    id &&
    !/^(domain|ipv4|ipv6|md5|sha256):\S[\s\S]*$/.test(id)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "indicator must be type:value (domain, ipv4, ipv6, md5, sha256)",
    );
  if (command.name === "ioc processes" && !flags.get("--host")?.trim())
    throw new CliError(
      "VALIDATION_ERROR",
      "ioc processes requires --host <device_id>",
    );
  for (const flag of ["--filter", "--hostname", "--sort"])
    if (flags.has(flag) && !flags.get(flag)!.trim())
      throw new CliError("VALIDATION_ERROR", `${flag} requires a value`);
  const fields = flags.get("--fields");
  if (fields !== undefined) {
    const valid =
      command.name === "application list"
        ? applicationFields
        : (command.fields ?? []);
    const names = fields.split(",").map((value) => value.trim());
    if (names.some((name) => !name || !valid.includes(name)))
      throw new CliError("VALIDATION_ERROR", "unknown --fields column", [
        `valid fields: ${valid.join(", ")}`,
      ]);
  }
  const invocation = { command, flags, id, limit };
  validateSearch(invocation);
  validateIdentity(invocation);
  return invocation;
}

export function filterOf(invocation: Invocation): string | undefined {
  const { command, flags } = invocation;
  const terms: string[] = [];
  const detection = command.name.startsWith("detection ");
  const host = command.name === "host list";
  const vuln = command.name === "vuln list";
  const cve = command.name === "cve list";
  const oneOf = (flag: string, choices: string[]): string | undefined => {
    const value = flags.get(`--${flag}`)?.toLowerCase();
    if (value !== undefined && !choices.includes(value))
      throw new CliError("VALIDATION_ERROR", `unknown ${flag} ${value}`, [
        `valid values for --${flag}: ${choices.join(", ")}`,
      ]);
    return value;
  };
  if (detection) {
    const severity = oneOf("severity", [
      "informational",
      "low",
      "medium",
      "high",
      "critical",
    ]);
    if (severity)
      terms.push(
        `severity_name:'${severity[0]!.toUpperCase()}${severity.slice(1)}'`,
      );
    const status = oneOf("status", [
      "new",
      "in_progress",
      "closed",
      "reopened",
    ]);
    if (status) terms.push(`status:'${status}'`);
    const product = oneOf("product", [
      "epp",
      "idp",
      "mobile",
      "xdr",
      "overwatch",
      "cwpp",
      "ngsiem",
      "thirdparty",
      "data-protection",
    ]);
    if (product) terms.push(`product:'${product}'`);
  }
  if (host) {
    if (flags.has("--hostname"))
      terms.push(`hostname:'${flags.get("--hostname")}'`);
    const platform = oneOf("platform", ["windows", "mac", "linux"]);
    if (platform)
      terms.push(
        `platform_name:'${platform[0]!.toUpperCase()}${platform.slice(1)}'`,
      );
    const status = oneOf("status", [
      "normal",
      "containment_pending",
      "contained",
      "lift_containment_pending",
    ]);
    if (status) terms.push(`status:'${status}'`);
  }
  if (vuln || cve) {
    if (vuln && flags.has("--host")) {
      if (!flags.get("--host")!.trim())
        throw new CliError("VALIDATION_ERROR", "--host requires a value");
      terms.push(`aid:'${flags.get("--host")}'`);
    }
    const severity = oneOf("severity", ["low", "medium", "high", "critical"]);
    if (severity)
      terms.push(
        `${vuln ? "cve.severity" : "severity"}:'${severity.toUpperCase()}'`,
      );
    if (vuln) {
      const status = oneOf("status", ["open", "closed", "reopen", "expired"]);
      if (status) terms.push(`status:'${status}'`);
    }
  }
  const since = flags.get("--since");
  if (since !== undefined) {
    if (!/^\d+[mhd]$/i.test(since))
      throw new CliError(
        "VALIDATION_ERROR",
        "--since must be a relative window such as 24h",
        [
          "valid units for --since: m (minutes), h (hours), d (days)",
          "Example: `--since 7d`",
        ],
      );
    if (detection || host || vuln || cve)
      terms.push(
        `${cve ? "publish_date" : detection || vuln ? "created_timestamp" : "last_seen"}:>'now-${since.toLowerCase()}'`,
      );
  }
  const raw = flags.get("--filter");
  if (raw !== undefined) terms.push(terms.length ? `(${raw})` : raw);
  if (vuln && !terms.length)
    throw new CliError("VALIDATION_ERROR", "vuln list requires a filter", [
      "Run `falcon-axi vuln list --host <device_id>` for one host's vulnerabilities",
      "Run `falcon-axi vuln list --severity critical --status open` for the fleet's worst",
    ]);
  if (vuln && terms.join("+").includes("*"))
    throw new CliError(
      "FQL_INVALID",
      "Spotlight filters do not support wildcards",
      [
        "Remove the `*` and match an exact value, for example `cve.id:'CVE-2024-3094'`",
        "Run `falcon-axi vuln list --help` for the filterable fields",
      ],
    );
  return terms.length ? terms.join("+") : undefined;
}
