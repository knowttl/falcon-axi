import { CliError, object } from "./core.js";

export const RTR_COMMANDS = Object.freeze([
  "cat",
  "cd",
  "csrutil",
  "env",
  "eventlog",
  "filehash",
  "getsid",
  "ifconfig",
  "ipconfig",
  "ls",
  "mount",
  "netstat",
  "ps",
  "reg query",
  "users",
]);
export interface RtrPolicy {
  readonly enabled: boolean;
  readonly commands: readonly string[];
}
export function rtrPolicy(value: unknown): RtrPolicy {
  if (value === undefined) return { enabled: false, commands: RTR_COMMANDS };
  if (
    !object(value) ||
    typeof value.enabled !== "boolean" ||
    Object.keys(value).some((key) => !["enabled", "commands"].includes(key)) ||
    (value.commands !== undefined &&
      (!Array.isArray(value.commands) ||
        value.commands.some(
          (item: unknown) =>
            typeof item !== "string" || !RTR_COMMANDS.includes(item),
        )))
  )
    throw new CliError(
      "CONFIG_INVALID",
      "rtr requires a boolean enabled and optional commands subset",
    );
  return {
    enabled: value.enabled,
    commands:
      value.commands === undefined
        ? RTR_COMMANDS
        : [...new Set(value.commands as string[])],
  };
}
export function readOnly(): boolean {
  const value = process.env.FALCON_AXI_READ_ONLY ?? "false";
  if (!/^(true|false|1|0)$/i.test(value))
    throw new CliError(
      "CONFIG_INVALID",
      "FALCON_AXI_READ_ONLY must be 1, true, 0 or false",
    );
  return /^(true|1)$/i.test(value);
}
export function commandTokens(command: string): string[] {
  const tokens: string[] = [];
  let index = 0;
  while (index < command.length) {
    if (command[index] === " ") {
      index++;
      continue;
    }
    const start = index;
    if (["'", '"'].includes(command[index]!)) {
      const quote = command[index++]!;
      while (index < command.length && command[index] !== quote) index++;
      if (index === command.length)
        throw new CliError(
          "VALIDATION_ERROR",
          "RTR command has unmatched quotes",
        );
      index++;
    } else while (index < command.length && command[index] !== " ") index++;
    tokens.push(command.slice(start, index));
  }
  return tokens;
}
export function parseRtr(command: string, allowed: readonly string[]): string {
  if (allowed.some((name) => !RTR_COMMANDS.includes(name)))
    throw new CliError(
      "CONFIG_INVALID",
      "RTR command restriction cannot widen the standard set",
    );
  if (
    !command ||
    Buffer.byteLength(command) > 4096 ||
    /[\x00-\x1f\x7f;|&<>`$\u0085\u2028\u2029]/.test(command)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "RTR requires one command without shell syntax or control characters",
    );
  const tokens = commandTokens(command);
  if (!tokens.length)
    throw new CliError("VALIDATION_ERROR", "RTR command is empty");
  if (
    tokens.some(
      (token) =>
        /[()]/.test(token) &&
        !(["'", '"'].includes(token[0]!) && token.at(-1) === token[0]),
    )
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "RTR parentheses require a quoted data argument",
    );
  const base =
    tokens[0] === "reg" && tokens[1] === "query" ? "reg query" : tokens[0]!;
  if (!allowed.includes(base))
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "RTR command is outside the effective read-only command set",
    );
  if (base === "eventlog" && !["view", "list"].includes(tokens[1] ?? ""))
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "eventlog permits only view and list",
    );
  return base === "reg query" ? "reg" : base;
}
export function validateRtrHost(host: string): void {
  if (host.length !== 32 || !/^[a-fA-F0-9]{32}$/.test(host))
    throw new CliError(
      "VALIDATION_ERROR",
      "RTR requires one 32-character device id",
    );
}
export function catListing(
  command: string,
  allowed: readonly string[],
): string | undefined {
  const tokens = commandTokens(command);
  if (tokens.length !== 2 || tokens[0] !== "cat" || !allowed.includes("ls"))
    return;
  const path = tokens[1]!.replace(/^["']|["']$/g, "");
  if (!path || path.startsWith("-") || /[*?\[\]]/.test(path)) return;
  const listing = `ls ${tokens[1]}`;
  parseRtr(listing, allowed);
  return listing;
}
