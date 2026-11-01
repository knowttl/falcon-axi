import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { parseTOML, getStaticTOMLValue } from "toml-eslint-parser";
import type { AST } from "toml-eslint-parser";
import { CliError, object } from "./core.js";
import {
  durableInstallation,
  executableCommand,
  shellArgument,
} from "./executable.js";

const marker = "falcon-axi-session";
const pluginMarker = `// Managed by ${marker}\n`;
const invalid = (): CliError =>
  new CliError(
    "CONFIG_INVALID",
    "cannot install hooks; check agent configuration syntax and file permissions",
    ["Repair the local agent configuration, then run `falcon-axi setup hooks`"],
  );

async function text(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function jsonHook(previous: string, command: string): string {
  const document: unknown = previous ? JSON.parse(previous) : {};
  if (!object(document)) throw invalid();
  const hooks = Object.hasOwn(document, "hooks") ? document.hooks : {};
  if (!object(hooks)) throw invalid();
  const sessions = Object.hasOwn(hooks, "SessionStart")
    ? hooks.SessionStart
    : [];
  if (!Array.isArray(sessions)) throw invalid();
  const wanted = { type: "command", command, timeout: 10 };
  let managed = false;
  const result: Record<string, unknown>[] = [];
  for (const entry of sessions) {
    if (!object(entry) || !Array.isArray(entry.hooks)) throw invalid();
    const remaining: Record<string, unknown>[] = [];
    for (const hook of entry.hooks) {
      if (!object(hook)) throw invalid();
      if (String(hook.command ?? "").includes(marker)) {
        if (!managed) remaining.push(wanted);
        managed = true;
      } else remaining.push(hook);
    }
    if (remaining.length) result.push({ ...entry, hooks: remaining });
  }
  if (!managed) result.push({ matcher: "", hooks: [wanted] });
  hooks.SessionStart = result;
  document.hooks = hooks;
  return previous && isDeepStrictEqual(JSON.parse(previous), document)
    ? previous
    : JSON.stringify(document, null, 2) + "\n";
}

function codexFeatures(previous: string): string {
  const ast = parseTOML(previous, { tomlVersion: "1.0" });
  const document = getStaticTOMLValue(ast);
  const features = document.features;
  if (features !== undefined && (!object(features) || features instanceof Date))
    throw invalid();
  if (features?.hooks === true) return previous;
  const key = (node: AST.TOMLKey): string[] =>
    node.keys.map((part) =>
      part.type === "TOMLBare" ? part.name : part.value,
    );
  let hook: AST.TOMLContentNode | undefined;
  let inline: AST.TOMLInlineTable | undefined;
  let table: AST.TOMLTable | undefined;
  const inspect = (entry: AST.TOMLKeyValue, prefix: string[]): void => {
    const path = [...prefix, ...key(entry.key)];
    if (path.length === 2 && path[0] === "features" && path[1] === "hooks")
      hook = entry.value;
    if (
      path.length === 1 &&
      path[0] === "features" &&
      entry.value.type === "TOMLInlineTable"
    ) {
      inline = entry.value;
      for (const child of inline.body) inspect(child, path);
    }
  };
  for (const entry of ast.body[0].body) {
    if (entry.type === "TOMLKeyValue") inspect(entry, []);
    else {
      if (entry.resolvedKey.length === 1 && entry.resolvedKey[0] === "features")
        table = entry;
      for (const child of entry.body) inspect(child, key(entry.key));
    }
  }
  if (hook)
    return (
      previous.slice(0, hook.range[0]) + "true" + previous.slice(hook.range[1])
    );
  if (inline) {
    const position = inline.range[1] - 1;
    return (
      previous.slice(0, position) +
      `${inline.body.length ? ", " : ""}hooks = true` +
      previous.slice(position)
    );
  }
  if (table) {
    const position = previous.indexOf("\n", table.key.range[1]);
    return position < 0
      ? previous + "\nhooks = true\n"
      : previous.slice(0, position + 1) +
          "hooks = true\n" +
          previous.slice(position + 1);
  }
  // Root dotted keys remain root keys even when subsequent tables exist.
  return "features.hooks = true\n" + previous;
}

function plugin(command: string[]): string {
  return (
    pluginMarker +
    `import { execFile } from "node:child_process";
export const FalconAxi = async ({ directory }) => ({
  "experimental.chat.system.transform": async (_input, output) => {
    const text = await new Promise((resolve) => {
      execFile(${JSON.stringify(command[0])}, ${JSON.stringify(command.slice(1))}, { cwd: directory, timeout: 10000 }, (error, stdout) => {
        resolve(error ? "falcon-axi: local status unavailable; run falcon-axi setup" : stdout.trim());
      });
    });
    if (text) output.system.push(text);
  },
});
`
  );
}

export async function installHooks(): Promise<Record<string, unknown>> {
  try {
    const binary = executableCommand(true);
    durableInstallation();
    const command = `${binary.map(shellArgument).join(" ")} # ${marker}`;
    const home = process.env.HOME || homedir();
    const paths = [
      join(home, ".claude/settings.json"),
      join(home, ".codex/hooks.json"),
      join(home, ".codex/config.toml"),
      join(home, ".config/opencode/plugins/axi-falcon-axi.js"),
    ];
    const old = await Promise.all(paths.map(text));
    if (old[3] !== undefined && !old[3].startsWith(pluginMarker))
      throw invalid();
    // Prepare all four documents before writing any configuration.
    const updates = [
      jsonHook(old[0] ?? "", command),
      jsonHook(old[1] ?? "", command),
      codexFeatures(old[2] ?? ""),
      plugin(binary),
    ];
    const changed = updates.map((content, index) => content !== old[index]);
    for (const [index, path] of paths.entries()) {
      if (!changed[index]) continue;
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, updates[index]!);
    }
    return {
      hooks: {
        status: changed.some(Boolean) ? "installed" : "unchanged",
        claude: changed[0] ? "updated" : "unchanged",
        codex: changed[1] || changed[2] ? "updated" : "unchanged",
        opencode: changed[3] ? "updated" : "unchanged",
      },
    };
  } catch (error) {
    if (error instanceof CliError) throw error;
    throw invalid();
  }
}
