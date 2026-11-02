import { realpathSync, statSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { CliError } from "./core.js";

export function shellArgument(value: string): string {
  return process.platform === "win32"
    ? `"${value}"`
    : `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function executableCommand(hook = false): string[] {
  const entry = realpathSync(resolve(process.argv[1]!));
  const target = hook ? join(dirname(entry), "hook.js") : entry;
  const name = hook ? "falcon-axi-hook" : "falcon-axi";
  if (!statSync(target).isFile())
    throw new CliError(
      "CONFIG_INVALID",
      `cannot locate ${name}; reinstall falcon-axi`,
    );
  return [process.execPath, target];
}

export function durableInstallation(): void {
  const entry = resolve(process.argv[1]!);
  const hook = join(dirname(realpathSync(entry)), "hook.js");
  const temporaryRoots =
    process.platform === "win32" ? [] : ["/tmp", realpathSync("/tmp")];
  for (const path of [
    entry,
    realpathSync(entry),
    hook,
    realpathSync(hook),
    process.execPath,
  ]) {
    const parts = path.split(sep);
    if (
      temporaryRoots.some(
        (root) => path === root || path.startsWith(root + sep),
      ) ||
      parts.some((part) =>
        [".treehouse", "worktrees", ".no-mistakes"].includes(part),
      )
    )
      throw new CliError(
        "CONFIG_INVALID",
        "session hooks require a durable installation outside temporary directories and git worktrees",
        [
          "Install with `npm install -g @knowttl/falcon-axi@next`, then run `falcon-axi setup hooks`",
        ],
      );
    for (
      let parent = dirname(path);
      parent !== dirname(parent);
      parent = dirname(parent)
    ) {
      try {
        if (statSync(join(parent, ".git")).isFile())
          throw new CliError(
            "CONFIG_INVALID",
            "session hooks require a durable installation outside temporary directories and git worktrees",
          );
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
}
