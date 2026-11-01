/** Compiled primitive proof only; full RTR lifecycle acceptance remains S11. */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (
  process.argv.slice(2).join(" ") !== "--slice S01 --paths native --offline" ||
  process.platform !== "linux"
) {
  console.error(
    "Required Linux primitive selectors: --slice S01 --paths native --offline",
  );
  process.exit(2);
}
const directory = mkdtempSync(join(tmpdir(), "falcon-native-launcher-"));
try {
  const launcher = join(directory, "network-deny");
  const compile = spawnSync(
    "cc",
    [
      "-Wall",
      "-Wextra",
      "-Werror",
      "-o",
      launcher,
      fileURLToPath(
        new URL("../../../tests/typescript/network-deny.c", import.meta.url),
      ),
    ],
    { stdio: "inherit" },
  );
  if (compile.status !== 0)
    throw new Error("Offline network deny launcher failed to compile");
  const result = spawnSync(
    launcher,
    [
      process.execPath,
      "--test",
      fileURLToPath(
        new URL(
          "../../tests/typescript/native-filesystem.test.js",
          import.meta.url,
        ),
      ),
    ],
    { stdio: "inherit" },
  );
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(directory, { recursive: true, force: true });
}
