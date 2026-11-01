import { rmSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const pins = JSON.parse(
  readFileSync(join(root, "native/checksums.json"), "utf8"),
) as Record<string, string>;
const provenance = JSON.parse(
  readFileSync(join(root, "native/provenance.json"), "utf8"),
) as { inputs: Record<string, string> };
for (const [path, expected] of Object.entries({
  ...provenance.inputs,
  ...Object.fromEntries(
    Object.entries(pins).map(([name, hash]) => [
      `native/prebuilds/${name}`,
      hash,
    ]),
  ),
})) {
  if (
    createHash("sha256")
      .update(readFileSync(join(root, path)))
      .digest("hex") !== expected
  )
    throw new Error(
      `Native artifact provenance mismatch: ${path}; maintainer rebuild required`,
    );
}
// A deleted source must not survive in the allowlisted npm build directory.
rmSync(join(root, ".typescript-build"), { recursive: true, force: true });
const result = spawnSync(
  process.execPath,
  [join(root, "node_modules/typescript/bin/tsc"), "-p", "tsconfig.json"],
  { cwd: root, stdio: "inherit" },
);
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
