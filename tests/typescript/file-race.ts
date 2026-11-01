import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";

// Test-owned filesystem delivery boundary, excluded from the npm artifact.
const original = fs.open;
if (process.env.S02_OWNER_MISMATCH === "1") {
  const uid = process.getuid!();
  process.getuid = () => uid + 1;
}
fs.open = (async (path, flags, mode) => {
  if (path === process.env.S02_RACE_CONFIG) {
    await fs.rename(path, `${String(path)}.before`);
    await fs.symlink(process.env.S02_RACE_TARGET!, path);
  }
  return original(path, flags, mode);
}) as typeof fs.open;
syncBuiltinESMExports();
