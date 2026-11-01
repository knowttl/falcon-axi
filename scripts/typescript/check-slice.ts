import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { join } from "node:path";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

const args = process.argv.slice(2);
const selections = new Map<string, string>();
for (let index = 0; index < args.length; index++) {
  const key = args[index]!;
  if (key === "--offline") selections.set(key, "true");
  else if (["--slice", "--paths"].includes(key) && args[index + 1])
    selections.set(key, args[++index]!);
  else {
    console.error(`Unknown selector ${key}`);
    process.exit(2);
  }
}
const paths = selections.get("--paths");
if (
  !["S01", "S02", "S03", "S04", "S05", "S06", "S07"].includes(
    selections.get("--slice") ?? "",
  ) ||
  selections.get("--offline") !== "true" ||
  !["native", "artium", "native,artium"].includes(paths ?? "")
) {
  console.error(
    "Required selectors: --slice S01|S02|S03|S04|S05|S06|S07 --paths native[,artium] --offline",
  );
  process.exit(2);
}
if (paths?.includes("artium") && !process.env.S01_ARTIUM_ROOT) {
  console.error("Real local Artium fixture is required for the requested path");
  process.exit(1);
}
// This process already runs inside a new network namespace. Only loopback is enabled.
const network = spawnSync("/usr/sbin/ip", ["link", "set", "lo", "up"], {
  encoding: "utf8",
});
if (network.status !== 0) {
  console.error(network.stderr);
  process.exit(1);
}
const tests = [
  fileURLToPath(
    new URL(
      `../../tests/typescript/${selections.get("--slice") === "S01" ? "s01" : ["S06", "S07"].includes(selections.get("--slice")!) ? "s06-s07" : ["S04", "S05"].includes(selections.get("--slice")!) ? "s04-s05" : "s02-s03"}.test.js`,
      import.meta.url,
    ),
  ),
];
const evidence =
  process.env.S01_EVIDENCE_DIR ??
  mkdtempSync(join(tmpdir(), "falcon-s01-proof-"));
mkdirSync(evidence, { recursive: true, mode: 0o700 });
const results: Record<string, unknown>[] = [];
for (const path of paths!.split(",")) {
  const result = spawnSync(
    process.execPath,
    ["--test", "--test-reporter=tap", ...tests],
    {
      cwd: resolve("."),
      encoding: "utf8",
      env: {
        ...process.env,
        S01_ACTIVE_PATH: path,
        S01_EVIDENCE_DIR: evidence,
      },
    },
  );
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  const count = (name: string): number =>
    Number(
      new RegExp(`^# ${name} (\\d+)$`, "m").exec(result.stdout ?? "")?.[1] ?? 0,
    );
  const expected = count("tests");
  results.push({
    path,
    expected,
    executed: count("pass") + count("fail"),
    passed: count("pass"),
    failed: count("fail"),
    skipped: count("skipped"),
    pending: count("todo") + count("cancelled"),
    exit: result.status,
  });
  writeFileSync(join(evidence, `${path}.tap`), result.stdout ?? "", {
    mode: 0o600,
  });
  if (result.status !== 0 || expected === 0 || count("pass") !== expected) {
    process.exitCode = result.status ?? 1;
    if (!process.exitCode) process.exitCode = 1;
    break;
  }
  if (selections.get("--slice") !== "S01") {
    const coverage = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./coverage.js", import.meta.url)),
        "--strict",
        "--evidence",
        evidence,
        "--path",
        path,
        "--slice",
        selections.get("--slice")!,
      ],
      { cwd: resolve("."), encoding: "utf8" },
    );
    process.stdout.write(coverage.stdout ?? "");
    process.stderr.write(coverage.stderr ?? "");
    if (coverage.status !== 0) {
      process.exitCode = coverage.status ?? 1;
      break;
    }
  }
}
writeFileSync(
  join(evidence, "result.json"),
  JSON.stringify(
    {
      slice: selections.get("--slice"),
      command: process.argv,
      results,
      nativeWindows: "pending",
      primitiveProof:
        "separate compiled gate: npm run probe:primitive; S11 acceptance pending",
    },
    null,
    2,
  ) + "\n",
  { mode: 0o600 },
);
console.log(`evidence: ${evidence}`);
