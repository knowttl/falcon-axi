import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { join } from "node:path";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { rtrCoverage } from "./rtr-coverage.js";
import { finalCoverage } from "./final-coverage.js";

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
const slice = selections.get("--slice") ?? "";
if (
  ![
    "S01",
    "S02",
    "S03",
    "S04",
    "S05",
    "S06",
    "S07",
    "S08",
    "S09",
    "S10",
    "S11",
    "S12",
    "S13",
  ].includes(slice) ||
  selections.get("--offline") !== "true" ||
  !["native", "artium", "native,artium"].includes(paths ?? "")
) {
  console.error(
    "Required selectors: --slice S01|S02|S03|S04|S05|S06|S07|S08|S09|S10|S11|S12|S13 --paths native[,artium] --offline",
  );
  process.exit(2);
}
if (paths?.includes("artium") && !process.env.S01_ARTIUM_ROOT) {
  console.error("Real local Artium fixture is required for the requested path");
  process.exit(1);
}
const rtr = slice === "S11";
const complete = slice === "S13";
if (complete && paths === "artium") {
  console.error(
    "S13 hosted acceptance requires --paths native,artium to include its native prerequisites",
  );
  process.exit(2);
}
const evidence =
  process.env.S01_EVIDENCE_DIR ??
  mkdtempSync(join(tmpdir(), "falcon-s01-proof-"));
mkdirSync(evidence, { recursive: true, mode: 0o700 });
function reportFailure(
  check: string,
  result: Pick<ReturnType<typeof spawnSync>, "error" | "signal" | "status">,
): void {
  const detail =
    result.error?.message ??
    (result.signal ? `signal ${result.signal}` : `exit ${result.status}`);
  console.error(`${slice}: ${check} failed (${detail})`);
}

if (complete) {
  for (const [script, ...arguments_] of [
    ["generate.js", "--check"],
    ["architecture.js"],
    ["coverage.js", "--strict"],
  ]) {
    const result = spawnSync(
      process.execPath,
      [fileURLToPath(new URL(`./${script}`, import.meta.url)), ...arguments_],
      { stdio: "inherit" },
    );
    if (result.status !== 0) {
      reportFailure(script, result);
      process.exit(result.status ?? 1);
    }
  }
  for (const prerequisite of ["S10", "S11"]) {
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(import.meta.url),
        "--slice",
        prerequisite,
        "--paths",
        paths!,
        "--offline",
      ],
      {
        stdio: "inherit",
        env: { ...process.env, S01_EVIDENCE_DIR: join(evidence, prerequisite) },
      },
    );
    if (result.status !== 0) {
      reportFailure(`${prerequisite} prerequisite`, result);
      process.exit(result.status ?? 1);
    }
  }
}
const installation = complete || slice === "S12";
const restricted = rtr || installation;
if (!restricted && !process.env.FALCON_TEST_NAMESPACED) {
  const result = spawnSync(
    "unshare",
    [
      "--user",
      "--map-root-user",
      "--net",
      "--mount",
      process.execPath,
      fileURLToPath(import.meta.url),
      ...args,
    ],
    {
      stdio: "inherit",
      env: { ...process.env, FALCON_TEST_NAMESPACED: "1" },
    },
  );
  if (result.status !== 0)
    reportFailure(result.error ? "unshare" : "namespaced slice", result);
  process.exit(result.status ?? 1);
}
// Ordinary-read checks use loopback in a network namespace; RTR retains real inode ownership.
if (!restricted) {
  const network = spawnSync("/usr/sbin/ip", ["link", "set", "lo", "up"], {
    encoding: "utf8",
  });
  if (network.status !== 0) {
    if (network.stderr) process.stderr.write(network.stderr);
    reportFailure("/usr/sbin/ip link set lo up", network);
    process.exit(1);
  }
}
const tests = [
  fileURLToPath(
    new URL(
      `../../tests/typescript/${complete ? "s13" : installation ? "s12" : rtr ? "s11" : ["S08", "S09", "S10"].includes(slice) ? "s08-s10" : slice === "S01" ? "s01" : ["S06", "S07"].includes(slice) ? "s06-s07" : ["S04", "S05"].includes(slice) ? "s04-s05" : "s02-s03"}.test.js`,
      import.meta.url,
    ),
  ),
];
const deny = join(evidence, "network-deny");
if (restricted) {
  const compile = spawnSync(
    "/usr/bin/gcc",
    [
      "-B/usr/bin/",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-o",
      deny,
      fileURLToPath(
        new URL("../../../tests/typescript/network-deny.c", import.meta.url),
      ),
    ],
    { stdio: "inherit" },
  );
  if (compile.status !== 0) {
    reportFailure("/usr/bin/gcc network-deny build", compile);
    process.exit(1);
  }
}
const results: Record<string, unknown>[] = [];
for (const path of paths!.split(",")) {
  const nativeRtr = restricted && path === "native";
  let primitives = "";
  if (nativeRtr && rtr) {
    const probe = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./primitive-probe.js", import.meta.url)),
        "--slice",
        "S01",
        "--paths",
        "native",
        "--offline",
      ],
      { encoding: "utf8" },
    );
    process.stdout.write(probe.stdout ?? "");
    process.stderr.write(probe.stderr ?? "");
    primitives = probe.stdout ?? "";
    writeFileSync(join(evidence, "native-primitives.tap"), primitives, {
      mode: 0o600,
    });
    if (probe.status !== 0) {
      reportFailure("primitive-probe.js", probe);
      process.exitCode = probe.status ?? 1;
      break;
    }
  }
  const result = spawnSync(
    nativeRtr ? deny : process.execPath,
    [
      ...(nativeRtr ? [process.execPath] : []),
      "--test",
      "--test-reporter=tap",
      ...(rtr ? ["--test-name-pattern=S11"] : []),
      ...(installation
        ? [complete ? "--test-name-pattern=S1[23]" : "--test-name-pattern=S12"]
        : []),
      ...(rtr && path === "artium"
        ? [
            fileURLToPath(
              new URL(
                "../../tests/typescript/s11-artium.test.js",
                import.meta.url,
              ),
            ),
          ]
        : [
            ...tests,
            ...(complete && path === "artium"
              ? [
                  fileURLToPath(
                    new URL(
                      "../../tests/typescript/s13-artium.test.js",
                      import.meta.url,
                    ),
                  ),
                ]
              : []),
          ]),
    ],
    {
      cwd: resolve("."),
      encoding: "utf8",
      env: {
        ...process.env,
        S01_ACTIVE_PATH: path,
        S01_EVIDENCE_DIR: evidence,
        ...(restricted
          ? { S11_SOCKET_DELIVERY: "1", S11_DENY_LAUNCHER: deny }
          : {}),
        ...(installation ? { S12_INSTALL_CHECK: "1" } : {}),
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
  if (
    result.status !== 0 ||
    expected === 0 ||
    count("fail") !== 0 ||
    count("pass") + count("skipped") !== expected
  ) {
    if (result.status === 0)
      console.error(`${slice}: ${path} TAP validation failed (invalid totals)`);
    else reportFailure(`${path} TAP tests`, result);
    process.exitCode = result.status || 1;
    break;
  }
  if (rtr) {
    writeFileSync(
      join(evidence, `${path}-coverage.json`),
      JSON.stringify(
        rtrCoverage(path, result.stdout ?? "", primitives),
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );
  } else if (complete) {
    writeFileSync(
      join(evidence, `${path}-coverage.json`),
      JSON.stringify(finalCoverage(path, evidence), null, 2) + "\n",
      { mode: 0o600 },
    );
  } else if (!installation && slice !== "S01") {
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
        slice,
      ],
      { cwd: resolve("."), encoding: "utf8" },
    );
    process.stdout.write(coverage.stdout ?? "");
    process.stderr.write(coverage.stderr ?? "");
    if (coverage.status !== 0) {
      reportFailure(`${path} coverage.js`, coverage);
      process.exitCode = coverage.status ?? 1;
      break;
    }
  }
}
writeFileSync(
  join(evidence, "result.json"),
  JSON.stringify(
    {
      slice,
      command: process.argv,
      results,
      nativeWindows: "pending",
      primitiveProof: rtr
        ? "compiled gate repeated with native S11 lifecycle"
        : "separate compiled gate: npm run probe:primitive",
    },
    null,
    2,
  ) + "\n",
  { mode: 0o600 },
);
console.log(`evidence: ${evidence}`);
