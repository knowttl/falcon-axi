import { createSocket } from "node:dgram";
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// Run only under unshare --user --map-root-user --net --mount.
// The resolver file is bind-mounted solely inside that private mount namespace.
const executable = process.argv[2];
if (!executable) throw new Error("Supply the installed candidate executable");
execFileSync("mount", ["--make-rprivate", "/"]);
execFileSync("/usr/sbin/ip", ["link", "set", "lo", "up"]);
const directory = await mkdtemp(join(tmpdir(), "falcon-dns-deadline-"));
const resolver = join(directory, "resolv.conf");
await writeFile(
  resolver,
  "nameserver 127.0.0.1\noptions timeout:3 attempts:1\n",
  { mode: 0o600 },
);
execFileSync("mount", ["--bind", resolver, "/etc/resolv.conf"]);
const dns = createSocket("udp4");
let queries = 0;
dns.on("message", () => {
  queries++;
});
await new Promise<void>((resolve) => dns.bind(53, "127.0.0.1", resolve));
const started = performance.now();
const child = spawn(
  executable,
  ["search", "status", "synthetic-job", "--wait", "1"],
  {
    env: {
      PATH: process.env.PATH,
      HOME: directory,
      FALCON_AXI_CLIENT_ID: "synthetic-dns-deadline-client",
      FALCON_AXI_CLIENT_SECRET: "synthetic-dns-deadline-secret",
    },
  },
);
let stdout = "";
let stderr = "";
let firstOutputMs: number | undefined;
child.stdout.on("data", (chunk: Buffer) => {
  firstOutputMs ??= performance.now() - started;
  stdout += chunk.toString();
});
child.stderr.on("data", (chunk: Buffer) => {
  stderr += chunk.toString();
});
const code = await new Promise<number | null>((resolve, reject) => {
  child.once("error", reject);
  child.once("close", resolve);
});
const settledMs = performance.now() - started;
await new Promise<void>((resolve) => dns.close(resolve));
execFileSync("umount", ["/etc/resolv.conf"]);
await rm(directory, { recursive: true, force: true });
const passed =
  code === 1 &&
  stdout.includes("code: WAIT_TIMEOUT") &&
  queries > 0 &&
  settledMs < 1600 &&
  !stderr;
console.log(
  JSON.stringify(
    {
      contract: "AC-DEADLINE OAuth inherited DNS settlement",
      configuredWaitMs: 1000,
      resolverTimeoutMs: 3000,
      queries,
      firstOutputMs,
      settledMs,
      code,
      stdout,
      stderr,
      passed,
    },
    null,
    2,
  ),
);
process.exitCode = passed ? 0 : 1;
