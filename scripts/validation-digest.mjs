import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";

const digestPath = ".no-mistakes/validation-failure-digest.txt";
const failurePattern =
  /^\s*not ok\b|^# fail [1-9]|\[warn\]|error TS\d+|ELIFECYCLE|^[\w-]+: .*\bfailed\b/;
const maxFailureLines = 60;
const tailLines = 30;

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error("Expected a validation command");
rmSync(digestPath, { force: true });

const chunks = [];
const child = spawn(command, args, { stdio: ["inherit", "pipe", "pipe"] });
for (const [source, sink] of [
  [child.stdout, process.stdout],
  [child.stderr, process.stderr],
]) {
  source.on("data", (chunk) => chunks.push(chunk));
  source.pipe(sink, { end: false });
}
const [status, signal] = await new Promise((resolve, reject) => {
  child.on("error", reject);
  child.on("close", (code, killedBy) => resolve([code, killedBy]));
});

if (status !== 0) {
  const lines = Buffer.concat(chunks).toString("utf8").trimEnd().split("\n");
  const failureLines = lines.filter((line) => failurePattern.test(line));
  const digest = [
    "===== validation failure digest =====",
    `Command: ${[command, ...args].join(" ")}`,
    `Exit status: ${status ?? `signal ${signal}`}`,
    "--- failure lines ---",
    ...(failureLines.length === 0
      ? ["(no recognized failure lines; read the last lines)"]
      : failureLines.slice(0, maxFailureLines)),
    ...(failureLines.length > maxFailureLines
      ? [`... ${failureLines.length - maxFailureLines} more`]
      : []),
    `--- last ${tailLines} lines ---`,
    ...lines.slice(-tailLines),
    "",
  ].join("\n");
  mkdirSync(".no-mistakes", { recursive: true });
  writeFileSync(digestPath, digest);
}
process.exitCode = status ?? 1;
