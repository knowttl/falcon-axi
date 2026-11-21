import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";

const digestPath = ".no-mistakes/validation-failure-digest.txt";
const failurePattern =
  /^\s*not ok\b|\[warn\]|error TS\d+|^[\w-]+: .*\bfailed\b/;
const maxFailureLines = 60;
const tailLines = 30;

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error("Expected a validation command");
rmSync(digestPath, { force: true });

const stdoutChunks = [];
const stderrChunks = [];
const child = spawn(command, args, { stdio: ["inherit", "pipe", "pipe"] });
for (const [source, sink, chunks] of [
  [child.stdout, process.stdout, stdoutChunks],
  [child.stderr, process.stderr, stderrChunks],
]) {
  source.on("data", (chunk) => chunks.push(chunk));
  source.pipe(sink, { end: false });
}
let spawnError;
const [code, signal] = await new Promise((resolve) => {
  child.on("error", (error) => {
    spawnError = error;
  });
  child.on("close", (code, killedBy) => resolve([code, killedBy]));
});
const status = spawnError ? 1 : code;
if (spawnError) {
  const line = `validation: ${command} failed to start: ${spawnError.message}\n`;
  process.stderr.write(line);
  stderrChunks.push(Buffer.from(line));
}

if (status !== 0) {
  const [stdoutLines, stderrLines] = [stdoutChunks, stderrChunks].map(
    (chunks) => Buffer.concat(chunks).toString("utf8").trimEnd().split("\n"),
  );
  const failureLines = [...stdoutLines, ...stderrLines].filter((line) =>
    failurePattern.test(line),
  );
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
    `--- last ${tailLines} stdout lines ---`,
    ...stdoutLines.slice(-tailLines),
    `--- last ${tailLines} stderr lines ---`,
    ...stderrLines.slice(-tailLines),
    "",
  ].join("\n");
  mkdirSync(".no-mistakes", { recursive: true, mode: 0o700 });
  writeFileSync(digestPath, digest, { mode: 0o600 });
}
process.exitCode = status ?? 1;
