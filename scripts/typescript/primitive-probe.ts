/** Rejected Node-only approach, never an RTR implementation or a shipped CLI. */
import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
if (
  args.join(" ") !== "--slice S01 --paths native --offline" ||
  process.platform !== "linux"
) {
  console.log(
    JSON.stringify({
      error:
        "This Linux feasibility probe requires --slice S01 --paths native --offline",
      exit: 2,
    }),
  );
  process.exit(2);
}

const root = fs.mkdtempSync(join(tmpdir(), "falcon-s01-primitives-"));
const selected = join(root, "selected");
const moved = join(root, "retained");
const replacement = join(root, "replacement");
fs.mkdirSync(selected, { mode: 0o700 });
fs.mkdirSync(replacement, { mode: 0o700 });
const directory = fs.openSync(
  selected,
  fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
);

try {
  const expected = "synthetic original\n";
  const other = "synthetic replacement\n";
  fs.writeFileSync(join(selected, "writes.log"), expected, { mode: 0o600 });
  fs.writeFileSync(join(replacement, "writes.log"), other, { mode: 0o600 });

  // Control: O_NOFOLLOW rejects a final symlink on this runtime/filesystem.
  fs.symlinkSync(join(selected, "writes.log"), join(root, "final-link"));
  assert.throws(
    () =>
      fs.openSync(
        join(root, "final-link"),
        fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW,
      ),
    { code: "ELOOP" },
  );

  const checked = fs.fstatSync(directory);
  assert.equal(checked.uid, process.getuid?.());
  assert.equal(checked.mode & 0o077, 0);
  assert.equal(fs.lstatSync(selected).isSymbolicLink(), false);

  // Deterministic interleaving of a replacement between validation and open.
  fs.renameSync(selected, moved);
  fs.symlinkSync(replacement, selected);
  const file = fs.openSync(
    join(selected, "writes.log"),
    fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW,
  );
  try {
    const info = fs.fstatSync(file);
    assert.equal(info.uid, process.getuid?.());
    assert.equal(info.nlink, 1);
    assert.equal(info.mode & 0o077, 0);
    fs.writeSync(file, "synthetic append\n");
    fs.fsyncSync(file);
    fs.fsyncSync(directory);
  } finally {
    fs.closeSync(file);
  }

  assert.equal(fs.fstatSync(directory).ino, checked.ino);
  assert.equal(fs.readFileSync(join(moved, "writes.log"), "utf8"), expected);
  const followedAncestor =
    fs.readFileSync(join(replacement, "writes.log"), "utf8") ===
    `${other}synthetic append\n`;
  assert.equal(followedAncestor, true);

  console.log(
    JSON.stringify(
      {
        slice: "S01",
        candidate:
          "Node path open with O_NOFOLLOW and descriptor metadata checks",
        runtime: process.version,
        platform: process.platform,
        arch: process.arch,
        results: [
          { id: "final-symlink-refusal", status: "passed" },
          { id: "file-and-directory-fsync", status: "passed" },
          {
            id: "ancestor-replacement-refusal",
            status: "failed",
            observation:
              "append reached replacement despite retained directory descriptor",
          },
          { id: "descriptor-relative-open", status: "unproven" },
          { id: "nonblocking-retained-inode-lock", status: "unproven" },
          { id: "interrupted-durable-append", status: "unproven" },
        ],
        verdict:
          "STOP: Node-only substitute rejected; compiled narrow adapter not proved",
        limits:
          "No native dependency executed; no transport, output, installed CLI or Artium claim",
      },
      null,
      2,
    ),
  );
  process.exitCode = 1;
} finally {
  fs.closeSync(directory);
  fs.rmSync(root, { recursive: true, force: true });
}
