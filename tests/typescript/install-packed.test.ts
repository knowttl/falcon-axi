import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { installPacked } from "./install-packed.js";

test("S13 packed binaries use only copied runtime dependencies", () => {
  const root = mkdtempSync(join(process.cwd(), ".install-packed-test-"));
  try {
    const checkout = join(root, "checkout");
    const packageDirectory = join(root, "archive/package");
    const prefix = join(root, "prefix");
    const direct = join(checkout, "node_modules/direct");
    const transitive = join(direct, "node_modules/transitive");
    mkdirSync(transitive, { recursive: true });
    mkdirSync(packageDirectory, { recursive: true });
    mkdirSync(prefix);
    writeFileSync(
      join(direct, "package.json"),
      JSON.stringify({ name: "direct", dependencies: { transitive: "1" } }),
    );
    writeFileSync(
      join(direct, "index.js"),
      'module.exports = require("transitive");',
    );
    writeFileSync(
      join(transitive, "package.json"),
      JSON.stringify({ name: "transitive" }),
    );
    writeFileSync(join(transitive, "index.js"), 'module.exports = "copied";');
    writeFileSync(
      join(packageDirectory, "package.json"),
      JSON.stringify({
        name: "example",
        bin: { example: "bin.js" },
        dependencies: { direct: "1" },
      }),
    );
    writeFileSync(
      join(packageDirectory, "bin.js"),
      '#!/usr/bin/env node\nconsole.log(require("direct"));\n',
    );
    const tarball = join(root, "package.tgz");
    execFileSync("tar", [
      "-czf",
      tarball,
      "-C",
      join(root, "archive"),
      "package",
    ]);
    installPacked(checkout, tarball, prefix);
    rmSync(checkout, { recursive: true });
    assert.equal(
      execFileSync(join(prefix, "node_modules/.bin/example"), {
        encoding: "utf8",
      }),
      "copied\n",
    );
    assert.throws(() =>
      execFileSync(process.execPath, ["-e", 'require("transitive")'], {
        cwd: join(prefix, "node_modules/example"),
        stdio: "pipe",
      }),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
