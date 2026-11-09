import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { installPacked } from "../../tests/typescript/install-packed.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const directory = mkdtempSync(join(tmpdir(), "falcon-package-contract "));
try {
  if (process.argv[2] !== "--socket-denied") {
    const deny = join(directory, "network-deny");
    execFileSync("/usr/bin/gcc", [
      "-B/usr/bin/",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-o",
      deny,
      join(root, "tests/typescript/network-deny.c"),
    ]);
    execFileSync(
      deny,
      [process.execPath, fileURLToPath(import.meta.url), "--socket-denied"],
      { cwd: root, stdio: "inherit", timeout: 25000 },
    );
  } else {
    const env = {
      PATH: process.env.PATH,
      HOME: directory,
    };
    const run = (command: string, args: string[], cwd = directory): string =>
      execFileSync(command, args, {
        cwd,
        env,
        encoding: "utf8",
        timeout: 20000,
        stdio: ["ignore", "pipe", "pipe"],
      });
    // Prove that npm and every installed child inherit the kernel socket deny.
    for (const host of ["192.0.2.1", "2001:db8::1"])
      await assert.rejects(
        new Promise<void>((resolve, reject) => {
          const socket = new Socket();
          socket.once("error", reject);
          socket.once("connect", () => {
            socket.destroy();
            resolve();
          });
          socket.connect(443, host);
        }),
        { code: "EPERM" },
      );
    const source = JSON.parse(
      readFileSync(join(root, "package.json"), "utf8"),
    ) as {
      name: string;
      version: string;
      bin: Record<string, string>;
    };
    const packs = JSON.parse(
      run(
        "npm",
        [
          "pack",
          "--offline",
          "--json",
          "--ignore-scripts",
          "--pack-destination",
          directory,
        ],
        root,
      ),
    ) as { filename: string; files: { path: string }[] }[];
    assert.equal(packs.length, 1);
    const pack = packs[0]!;
    const files = pack.files.map((file) => file.path);
    const required = [
      "package.json",
      "README.md",
      "LICENSE",
      ".typescript-build/src/bin.js",
      ".typescript-build/src/hook.js",
      ".typescript-build/src/version.js",
      ".typescript-build/src/cli.js",
      ".typescript-build/src/metadata.js",
      ".typescript-build/src/parser.js",
      ".typescript-build/src/axi-credential.schema.json",
      ".typescript-build/native/checksums.json",
      "native/prebuilds/linux-x64.node",
      "native/prebuilds/win32-x64.node",
      "artium-invocations.json",
      "skills/falcon-axi/SKILL.md",
    ];
    for (const path of required)
      assert.ok(files.includes(path), `Missing ${path}`);
    for (const path of files)
      assert.ok(
        required.includes(path) ||
          /^skills\/falcon-axi\/references\/[a-z][a-z0-9-]*\.md$/.test(path) ||
          /^\.typescript-build\/src\/(?:transport\/)?[a-z][a-z0-9-]*\.(?:js|json)$/.test(
            path,
          ),
        `Unexpected packaged file: ${path}`,
      );
    assert.equal(source.name, "@knowttl/falcon-axi");
    assert.deepEqual(source.bin, {
      "falcon-axi": ".typescript-build/src/bin.js",
      "falcon-axi-hook": ".typescript-build/src/hook.js",
    });
    installPacked(root, join(directory, pack.filename), directory);
    const installed = join(directory, "node_modules", source.name);
    const published = JSON.parse(
      readFileSync(join(installed, "package.json"), "utf8"),
    );
    assert.equal(published.name, source.name);
    assert.equal(published.version, source.version);
    assert.deepEqual(published.bin, source.bin);
    for (const path of files) {
      const content = readFileSync(join(installed, path), "utf8");
      assert.ok(!content.includes(root), `Checkout path in ${path}`);
      assert.ok(
        !/(?:\/home\/[^\s"']+|\/Users\/[^\s"']+|[A-Z]:\\Users\\|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|npm_[A-Za-z0-9]{36}|gh[pousr]_[A-Za-z0-9]{36})/.test(
          content,
        ),
        `Private material in ${path}`,
      );
    }
    const bin = join(directory, "node_modules/.bin/falcon-axi");
    assert.equal(run(bin, ["--version"]).trim(), source.version);
    const help = run(bin, ["--help"]);
    assert.ok(help.startsWith(`falcon-axi ${source.version} - `));
    assert.match(help, /^  detection list\s/m);
    assert.match(help, /^  setup hooks\s/m);
    const hook = join(directory, "node_modules/.bin/falcon-axi-hook");
    assert.match(run(hook, []), /^falcon-axi \S+: profile unresolved/);
    const catalog = JSON.parse(
      readFileSync(join(installed, "artium-invocations.json"), "utf8"),
    ) as {
      executable: string;
      hook: string;
      parser: { path: string; sha256: string };
      schema: { path: string; sha256: string };
      skill: { path: string; sha256: string };
    };
    assert.equal(catalog.executable, source.bin["falcon-axi"]);
    assert.equal(catalog.hook, source.bin["falcon-axi-hook"]);
    for (const entry of [catalog.parser, catalog.schema, catalog.skill]) {
      assert.ok(files.includes(entry.path));
      assert.equal(
        createHash("sha256")
          .update(readFileSync(join(installed, entry.path)))
          .digest("hex"),
        entry.sha256,
      );
    }
    // Artium imports metadata for admission and pins the parser and schema paths.
    const metadata = await import(
      pathToFileURL(join(installed, ".typescript-build/src/metadata.js")).href
    );
    assert.ok(
      metadata.commands.some(
        (command: { name: string }) => command.name === "detection list",
      ),
    );
    assert.ok(metadata.valueFlags.includes("--profile"));
    assert.ok(metadata.boolFlags.includes("--help"));
    const cli = await import(
      pathToFileURL(join(installed, ".typescript-build/src/cli.js")).href
    );
    assert.equal(typeof cli.main, "function");
    const schema = JSON.parse(
      readFileSync(
        join(installed, ".typescript-build/src/axi-credential.schema.json"),
        "utf8",
      ),
    );
    assert.equal(schema.type, "object");
    console.log(
      "package-contract: packed shape, offline install, bin and admission imports passed",
    );
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
}
