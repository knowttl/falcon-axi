import assert from "node:assert/strict";
import { test, after } from "node:test";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { openRetainedFile } from "../../src/rtr-filesystem.js";

const root = fs.mkdtempSync(join(tmpdir(), "falcon-native-"));
after(() => fs.rmSync(root, { recursive: true, force: true }));
const worker = fileURLToPath(new URL("./native-worker.js", import.meta.url));

test("the process-level offline deny survives child launch for IPv4 and IPv6", () => {
  for (const address of ["127.0.0.1", "::1"]) {
    const child = spawnSync(
      process.execPath,
      [worker, "network-deny", address],
      { encoding: "utf8", timeout: 5000 },
    );
    assert.equal(child.status, 0, child.stderr);
  }
});

test("the installed artifact executes its prebuild and keeps reads and Windows refusal independent of it", () => {
  const directory = fs.mkdtempSync(join(root, "installed-"));
  const pack = spawnSync(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", directory],
    { encoding: "utf8" },
  );
  assert.equal(pack.status, 0, pack.stderr);
  const artifact = (JSON.parse(pack.stdout) as { filename: string }[])[0]!;
  const install = spawnSync(
    "npm",
    [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--prefix",
      directory,
      join(directory, artifact.filename),
    ],
    { encoding: "utf8" },
  );
  assert.equal(install.status, 0, install.stderr);
  const packageRoot = join(directory, "node_modules/@knowttl/falcon-axi");
  const adapter = pathToFileURL(
    join(packageRoot, ".typescript-build/src/rtr-filesystem.js"),
  ).href;
  const path = join(directory, "journal");
  const invoke = (mode: string) =>
    spawnSync(process.execPath, [worker, mode, path, adapter], {
      encoding: "utf8",
      timeout: 5000,
    });
  const append = invoke("append");
  assert.equal(append.status, 0, append.stderr);
  assert.equal(fs.readFileSync(path, "utf8"), "synthetic intent\n");
  const binary = join(packageRoot, "native/prebuilds/linux-x64.node");
  fs.appendFileSync(binary, "tampered");
  const corrupted = invoke("lock");
  assert.equal(corrupted.status, 1, corrupted.stderr);
  assert.equal(corrupted.stdout.trim(), "CONFIG_INSECURE");
  fs.rmSync(join(packageRoot, "native"), { recursive: true });
  for (const args of [
    ["--version"],
    ["detection", "list", "--help"],
    ["rtr", "session", "list", "--help"],
  ]) {
    const cli = spawnSync(
      process.execPath,
      [join(packageRoot, ".typescript-build/src/bin.js"), ...args],
      { encoding: "utf8", timeout: 5000 },
    );
    assert.equal(cli.status, 0, cli.stdout + cli.stderr);
    assert.ok(cli.stdout.length > 0);
  }
  const windows = invoke("windows");
  assert.equal(windows.status, 0, windows.stderr);
});

test("append stays on the retained inode after ancestor replacement", () => {
  const selected = join(root, "selected");
  const moved = join(root, "retained");
  const replacement = join(root, "replacement");
  fs.mkdirSync(selected, { mode: 0o700 });
  fs.mkdirSync(replacement, { mode: 0o700 });
  fs.writeFileSync(join(replacement, "writes.log"), "replacement\n", {
    mode: 0o600,
  });
  const file = openRetainedFile(join(selected, "writes.log"));
  try {
    fs.renameSync(selected, moved);
    fs.symlinkSync(replacement, selected);
    file.append(Buffer.from("synthetic append\n"));
    assert.equal(
      fs.readFileSync(join(moved, "writes.log"), "utf8"),
      "synthetic append\n",
    );
    assert.equal(
      fs.readFileSync(join(replacement, "writes.log"), "utf8"),
      "replacement\n",
    );
    assert.throws(() => openRetainedFile(join(selected, "writes.log")), {
      code: "CONFIG_INSECURE",
    });
  } finally {
    file.close();
  }
});

for (const target of ["file", "directory"]) {
  test(`append refuses newly unsafe retained ${target} permissions`, () => {
    const directory = fs.mkdtempSync(join(root, "changed-"));
    const path = join(directory, "journal");
    const file = openRetainedFile(path);
    try {
      fs.chmodSync(
        target === "file" ? path : directory,
        target === "file" ? 0o644 : 0o770,
      );
      assert.throws(() => file.append(Buffer.from("must refuse\n")), {
        code: "CONFIG_INSECURE",
      });
      assert.equal(fs.readFileSync(path, "utf8"), "");
    } finally {
      file.close();
    }
  });
}

for (const kind of ["symlink", "hardlink", "public", "directory", "fifo"]) {
  test(`refuses the origin's unsafe ${kind} target`, () => {
    const directory = fs.mkdtempSync(join(root, "unsafe-"));
    const source = join(directory, "source");
    const path = join(directory, "journal");
    fs.writeFileSync(source, "", { mode: 0o600 });
    if (kind === "symlink") fs.symlinkSync(source, path);
    if (kind === "hardlink") fs.linkSync(source, path);
    if (kind === "public") fs.writeFileSync(path, "", { mode: 0o644 });
    if (kind === "directory") fs.mkdirSync(path);
    if (kind === "fifo") assert.equal(spawnSync("mkfifo", [path]).status, 0);
    assert.throws(() => openRetainedFile(path), { code: "CONFIG_INSECURE" });
    assert.equal(fs.readFileSync(source, "utf8"), "");
  });
}

for (const mode of [0o770, 0o777, 0o700, 0o755, 0o1777]) {
  test(`ancestor mode ${mode.toString(8)} preserves the origin's traversal policy`, () => {
    const parent = fs.mkdtempSync(join(root, "ancestor-"));
    fs.chmodSync(parent, mode);
    const path = join(parent, "private", "journal");
    if (mode === 0o770 || mode === 0o777) {
      assert.throws(() => openRetainedFile(path), { code: "CONFIG_INSECURE" });
      assert.equal(fs.existsSync(join(parent, "private")), false);
    } else {
      const file = openRetainedFile(path);
      try {
        file.append(Buffer.from("synthetic\n"));
      } finally {
        file.close();
      }
      assert.equal(fs.statSync(path).mode & 0o777, 0o600);
      assert.equal(fs.readFileSync(path, "utf8"), "synthetic\n");
    }
  });
}

test("nonblocking lock excludes another process until close and retains the empty inode", () => {
  const path = join(root, "rtr-synthetic.lock");
  const lock = openRetainedFile(path, true);
  const inode = fs.statSync(path).ino;
  try {
    const contender = spawnSync(process.execPath, [worker, "lock", path], {
      encoding: "utf8",
      timeout: 5000,
    });
    assert.equal(contender.status, 1, contender.stderr);
    assert.equal(contender.stdout.trim(), "READ_ONLY_VIOLATION");
  } finally {
    lock.close();
  }
  const next = spawnSync(process.execPath, [worker, "lock", path], {
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(next.status, 0, next.stderr);
  assert.equal(next.stdout.trim(), "acquired");
  assert.equal(fs.statSync(path).ino, inode);
  assert.equal(fs.readFileSync(path).length, 0);
});

test("interrupted and short writes finish once; an unconfirmed flush poisons the handle", () => {
  const shim = join(root, "fault.so");
  const source = fileURLToPath(
    new URL("../../../tests/typescript/native-fault.c", import.meta.url),
  );
  const build = spawnSync(
    "cc",
    [
      "-shared",
      "-fPIC",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-o",
      shim,
      source,
      "-ldl",
    ],
    { encoding: "utf8" },
  );
  assert.equal(build.status, 0, build.stderr);
  for (const fault of [
    "interrupted",
    "flush-failure",
    "directory-flush-failure",
  ]) {
    const path = join(root, `${fault}.log`);
    const child = spawnSync(process.execPath, [worker, fault, path], {
      encoding: "utf8",
      timeout: 5000,
      env: {
        ...process.env,
        LD_PRELOAD: shim,
        FALCON_TEST_FILE: path,
        FALCON_TEST_FAULT: fault,
        FALCON_TEST_DIRECTORY: root,
      },
    });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(fs.readFileSync(path, "utf8"), "synthetic intent\n");
  }
});
