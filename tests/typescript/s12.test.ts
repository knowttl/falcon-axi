import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync, spawnSync } from "node:child_process";
import {
  readFile,
  writeFile,
  mkdir,
  stat,
  realpath,
  cp,
  rm,
  mkdtemp,
  chmod,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { decode } from "@toon-format/toon";
import { parseTOML, getStaticTOMLValue } from "toml-eslint-parser";
import { directory, executable, run } from "./s01.test.js";

const paths = [
  ".claude/settings.json",
  ".codex/hooks.json",
  ".codex/config.toml",
  ".config/opencode/plugins/axi-falcon-axi.js",
];
test("S12 PATH and absolute setup install identical hooks that run with minimal PATH", async () => {
  const home = join(directory, "path invocation home");
  await mkdir(home);
  const setup = spawnSync("falcon-axi", ["setup", "hooks"], {
    cwd: home,
    encoding: "utf8",
    env: {
      HOME: home,
      PATH: `${dirname(executable)}:${dirname(process.execPath)}`,
    },
  });
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  const snapshot = await Promise.all(
    paths.map((path) => readFile(join(home, path), "utf8")),
  );
  const document = JSON.parse(snapshot[0]!) as {
    hooks: { SessionStart: { hooks: { command: string }[] }[] };
  };
  const result = spawnSync(document.hooks.SessionStart[0]!.hooks[0]!.command, {
    shell: true,
    cwd: home,
    encoding: "utf8",
    env: { HOME: home, PATH: "/usr/bin:/bin" },
    timeout: 10000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /^falcon-axi \S+: profile unresolved \(PROFILE_REQUIRED\).*\n$/,
  );
  assert.match(
    (await invoke(home, ["setup", "hooks"])).stdout,
    /status: unchanged/,
  );
  assert.deepEqual(
    await Promise.all(paths.map((path) => readFile(join(home, path), "utf8"))),
    snapshot,
  );
});
test("S12 PATH shadow cannot redirect an installed session hook", async () => {
  const home = join(directory, "shadow home");
  const shadow = join(directory, "shadow bin");
  await mkdir(home);
  await mkdir(shadow);
  await writeFile(
    join(shadow, "falcon-axi-hook"),
    '#!/bin/sh\nprintf "wrong-hook\\n"\n',
  );
  await chmod(join(shadow, "falcon-axi-hook"), 0o700);
  const environment = {
    HOME: home,
    PATH: `${shadow}:${dirname(executable)}:${dirname(process.execPath)}`,
  };
  const setup = spawnSync(
    process.execPath,
    [await realpath(executable), "setup", "hooks"],
    { cwd: home, encoding: "utf8", env: environment },
  );
  assert.equal(setup.status, 0, setup.stdout + setup.stderr);
  const document = JSON.parse(
    await readFile(join(home, paths[0]!), "utf8"),
  ) as { hooks: { SessionStart: { hooks: { command: string }[] }[] } };
  const command = document.hooks.SessionStart[0]!.hooks[0]!.command;
  const result = spawnSync(command, {
    shell: true,
    cwd: home,
    encoding: "utf8",
    env: environment,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^falcon-axi \S+: profile unresolved/);
});
async function invoke(
  home: string,
  args: string[],
  entry?: string,
): Promise<{ code: number | null; stdout: string }> {
  const result = spawnSync(
    process.execPath,
    [entry ?? (await realpath(executable)), ...args],
    {
      cwd: home,
      encoding: "utf8",
      env: {
        HOME: home,
        PATH: dirname(process.execPath),
        FALCON_AXI_CONFIG: join(home, "missing-config.json"),
      },
    },
  );
  assert.equal(result.stderr, "");
  return { code: result.status, stdout: result.stdout };
}

test("S12 emitted hooks execute outside PATH, remain unchanged, and repair relocation", async () => {
  const home = join(directory, "hook home");
  await mkdir(join(home, ".codex"), { recursive: true });
  await mkdir(join(home, ".claude"));
  const other = {
    matcher: "startup",
    hooks: [{ type: "command", command: "another-tool", timeout: 3 }],
  };
  await writeFile(
    join(home, paths[0]!),
    JSON.stringify({ theme: "dark", hooks: { SessionStart: [other] } }),
  );
  const config =
    '# keep this\nmodel = "example"\n[features]\nhooks = false # hook setting\nother = true\n';
  await writeFile(join(home, paths[2]!), config);
  assert.match(
    (await invoke(home, ["setup", "hooks"])).stdout,
    /status: installed/,
  );
  const settingsPath = join(home, paths[0]!);
  const settings = JSON.parse(await readFile(settingsPath, "utf8")) as {
    hooks: {
      SessionStart: {
        hooks: { command: string; timeout: number; type: string }[];
      }[];
    };
  };
  const owned = settings.hooks.SessionStart[1]!.hooks[0]!;
  settings.hooks.SessionStart[1]!.hooks[0] = {
    timeout: owned.timeout,
    command: owned.command,
    type: owned.type,
  };
  await writeFile(settingsPath, JSON.stringify(settings, null, 2) + "\n");
  const snapshot = await Promise.all(
    paths.map(async (path) => [
      await readFile(join(home, path), "utf8"),
      (await stat(join(home, path), { bigint: true })).mtimeNs,
    ]),
  );
  const hook = JSON.parse(snapshot[0]![0] as string) as {
    theme: string;
    hooks: { SessionStart: { hooks: { command: string }[] }[] };
  };
  assert.equal(hook.theme, "dark");
  assert.deepEqual(hook.hooks.SessionStart[0], other);
  const command = hook.hooks.SessionStart[1]!.hooks[0]!.command;
  const emitted = spawnSync(command, {
    shell: true,
    cwd: home,
    encoding: "utf8",
    env: { HOME: home, PATH: dirname(process.execPath) },
  });
  assert.equal(emitted.status, 0, emitted.stderr);
  assert.match(
    emitted.stdout,
    /^falcon-axi \S+: profile unresolved \(PROFILE_REQUIRED\).*\n$/,
  );
  const plugin = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
    import {readFileSync} from 'node:fs';
    const {FalconAxi} = await import('data:text/javascript;base64,' + Buffer.from(readFileSync(process.argv[1], 'utf8')).toString('base64'));
    const hooks = await FalconAxi({directory: process.cwd()});
    const output = {system: ['existing context']};
    await hooks['experimental.chat.system.transform']({}, output);
    console.log(JSON.stringify(output));
  `,
      join(home, paths[3]!),
    ],
    {
      cwd: home,
      encoding: "utf8",
      env: { HOME: home, PATH: dirname(process.execPath) },
    },
  );
  assert.match(plugin, /existing context.*profile unresolved/);
  assert.match(
    (await invoke(home, ["setup", "hooks"])).stdout,
    /status: unchanged/,
  );
  assert.deepEqual(
    await Promise.all(
      paths.map(async (path) => [
        await readFile(join(home, path), "utf8"),
        (await stat(join(home, path), { bigint: true })).mtimeNs,
      ]),
    ),
    snapshot,
  );
  const relocated = join(directory, "relocated installation");
  await cp(join(directory, "clean install"), relocated, {
    recursive: true,
    verbatimSymlinks: true,
  });
  const entry = await realpath(join(relocated, "node_modules/.bin/falcon-axi"));
  assert.match(
    (await invoke(home, ["setup", "hooks"], entry)).stdout,
    /status: installed/,
  );
  assert.match(
    await readFile(join(home, paths[0]!), "utf8"),
    /relocated installation/,
  );
  assert.match(await readFile(join(home, paths[2]!), "utf8"), /# keep this/);
  await rm(relocated, { recursive: true });
});

test("S12 installed executable identity matches package version", async () => {
  const home = directory;
  const entry = await realpath(executable);
  const pkg = JSON.parse(
    await readFile(
      join(dirname(dirname(dirname(entry))), "package.json"),
      "utf8",
    ),
  ) as { version: string };
  for (const flag of ["-v", "-V", "--version"]) {
    const version = await invoke(home, [flag]);
    assert.equal(version.code, 0);
    assert.equal(version.stdout, pkg.version + "\n");
  }
  const result = spawnSync(process.execPath, [entry], {
    cwd: home,
    encoding: "utf8",
    env: {
      HOME: home,
      PATH: `${dirname(executable)}:${dirname(process.execPath)}`,
    },
  });
  const document = decode(result.stdout) as { bin: string };
  const identity = spawnSync(`${document.bin} --version`, {
    shell: true,
    cwd: home,
    encoding: "utf8",
    env: { HOME: home, PATH: dirname(process.execPath) },
  });
  assert.equal(identity.status, 0, identity.stderr);
  assert.equal(identity.stdout, pkg.version + "\n");
});

for (const kind of [
  "temporary",
  "worktree",
  ".treehouse",
  "worktrees",
  ".no-mistakes",
])
  test(`S12 non-durable installation refuses before configuration ${kind}`, async () => {
    const scratch =
      kind === "temporary"
        ? await mkdtemp(join(tmpdir(), "falcon-s12-"))
        : join(directory, "durability", kind);
    try {
      const installation = join(scratch, "installation");
      await cp(join(directory, "clean install"), installation, {
        recursive: true,
        verbatimSymlinks: true,
      });
      if (kind === "worktree")
        await writeFile(join(scratch, ".git"), "gitdir: synthetic\n");
      const home = join(scratch, "home");
      await mkdir(home);
      const result = await invoke(
        home,
        ["setup", "hooks"],
        await realpath(join(installation, "node_modules/.bin/falcon-axi")),
      );
      assert.equal(result.code, 2);
      assert.match(result.stdout, /durable installation/);
      for (const path of paths)
        await assert.rejects(stat(join(home, path)), { code: "ENOENT" });
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });

for (const [index, content] of [
  '{"theme":"\xff"}',
  '{"theme":"\xff"}',
  'model = "\xff"\n',
  "// Managed by falcon-axi-session\n// \xff\n",
].entries())
  test(`S12 invalid UTF-8 configuration preserves all files ${paths[index]}`, async () => {
    const home = join(directory, `invalid-utf8-${index}`);
    await mkdir(home);
    assert.equal((await invoke(home, ["setup", "hooks"])).code, 0);
    await writeFile(join(home, paths[index]!), Buffer.from(content, "latin1"));
    const snapshot = await Promise.all(
      paths.map((path) => readFile(join(home, path))),
    );
    const result = await invoke(home, ["setup", "hooks"]);
    assert.equal(result.code, 2);
    assert.match(result.stdout, /CONFIG_INVALID/);
    assert.deepEqual(
      await Promise.all(paths.map((path) => readFile(join(home, path)))),
      snapshot,
    );
  });

for (const [index, content] of [
  "{damaged",
  '{"hooks":{"SessionStart":{}}}',
  "[broken",
  "features = false\n",
  "[[features]]\nhooks = false\n",
  "// user plugin\n",
  "",
].entries())
  test(`S12 malformed configuration refuses before writes ${index}`, async () => {
    const home = join(directory, `malformed-${index}`);
    const path = join(home, paths[index < 2 ? index : index < 5 ? 2 : 3]!);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
    assert.equal((await invoke(home, ["setup", "hooks"])).code, 2);
    assert.equal(await readFile(path, "utf8"), content);
    for (const other of paths.filter(
      (relative) => join(home, relative) !== path,
    ))
      await assert.rejects(stat(join(home, other)), { code: "ENOENT" });
  });

for (const [index, content] of [
  '[features]\n"hooks" = false # hook setting\nother = true\n',
  "[features]\n'hooks' = false # hook setting\nother = true\n",
  '["features"]\nhooks = false # hook setting\nother = true\n',
  "['features']\nhooks = false # hook setting\nother = true\n",
  '[ "features" ]\nhooks = false # hook setting\nother = true\n',
  "features = { hooks = false, other = true } # hook setting\n",
  "features.hooks = false # hook setting\nfeatures.other = true\n",
  '"features"."hooks" = false # hook setting\nfeatures.other = true\n',
  "features = {} # hook setting\n",
  "features.other = true # hook setting\n",
  "[features]\nother = true # hook setting",
  '[features]\nnote = """\n[example]\n""" # hook setting\n[features.nested]\nother = true\n',
].entries())
  test(`S12 retained TOML spelling and comments ${index}`, async () => {
    const home = join(directory, `toml-${index}`);
    const path = join(home, paths[2]!);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content);
    const expected = getStaticTOMLValue(parseTOML(content));
    (expected.features as Record<string, unknown>).hooks = true;
    assert.equal((await invoke(home, ["setup", "hooks"])).code, 0);
    const actual = await readFile(path, "utf8");
    assert.deepEqual(getStaticTOMLValue(parseTOML(actual)), expected);
    assert.match(actual, /# hook setting/);
  });

for (const [channel, credential] of Object.entries({
  canonical: {
    FALCON_AXI_CLIENT_ID: "synthetic-hook-id",
    FALCON_AXI_CLIENT_SECRET: "synthetic-hook-secret",
    FALCON_AXI_REGION: "us-2",
  },
  legacy: {
    FALCON_CLIENT_ID: "synthetic-hook-id",
    FALCON_CLIENT_SECRET: "synthetic-hook-secret",
    FALCON_BASE_URL: "us-2",
  },
}))
  test(`S12 hook status stays offline and redacts configured secrets ${channel}`, async () => {
    const hook = join(dirname(await realpath(executable)), "hook.js");
    const result = spawnSync(process.execPath, [hook], {
      encoding: "utf8",
      env: {
        HOME: directory,
        PATH: dirname(process.execPath),
        ...credential,
      },
    });
    assert.equal(result.status, 0);
    assert.equal(result.stderr, "");
    assert.match(
      result.stdout,
      /profile resolved; region https:\/\/api.us-2.crowdstrike.com/,
    );
    assert.doesNotMatch(result.stdout, /synthetic-hook/);
  });

test("S12 invalid credential configuration keeps the hook fail open", async () => {
  const path = join(directory, "invalid-hook-credentials.json");
  await writeFile(path, "{malformed", { mode: 0o600 });
  const hook = join(dirname(await realpath(executable)), "hook.js");
  const result = spawnSync(process.execPath, [hook], {
    encoding: "utf8",
    env: {
      HOME: directory,
      PATH: dirname(process.execPath),
      FALCON_AXI_CONFIG: path,
    },
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.match(
    result.stdout,
    /^falcon-axi \S+: profile unresolved \(CONFIG_INVALID\).*\n$/,
  );
});

if (process.env.S01_ACTIVE_PATH === "artium")
  test("S12 managed setup remains local only", async () => {
    const result = await run(["setup", "hooks"]);
    assert.notEqual(result.code, 0);
  });
