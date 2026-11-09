import assert from "node:assert/strict";
import { test } from "node:test";
import {
  cp,
  mkdir,
  readFile,
  writeFile,
  realpath,
  rm,
  symlink,
} from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { directory, executable, prepareScenario, run } from "./s01.test.js";
import type { Scenario } from "./s01.test.js";
import "./s12.test.js";
import "./raw.test.js";
import "./final-coverage.test.js";

test("S13 generated parser schema skill and catalog refuse drift and repair it", async () => {
  const scratch = join(directory, "generation");
  for (const path of [
    ".typescript-build/src",
    "scripts/typescript",
    "skills/falcon-axi",
    "package.json",
    "artium-invocations.json",
    ".typescript-build/scripts/typescript/generate.js",
  ]) {
    await mkdir(dirname(join(scratch, path)), { recursive: true });
    await cp(resolve(path), join(scratch, path), { recursive: true });
  }
  const generator = join(
    scratch,
    ".typescript-build/scripts/typescript/generate.js",
  );
  const check = (): number | null =>
    spawnSync(process.execPath, [generator, "--check"], { encoding: "utf8" })
      .status;
  assert.equal(check(), 0);
  for (const path of [
    ".typescript-build/src/parser.js",
    ".typescript-build/src/axi-credential.schema.json",
    "skills/falcon-axi/SKILL.md",
    "artium-invocations.json",
  ]) {
    const target = join(scratch, path);
    const content = await readFile(target, "utf8");
    await writeFile(target, content + "\n");
    assert.notEqual(check(), 0, path);
    assert.equal(
      await readFile(target, "utf8"),
      content + "\n",
      "check must not write",
    );
    await writeFile(target, content);
    assert.equal(check(), 0);
  }
  const reference = join(scratch, "skills/falcon-axi/references/host-list.md");
  await rm(reference);
  const extra = join(scratch, "skills/falcon-axi/references/unshipped.md");
  await writeFile(extra, "unshipped");
  assert.notEqual(check(), 0);
  assert.equal(
    spawnSync(process.execPath, [generator], { encoding: "utf8" }).status,
    0,
  );
  assert.equal(check(), 0);
  await assert.rejects(readFile(extra), { code: "ENOENT" });
});

async function home(
  cwd: string,
  env: NodeJS.ProcessEnv,
  args: string[] = [],
): Promise<string> {
  const result = spawnSync(
    process.execPath,
    [await realpath(executable), ...args],
    {
      cwd,
      encoding: "utf8",
      env: {
        HOME: join(cwd, "home"),
        PATH: dirname(process.execPath),
        FALCON_AXI_CONFIG: join(cwd, "missing.json"),
        ...env,
      },
    },
  );
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /PROFILE_REQUIRED/);
  assert.equal(result.stderr, "");
  return result.stdout;
}
const hint = /npx skills add knowttl\/falcon-axi --skill falcon-axi/;

for (const marker of [
  "CLAUDECODE",
  "CODEX_THREAD_ID",
  "CODEX_SESSION_ID",
  "OPENCODE",
  "PI_CODING_AGENT",
])
  test(`S13 bare home offers skill in ${marker}`, async () => {
    assert.match(await home(directory, { [marker]: "synthetic" }), hint);
    assert.doesNotMatch(
      await home(directory, { [marker]: "synthetic" }, ["--region", "us-1"]),
      hint,
    );
  });

for (const [marker, root] of [
  ["CLAUDECODE", ".claude/skills"],
  ["CODEX_THREAD_ID", ".agents/skills"],
  ["PI_CODING_AGENT", ".pi/agent/skills"],
  ["PI_CODING_AGENT", ".agents/skills"],
  ["OPENCODE", ".config/opencode/skills"],
  ["OPENCODE", ".claude/skills"],
  ["OPENCODE", ".agents/skills"],
])
  test(`S13 installed user skill suppresses hint ${marker} ${root}`, async () => {
    const cwd = join(directory, `${marker}-${root!.replaceAll("/", "-")}`);
    const skill = join(cwd, "home", root!, "falcon-axi/SKILL.md");
    await mkdir(dirname(skill), { recursive: true });
    await writeFile(skill, "synthetic installed skill");
    assert.doesNotMatch(await home(cwd, { [marker!]: "synthetic" }), hint);
  });

for (const [marker, root] of [
  ["CLAUDECODE", ".claude/skills"],
  ["CODEX_SESSION_ID", ".agents/skills"],
  ["PI_CODING_AGENT", ".pi/skills"],
  ["OPENCODE", ".opencode/skills"],
])
  test(`S13 ancestor skill stops at repository boundary ${marker}`, async () => {
    const project = join(directory, `project-${marker}`);
    const child = join(project, "src");
    const skill = join(project, root!, "falcon-axi/SKILL.md");
    await mkdir(child, { recursive: true });
    await mkdir(join(project, ".git"));
    await mkdir(dirname(skill), { recursive: true });
    await writeFile(skill, "synthetic installed skill");
    assert.doesNotMatch(await home(child, { [marker!]: "synthetic" }), hint);
    const nested = join(child, "nested");
    await mkdir(join(nested, ".git"), { recursive: true });
    assert.match(await home(nested, { [marker!]: "synthetic" }), hint);
  });

for (const [marker, override, relative] of [
  ["CLAUDECODE", "CLAUDE_CONFIG_DIR", "skills"],
  ["PI_CODING_AGENT", "PI_CODING_AGENT_DIR", "skills"],
  ["OPENCODE", "XDG_CONFIG_HOME", "opencode/skills"],
])
  test(`S13 skill root override ${override}`, async () => {
    const cwd = join(directory, `override-${marker}`);
    const base = join(cwd, "custom");
    const skill = join(base, relative!, "falcon-axi/SKILL.md");
    await mkdir(dirname(skill), { recursive: true });
    await writeFile(skill, "synthetic installed skill");
    assert.doesNotMatch(
      await home(cwd, { [marker!]: "synthetic", [override!]: base }),
      hint,
    );
  });

test("S13 discovery errors fail open without breaking home", async () => {
  const cwd = join(directory, "probe-error");
  await mkdir(join(cwd, "home/.agents"), { recursive: true });
  await symlink("skills", join(cwd, "home/.agents/skills"));
  assert.doesNotMatch(await home(cwd, { CODEX_SESSION_ID: "synthetic" }), hint);
});

test("S13 Claude finds the main checkout skill from linked metadata", async () => {
  const main = join(directory, "main");
  const gitdir = join(main, ".git/worktrees/branch");
  const skill = join(main, ".claude/skills/falcon-axi/SKILL.md");
  const cwd = join(directory, "branch");
  await mkdir(gitdir, { recursive: true });
  await mkdir(dirname(skill), { recursive: true });
  await writeFile(skill, "synthetic installed skill");
  await mkdir(cwd);
  await writeFile(join(cwd, ".git"), `gitdir: ${gitdir}\n`);
  assert.doesNotMatch(await home(cwd, { CLAUDECODE: "synthetic" }), hint);
});

if (process.env.S01_ACTIVE_PATH !== "artium")
  test("S13 authenticated home retains skill hint only without arguments", async () => {
    const scenario = JSON.parse(
      await readFile(resolve("tests/golden/scenarios/home-view.json"), "utf8"),
    ) as Scenario;
    const env = {
      HOME: join(directory, "authenticated-home"),
      CODEX_THREAD_ID: "synthetic",
      FALCON_AXI_PROFILE: undefined,
      FALCON_AXI_CONFIG: "/nonexistent/falcon-axi/config.json",
      FALCON_AXI_CLIENT_ID: "synthetic-client-id",
      FALCON_AXI_CLIENT_SECRET: "synthetic-client-secret",
    };
    await prepareScenario(scenario);
    const bare = await run([], env);
    assert.equal(bare.code, 0, bare.stdout);
    assert.match(bare.stdout, hint);
    await prepareScenario(scenario);
    const scoped = await run(["--region", "us-1"], env);
    assert.equal(scoped.code, 0, scoped.stdout);
    assert.doesNotMatch(scoped.stdout, hint);
  });
