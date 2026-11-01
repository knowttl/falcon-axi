import assert from "node:assert/strict";
import { test, beforeEach, after } from "node:test";
import { readFile, writeFile, mkdtemp, lstat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { RTR_COMMANDS } from "../../src/rtr-policy.js";
import { rtrPolicy } from "../../src/rtr-policy.js";
import schema from "../../src/axi-credential.schema.json" with { type: "json" };
import contract from "../fixtures/migration/S11/contracts.json" with { type: "json" };
import { requestRead } from "../../src/transport/https.js";
import type { ChildProcess } from "node:child_process";
import { decode } from "@toon-format/toon";
import {
  directory,
  run,
  reset,
  wire,
  recordedResponse as recordResponse,
  dynamicResponse,
} from "./s01.test.js";
import { inspectRtrGrant } from "../../src/rtr.js";
import { requestRtr } from "../../src/transport/https.js";

const host = "a".repeat(32);
function recordedResponse(op: string, status: number, body: unknown): void {
  recordResponse(op, status, body, true);
}
let profile: string;
let shim: string;
let faultDirectory: string;
after(async () => {
  if (faultDirectory) await rm(faultDirectory, { recursive: true });
});
beforeEach(async () => {
  if (profile) return;
  profile = join(directory, "rtr-profile.json");
  await writeFile(
    profile,
    JSON.stringify({
      version: 1,
      profiles: {
        triage: {
          clientId: "synthetic-s01-client",
          clientSecret: { env: "ARTIUM_SECRET_0" },
          rtr: { enabled: true },
        },
      },
    }),
    { mode: 0o600 },
  );
  faultDirectory = await mkdtemp(join(tmpdir(), "falcon-s11-fault-"));
  shim = join(faultDirectory, "rtr-fault.so");
  execFileSync("/usr/bin/gcc", [
    "-B/usr/bin/",
    "-shared",
    "-fPIC",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-o",
    shim,
    resolve("tests/typescript/native-fault.c"),
    "-ldl",
  ]);
});
const args = (command = "ps"): string[] => [
  "rtr",
  "run",
  host,
  "--command",
  command,
  "--execute",
  "--confirm",
  `${host}:${command}`,
  "--config",
  profile,
  "--profile",
  "triage",
];
async function state(): Promise<NodeJS.ProcessEnv> {
  const path = await mkdtemp(join(directory, "rtr-state-"));
  return {
    XDG_STATE_HOME: path,
    FALCON_AXI_WRITE_LOG: join(path, "writes.log"),
  };
}
function lifecycle(output = "synthetic process\n"): void {
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 201, {
    resources: [{ cloud_request_id: "synthetic-request" }],
  });
  recordedResponse("RTR_CheckCommandStatus", 200, {
    resources: [{ complete: true, stdout: output, stderr: "", sequence_id: 3 }],
  });
  recordedResponse("RTR_CheckCommandStatus", 200, {
    resources: [{ complete: true, stdout: "", stderr: "", sequence_id: 3 }],
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
}
async function journal(
  env: NodeJS.ProcessEnv,
): Promise<Record<string, unknown>[]> {
  return (await readFile(env.FALCON_AXI_WRITE_LOG!, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
test("S11 local preview and exact confirmation refuse all network delivery", async () => {
  reset();
  const preview = await run(["rtr", "run", host, "--command", "ps"]);
  assert.equal(preview.code, 0, preview.stdout);
  assert.match(preview.stdout, /preview:/);
  assert.equal(wire.length, 0);
  const refusal = await run(
    ["rtr", "run", host, "--command", "ps", "--execute", "--confirm", "yes"],
    {
      FALCON_AXI_CONFIG: "/nonexistent/config.json",
      FALCON_AXI_PROFILE: undefined,
      FALCON_AXI_CLIENT_ID: undefined,
      FALCON_AXI_CLIENT_SECRET: undefined,
    },
  );
  assert.equal(refusal.code, 2, refusal.stdout);
  assert.match(refusal.stdout, /--confirm must match/);
  assert.equal(
    refusal.stdout,
    await readFile(resolve("tests/golden/rtr-run-confirmation.txt"), "utf8"),
  );
  assert.equal(wire.length, 0);
});
test("S11 installed lifecycle flushes recovery records, follows returned sequence and deletes once", async () => {
  reset();
  lifecycle();
  const env = await state();
  const result = await run(args(), env);
  assert.equal(result.code, 0, result.stdout);
  const value = decode(result.stdout) as {
    result: { complete: boolean; cleanup: string; output: string };
  };
  assert.deepEqual(value.result.complete, true);
  assert.equal(value.result.cleanup, "deleted");
  assert.equal(value.result.output, "synthetic process\n");
  assert.deepEqual(
    wire.map((entry) => entry.method),
    ["POST", "POST", "POST", "GET", "GET", "DELETE"],
  );
  assert.deepEqual(
    wire
      .filter((entry) => entry.method === "GET")
      .map((entry) =>
        new URL(entry.url, "https://synthetic.invalid").searchParams.get(
          "sequence_id",
        ),
      ),
    ["0", "3"],
  );
  const records = await journal(env);
  assert.deepEqual(
    records.map((row) => row.phase),
    ["intent", "init", "execute", "outcome"],
  );
  assert.equal(records[1]!.cleanup, "unknown");
  assert.equal(records[2]!.session, "synthetic-session");
  assert.equal(records[3]!.command_outcome, "complete");
  assert.doesNotMatch(
    await readFile(env.FALCON_AXI_WRITE_LOG!, "utf8"),
    /synthetic-s01-(secret|token|client)|synthetic process/,
  );
  const lock = join(env.XDG_STATE_HOME!, "falcon-axi", `rtr-${host}.lock`);
  const retained = await lstat(lock);
  assert.equal(retained.size, 0);
  reset();
  lifecycle();
  assert.equal((await run(args(), env)).code, 0);
  assert.equal((await lstat(lock)).ino, retained.ino);
});
for (const row of [
  { phase: "intent", flush: 2, init: 0, execute: 0, deleted: 0 },
  { phase: "pre-init", flush: 3, init: 0, execute: 0, deleted: 0 },
  { phase: "known-session", flush: 4, init: 1, execute: 0, deleted: 1 },
  { phase: "outcome", flush: 5, init: 1, execute: 1, deleted: 1 },
])
  test(`S11 ${row.phase} durability failure preserves deletion authority`, async () => {
    reset();
    lifecycle();
    const env = await state();
    const result = await run(args(), {
      ...env,
      LD_PRELOAD: shim,
      FALCON_TEST_FILE: env.FALCON_AXI_WRITE_LOG,
      FALCON_TEST_FLUSH_NUMBER: String(row.flush),
    });
    const diagnostic = JSON.stringify(result);
    assert.equal(result.code, 1, diagnostic);
    assert.match(result.stdout, /CONFIG_INSECURE/, diagnostic);
    assert.equal(
      wire.filter(
        (entry) => entry.method === "POST" && entry.url.includes("/sessions/"),
      ).length,
      row.init,
    );
    assert.equal(
      wire.filter(
        (entry) => entry.method === "POST" && entry.url.includes("/command/"),
      ).length,
      row.execute,
    );
    assert.equal(
      wire.filter((entry) => entry.method === "DELETE").length,
      row.deleted,
    );
    if (row.phase === "outcome") {
      assert.match(result.stdout, /journal_error:/);
      assert.match(result.stdout, /cleanup: deleted/);
      assert.match(result.stdout, /command_outcome: complete/);
    }
  });
test("S11 init refusal is never replayed and retains unknown cleanup", async () => {
  reset();
  recordedResponse("RTR_InitSession", 503, {
    errors: [{ message: "synthetic failure" }],
  });
  const env = await state();
  const result = await run(args(), env);
  assert.equal(result.code, 1, result.stdout);
  assert.equal(wire.length, 2);
  assert.match(result.stdout, /cleanup: unknown/);
  assert.match(result.stdout, /never replay initialization/);
  assert.equal((await journal(env)).at(-1)!.cleanup, "unknown");
});

test("S11 lost initialization response preserves the fake's uncertain created session", async () => {
  reset();
  let created = 0;
  dynamicResponse("RTR_InitSession", () => {
    created++;
    return { status: 201, body: undefined, disconnect: true };
  });
  const env = await state();
  const result = await run(args(), env);
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.equal(created, 1);
  assert.equal(wire.length, 2);
  assert.match(result.stdout, /cleanup: unknown/);
  assert.match(result.stdout, /never replay initialization/);
  assert.equal((await journal(env)).at(-1)!.cleanup, "unknown");
});
test("S11 READ_ONLY and absent opt-in refuse before OAuth", async () => {
  for (const extra of [
    { FALCON_AXI_READ_ONLY: "TrUe" },
    { FALCON_AXI_PROFILE: undefined },
  ]) {
    reset();
    const result = await run(
      extra.FALCON_AXI_READ_ONLY
        ? args()
        : [
            "rtr",
            "run",
            host,
            "--command",
            "ps",
            "--execute",
            "--confirm",
            `${host}:ps`,
          ],
      extra,
    );
    assert.equal(result.code, 1, result.stdout);
    assert.equal(wire.length, 0);
  }
});
test("S11 selected execution failure still deletes the known session", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 429, {
    errors: [{ message: "rate limit" }],
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args(), await state());
  assert.equal(result.code, 1, result.stdout);
  assert.equal(wire.length, 4);
  assert.equal(wire.at(-1)!.method, "DELETE");
  assert.match(result.stdout, /cleanup: deleted/);
});
const exactCat = {
  command: "cat file.txt",
  listing: "ls file.txt",
  listingOutput: "Name Type Size (bytes)\nfile.txt .txt 4\n",
  output: "text",
  complete: true,
  truncated: false,
  unverified: false,
};
for (const row of [
  { ...exactCat, name: "literal" },
  {
    ...exactCat,
    name: "quoted Windows path",
    command: 'cat "C:\\Program Files (x86)\\file.txt"',
    listing: 'ls "C:\\Program Files (x86)\\file.txt"',
  },
  {
    ...exactCat,
    name: "short read",
    output: "tex",
    complete: false,
    truncated: true,
  },
  {
    ...exactCat,
    name: "directory",
    listingOutput: "Name Type Size (bytes)\nfile.txt Directory 4\n",
    complete: false,
    unverified: true,
  },
  {
    ...exactCat,
    name: "ambiguous rows",
    listingOutput: "Name Type Size (bytes)\nfile.txt .txt 4\nfile.txt .txt 4\n",
    complete: false,
    unverified: true,
  },
])
  test(`S11 derived cat listing ${row.name} shares session and retains conservative completeness`, async () => {
    reset();
    recordedResponse("RTR_InitSession", 201, {
      resources: [{ session_id: "synthetic-session" }],
    });
    recordedResponse("RTR_ExecuteCommand", 201, {
      resources: [{ cloud_request_id: "synthetic-listing" }],
    });
    recordedResponse("RTR_CheckCommandStatus", 200, {
      resources: [
        {
          complete: true,
          stdout: row.listingOutput,
          stderr: "",
          sequence_id: 0,
        },
      ],
    });
    recordedResponse("RTR_CheckCommandStatus", 200, {
      resources: [{ complete: true, stdout: "", stderr: "" }],
    });
    recordedResponse("RTR_ExecuteCommand", 201, {
      resources: [{ cloud_request_id: "synthetic-cat" }],
    });
    recordedResponse("RTR_CheckCommandStatus", 200, {
      resources: [
        { complete: true, stdout: row.output, stderr: "", sequence_id: 0 },
      ],
    });
    recordedResponse("RTR_CheckCommandStatus", 200, {
      resources: [{ complete: true, stdout: "", stderr: "" }],
    });
    recordedResponse("RTR_DeleteSession", 204, undefined);
    const result = await run(args(row.command), await state());
    assert.equal(result.code, 0, result.stdout);
    const value = decode(result.stdout) as {
      result: {
        complete: boolean;
        size_unverified: boolean;
        truncated: boolean;
      };
    };
    assert.equal(value.result.complete, row.complete);
    assert.equal(value.result.size_unverified, row.unverified);
    assert.equal(value.result.truncated, row.truncated);
    assert.deepEqual(
      wire
        .filter(
          (entry) => entry.method === "POST" && entry.url.includes("/command/"),
        )
        .map((entry) => JSON.parse(entry.body) as unknown),
      [
        {
          base_command: "ls",
          command_string: row.listing,
          session_id: "synthetic-session",
        },
        {
          base_command: "cat",
          command_string: row.command,
          session_id: "synthetic-session",
        },
      ],
    );
  });
test("S11 status exhaustion is explicit and still deletes", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 201, {
    resources: [{ cloud_request_id: "synthetic-request" }],
  });
  dynamicResponse("RTR_CheckCommandStatus", (query) => ({
    status: 200,
    body: {
      resources: [
        {
          stdout: "x",
          stderr: "",
          complete: true,
          sequence_id: Number(query.get("sequence_id")),
        },
      ],
    },
  }));
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args(), await state());
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /complete: false/);
  assert.match(result.stdout, /truncated: true/);
  assert.equal(wire.filter((entry) => entry.method === "GET").length, 64);
  assert.equal(wire.at(-1)!.method, "DELETE");
});
test("S11 forged grants cannot reach the sealed sink", async () => {
  reset();
  assert.throws(() => inspectRtrGrant({}), /authority/);
  await assert.rejects(
    requestRtr({}, new AbortController().signal),
    /authority/,
  );
  assert.equal(wire.length, 0);
});

for (const command of [
  "runscript",
  "eventlog backup",
  "eventlog export",
  "reg delete HKLM",
  "ps; ls",
  "ps | ls",
  "ps\u00a0argument",
  'cat "unmatched',
  "ps (data)",
  "ps " + "x".repeat(4096),
])
  test(`S11 grammar refuses ${command.slice(0, 30)} before OAuth`, async () => {
    reset();
    const result = await run(args(command));
    assert.notEqual(result.code, 0, JSON.stringify(result));
    assert.equal(wire.length, 0);
  });

for (const row of [
  {
    name: "malformed sequence",
    chunk: { complete: false, stdout: "x" },
    truncated: false,
  },
  {
    name: "response acquisition cap",
    chunk: { complete: true, stdout: "x".repeat(1024 * 1024) },
    truncated: false,
  },
  {
    name: "retained output cap",
    chunk: { complete: true, stdout: "x".repeat(65536) },
    truncated: true,
  },
])
  test(`S11 ${row.name} still deletes`, async () => {
    reset();
    recordedResponse("RTR_InitSession", 201, {
      resources: [{ session_id: "synthetic-session" }],
    });
    recordedResponse("RTR_ExecuteCommand", 201, {
      resources: [{ cloud_request_id: "synthetic-request" }],
    });
    recordedResponse("RTR_CheckCommandStatus", 200, { resources: [row.chunk] });
    recordedResponse("RTR_DeleteSession", 204, undefined);
    const result = await run(args(), await state());
    assert.equal(result.code, row.truncated ? 0 : 1, JSON.stringify(result));
    assert.match(result.stdout, /complete: false/);
    assert.match(result.stdout, /cleanup: deleted/);
    assert.equal(wire.at(-1)!.method, "DELETE");
  });

test("S11 deletion failure is explicit and never replayed", async () => {
  reset();
  lifecycle();
  dynamicResponse("RTR_DeleteSession", () => ({
    status: 503,
    body: { errors: [] },
  }));
  const result = await run(args(), await state());
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.match(result.stdout, /cleanup: failed/);
  assert.match(result.stdout, /command_outcome: complete/);
  assert.equal(wire.filter((entry) => entry.method === "DELETE").length, 1);
});

for (const [command, operation, signal] of [
  ["ps", "RTR_ExecuteCommand", "SIGTERM"],
  ["ps", "RTR_CheckCommandStatus", "SIGINT"],
  ["cat file.txt", "RTR_ExecuteCommand", "SIGTERM"],
  ["cat file.txt", "RTR_CheckCommandStatus", "SIGINT"],
] as const)
  test(`S11 repeated interrupts during ${command} ${operation} preserve mandatory cleanup`, async () => {
    reset();
    let child: ChildProcess;
    recordedResponse("RTR_InitSession", 201, {
      resources: [{ session_id: "synthetic-session" }],
    });
    dynamicResponse("RTR_ExecuteCommand", () => {
      if (operation === "RTR_ExecuteCommand") child.kill(signal);
      return {
        status: 201,
        body: { resources: [{ cloud_request_id: "synthetic-request" }] },
      };
    });
    dynamicResponse("RTR_CheckCommandStatus", () => {
      child.kill(signal);
      return {
        status: 200,
        body: { resources: [{ complete: false, stdout: "", sequence_id: 0 }] },
      };
    });
    dynamicResponse("RTR_DeleteSession", () => {
      child.kill("SIGINT");
      child.kill("SIGTERM");
      return { status: 204, body: undefined };
    });
    const result = await run(
      args(command),
      await state(),
      false,
      false,
      undefined,
      false,
      (value) => {
        child = value;
      },
    );
    assert.equal(result.code, 1, JSON.stringify(result));
    assert.equal(result.signal, null);
    assert.match(result.stdout, /cleanup: deleted/);
    assert.equal(wire.filter((entry) => entry.method === "DELETE").length, 1);
    if (command.startsWith("cat"))
      assert.equal(
        wire.filter((entry) => entry.body.includes('"base_command":"cat"'))
          .length,
        0,
      );
  });

test("S11 allowlisted rejection names only the base command", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 400, {
    errors: [{ message: "Command not found: synthetic-sensitive-argument" }],
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(
    args("csrutil synthetic-sensitive-argument"),
    await state(),
  );
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.match(result.stdout, /Falcon does not accept the RTR command csrutil/);
  assert.doesNotMatch(
    result.stdout.split("error:")[1]!,
    /synthetic-sensitive-argument/,
  );
});

test("S11 READ_ONLY enabled after init preserves only owned deletion", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args(), {
    ...(await state()),
    S11_READ_ONLY_AFTER_INIT: "1",
  });
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.equal(wire.length, 3);
  assert.equal(wire.at(-1)!.method, "DELETE");
  assert.match(result.stdout, /cleanup: deleted/);
});

test("S11 same-device uppercase contender refuses before OAuth while holder owns init", async () => {
  reset();
  lifecycle();
  const env = await state();
  let contender: Awaited<ReturnType<typeof run>> | undefined;
  dynamicResponse("RTR_InitSession", async () => {
    const rival = args().map((item) =>
      item.replaceAll(host, host.toUpperCase()),
    );
    contender = await run(rival, env);
    assert.equal(wire.length, 2);
    return {
      status: 201,
      body: { resources: [{ session_id: "synthetic-session" }] },
    };
  });
  const result = await run(args(), env);
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(contender!.code, 1, JSON.stringify(contender));
  assert.match(contender!.stdout, /Another local RTR run/);
});

test("S11 offline deny survives controller subprocesses", () => {
  for (const address of ["127.0.0.1", "::1"]) {
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./native-worker.js", import.meta.url)),
        "network-deny",
        address,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
  }
});

for (const value of ["true", "1", "TrUe", "false", "0", "yes"])
  test(`S11 READ_ONLY ${value} keeps preview local`, async () => {
    reset();
    const result = await run(["rtr", "run", host, "--command", "ps"], {
      FALCON_AXI_READ_ONLY: value,
    });
    assert.equal(result.code, value === "yes" ? 2 : 0, JSON.stringify(result));
    assert.equal(wire.length, 0);
  });

for (const base of RTR_COMMANDS)
  test(`S11 fixed command preview ${base}`, async () => {
    reset();
    const result = await run([
      "rtr",
      "run",
      host,
      "--command",
      base === "eventlog" ? "eventlog list" : base,
    ]);
    assert.equal(result.code, 0, JSON.stringify(result));
    assert.equal(wire.length, 0);
  });

test("S11 execution never admits an unknown origin override", async () => {
  reset();
  const result = await run([
    ...args(),
    "--region",
    "https://synthetic-cloud.example",
    "--allow-unknown-origin",
  ]);
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.match(result.stdout, /ORIGIN_NOT_ALLOWED/);
  assert.equal(wire.length, 0);
});

test("S11 accumulated output redacts a token spanning chunks and an unfinished PEM", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 201, {
    resources: [{ cloud_request_id: "synthetic-request" }],
  });
  recordedResponse("RTR_CheckCommandStatus", 200, {
    resources: [{ complete: true, stdout: "synthetic-s01-", sequence_id: 0 }],
  });
  recordedResponse("RTR_CheckCommandStatus", 200, {
    resources: [
      {
        complete: true,
        stdout:
          "token\n-----BEGIN PRIVATE KEY-----\nsynthetic-private-material",
        sequence_id: 1,
      },
    ],
  });
  recordedResponse("RTR_CheckCommandStatus", 200, {
    resources: [{ complete: true, stdout: "" }],
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const env = await state();
  const result = await run(args(), env);
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.match(result.stdout, /\[redacted\]/);
  assert.doesNotMatch(result.stdout, /PRIVATE KEY|synthetic-private-material/);
  assert.doesNotMatch(
    await readFile(env.FALCON_AXI_WRITE_LOG!, "utf8"),
    /PRIVATE KEY|synthetic-private-material/,
  );
});

test("S11 size lookup request timeout aborts cat and uses independent cleanup", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  dynamicResponse("RTR_ExecuteCommand", () => new Promise<never>(() => {}));
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args("cat file.txt"), {
    ...(await state()),
    S11_SIZE_TIMEOUT: "1",
  });
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.match(result.stdout, /WAIT_TIMEOUT/);
  assert.match(result.stdout, /cleanup: deleted/);
  assert.equal(
    wire.filter((entry) => entry.body.includes('"base_command":"cat"')).length,
    0,
  );
  assert.equal(wire.at(-1)!.method, "DELETE");
});

test("S11 shared execution deadline during listing polling prevents cat and retains fresh cleanup", async () => {
  reset();
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  recordedResponse("RTR_ExecuteCommand", 201, {
    resources: [{ cloud_request_id: "synthetic-listing" }],
  });
  dynamicResponse("RTR_CheckCommandStatus", (query) => ({
    status: 200,
    body: {
      resources: [
        {
          complete: false,
          stdout: "",
          sequence_id: Number(query.get("sequence_id")),
        },
      ],
    },
  }));
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args("cat file.txt"), {
    ...(await state()),
    S11_EXECUTION_TIMEOUT: "1",
  });
  assert.equal(result.code, 1, JSON.stringify(result));
  assert.match(result.stdout, /WAIT_TIMEOUT/);
  assert.match(result.stdout, /cleanup: deleted/);
  assert.equal(
    wire.filter((entry) => entry.body.includes('"base_command":"cat"')).length,
    0,
  );
  assert.ok(wire.filter((entry) => entry.method === "GET").length < 64);
  assert.equal(wire.at(-1)!.method, "DELETE");
});

for (const seed of [
  "missing-grant",
  "tampered-body",
  "missing-flush",
  "suppressed-cleanup",
])
  test(`S11 mutation detector ${seed}`, async () => {
    reset();
    lifecycle();
    const env = await state();
    const result = await run(args(), {
      ...env,
      S11_MUTATION: seed,
      NODE_OPTIONS: `--import=${fileURLToPath(new URL("./delivery.js", import.meta.url))} --import=${fileURLToPath(new URL("./rtr-seeds.js", import.meta.url))}`,
    });
    assert.match(
      result.stderr,
      new RegExp(`seed-applied:${seed}`),
      JSON.stringify(result),
    );
    if (seed === "missing-grant" || seed === "tampered-body") {
      assert.equal(result.code, 1, JSON.stringify(result));
      assert.match(result.stdout, /READ_ONLY_VIOLATION/);
      assert.equal(wire.length, 1);
    } else if (seed === "missing-flush") {
      assert.equal(result.code, 0, JSON.stringify(result));
      const phases = (await journal(env)).map((record) => record.phase);
      assert.throws(
        () =>
          assert.deepEqual(phases, ["intent", "init", "execute", "outcome"]),
        assert.AssertionError,
      );
      assert.deepEqual(phases, ["intent", "execute", "outcome"]);
    } else {
      assert.equal(result.code, 0, JSON.stringify(result));
      assert.throws(
        () =>
          assert.equal(
            wire.filter((entry) => entry.method === "DELETE").length,
            1,
          ),
        assert.AssertionError,
      );
      assert.equal(wire.filter((entry) => entry.method === "DELETE").length, 0);
    }
  });

test("S11 command schema and platform help retain the closed command set", async () => {
  assert.deepEqual(
    schema.properties.rtr.properties.commands.items.enum,
    RTR_COMMANDS,
  );
  const help = await run(["rtr", "run", "--help"]);
  assert.equal(help.code, 0, JSON.stringify(help));
  const names = help.stdout
    .split("\n")
    .filter((line) => /^(Verified|Accepted)/.test(line))
    .flatMap((line) =>
      line
        .slice(line.indexOf(":") + 1)
        .trim()
        .replace(/\.$/, "")
        .split(", "),
    );
  assert.deepEqual(names.sort(), [...RTR_COMMANDS].sort());
  assert.equal(names.length, RTR_COMMANDS.length);
});

for (const policy of [
  { enabled: "true" },
  { enabled: true, commands: ["runscript"] },
  { enabled: true, commands: "ps" },
  { enabled: true, extra: true },
])
  test(`S11 profile policy refuses widening ${JSON.stringify(policy)}`, () => {
    assert.throws(() => rtrPolicy(policy), { code: "CONFIG_INVALID" });
  });

test("S11 every lifecycle descriptor refuses passive transport authority", async () => {
  reset();
  for (const id of contract.operationIds)
    await assert.rejects(
      async () =>
        requestRead(
          id,
          "https://api.crowdstrike.com",
          "synthetic-token",
          {},
          undefined,
          false,
          new AbortController().signal,
        ),
      { code: "READ_ONLY_VIOLATION" },
    );
  assert.equal(wire.length, 0);
});

test("S11 copied device ID with a trailing newline refuses before credentials", async () => {
  reset();
  const copied = host + "\n";
  const result = await run([
    "rtr",
    "run",
    copied,
    "--command",
    "ps",
    "--execute",
    "--confirm",
    `${copied}:ps`,
  ]);
  assert.equal(result.code, 2, JSON.stringify(result));
  assert.match(result.stdout, /one 32-character device id/);
  assert.equal(wire.length, 0);
});

for (const command of ["cat *.txt", "cat one.txt two.txt", "cat -help", "cat"])
  test(`S11 cat without literal path ${command} never claims completeness`, async () => {
    reset();
    lifecycle("text");
    const result = await run(args(command), await state());
    assert.equal(result.code, 0, JSON.stringify(result));
    assert.match(result.stdout, /complete: false/);
    assert.match(result.stdout, /size_unverified: true/);
    assert.equal(
      wire.filter((entry) => entry.body.includes('"base_command":"ls"')).length,
      0,
    );
  });

for (const row of [
  {
    name: "empty restriction",
    nameInFile: "triage",
    policy: { enabled: true, commands: [] },
    exit: 1,
  },
  {
    name: "disabled profile",
    nameInFile: "triage",
    policy: { enabled: false },
    exit: 1,
  },
  {
    name: "narrowed profile",
    nameInFile: "triage",
    policy: { enabled: true, commands: ["ls"] },
    exit: 1,
  },
  {
    name: "file profile named env",
    nameInFile: "env",
    policy: { enabled: true, commands: ["ps"] },
    exit: 0,
  },
])
  test(`S11 selected ${row.name} retains file-channel authorization`, async () => {
    reset();
    lifecycle();
    const env = await state();
    const selected = join(env.XDG_STATE_HOME!, "config.json");
    await writeFile(
      selected,
      JSON.stringify({
        version: 1,
        profiles: {
          [row.nameInFile]: {
            clientId: "synthetic-s01-client",
            clientSecret: { env: "ARTIUM_SECRET_0" },
            rtr: row.policy,
          },
        },
      }),
      { mode: 0o600 },
    );
    const invocation = args().map((item) =>
      item === profile ? selected : item === "triage" ? row.nameInFile : item,
    );
    const result = await run(invocation, env);
    assert.equal(result.code, row.exit, JSON.stringify(result));
    if (row.exit) assert.equal(wire.length, 0);
  });

test("S11 cat shares all 64 status requests with its derived listing", async () => {
  reset();
  let statusRequests = 0;
  recordedResponse("RTR_InitSession", 201, {
    resources: [{ session_id: "synthetic-session" }],
  });
  dynamicResponse("RTR_ExecuteCommand", (_query, body) => ({
    status: 201,
    body: {
      resources: [
        {
          cloud_request_id:
            body.base_command === "ls" ? "synthetic-listing" : "synthetic-cat",
        },
      ],
    },
  }));
  dynamicResponse("RTR_CheckCommandStatus", (query) => {
    statusRequests++;
    return {
      status: 200,
      body: {
        resources: [
          {
            complete: true,
            stdout:
              statusRequests === 1
                ? "Name Type Size (bytes)\nfile.txt .txt 4\n"
                : statusRequests < 64
                  ? " \n"
                  : "",
            sequence_id: Number(query.get("sequence_id")),
          },
        ],
      },
    };
  });
  recordedResponse("RTR_DeleteSession", 204, undefined);
  const result = await run(args("cat file.txt"), await state());
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.equal(statusRequests, 64);
  assert.match(result.stdout, /complete: false/);
  assert.match(result.stdout, /truncated: true/);
  assert.match(result.stdout, /size_unverified: false/);
  assert.match(result.stdout, /cleanup: deleted/);
});

test("S11 derived listing cannot widen a cat-only profile", async () => {
  reset();
  lifecycle("text");
  const env = await state();
  const selected = join(env.XDG_STATE_HOME!, "config.json");
  await writeFile(
    selected,
    JSON.stringify({
      version: 1,
      profiles: {
        triage: {
          clientId: "synthetic-s01-client",
          clientSecret: { env: "ARTIUM_SECRET_0" },
          rtr: { enabled: true, commands: ["cat"] },
        },
      },
    }),
    { mode: 0o600 },
  );
  const result = await run(
    args("cat file.txt").map((item) => (item === profile ? selected : item)),
    env,
  );
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.match(result.stdout, /complete: false/);
  assert.match(result.stdout, /size_unverified: true/);
  assert.equal(
    wire.filter((entry) => entry.body.includes('"base_command":"ls"')).length,
    0,
  );
});

for (const row of [
  {
    name: "valid BOM and replacement character",
    output: "\uFEFFsafe\uFFFD",
    expected: "\uFEFFsafe\uFFFD",
    complete: true,
  },
  {
    name: "partial UTF-8 suffix at cap",
    output: "\uFEFF" + "a".repeat(65530) + "🦅",
    expected: "\uFEFF" + "a".repeat(65530),
    complete: false,
  },
])
  test(`S11 retained output preserves ${row.name}`, async () => {
    reset();
    lifecycle(row.output);
    const result = await run(args(), await state());
    assert.equal(result.code, 0, JSON.stringify(result));
    const value = decode(result.stdout) as {
      result: { output: string; complete: boolean };
    };
    assert.equal(value.result.output, row.expected);
    assert.equal(value.result.complete, row.complete);
  });
