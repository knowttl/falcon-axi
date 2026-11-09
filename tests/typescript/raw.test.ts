import assert from "node:assert/strict";
import { test, beforeEach } from "node:test";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { decode } from "@toon-format/toon";
import {
  directory,
  run,
  reset,
  wire,
  recordedResponse,
  dynamicResponse,
} from "./s01.test.js";

let config: string;
beforeEach(async () => {
  reset();
  config = join(directory, "raw-profiles.json");
  const profile = (writes?: unknown): Record<string, unknown> => ({
    clientId: "synthetic-s01-client",
    clientSecret: { env: "ARTIUM_SECRET_0" },
    ...(writes ? { writes } : {}),
  });
  await writeFile(
    config,
    JSON.stringify({
      version: 1,
      profiles: {
        reader: profile(),
        ops: profile({ allowWrites: true, operations: ["raw-write"] }),
        other: profile({ allowWrites: true, operations: ["something-else"] }),
        off: profile({ allowWrites: false, operations: ["raw-write"] }),
      },
    }),
    { mode: 0o600 },
  );
});
const value = (stdout: string): Record<string, unknown> =>
  decode(stdout) as Record<string, unknown>;
const requests = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");
async function state(): Promise<NodeJS.ProcessEnv> {
  const path = await mkdtemp(join(directory, "raw-state-"));
  return {
    XDG_STATE_HOME: path,
    FALCON_AXI_WRITE_LOG: join(path, "writes.log"),
  };
}
async function journal(
  env: NodeJS.ProcessEnv,
): Promise<Record<string, unknown>[]> {
  return (await readFile(env.FALCON_AXI_WRITE_LOG!, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
const getArgs = (path: string, ...rest: string[]): string[] => [
  "raw",
  "get",
  "--path",
  path,
  "--config",
  config,
  "--profile",
  "reader",
  ...rest,
];
const writeArgs = (profile: string, ...rest: string[]): string[] => [
  "raw",
  "write",
  "--method",
  "PATCH",
  "--path",
  "/example/entities/things/v1",
  "--query",
  "ids=one&ids=two",
  "--config",
  config,
  "--profile",
  profile,
  ...rest,
];
async function body(): Promise<string> {
  const file = join(directory, "raw-body.json");
  await writeFile(file, JSON.stringify({ name: "synthetic", enabled: true }));
  return file;
}
async function confirmValue(profile: string, file: string): Promise<string> {
  const preview = await run(writeArgs(profile, "--body-file", file));
  assert.equal(preview.code, 0, preview.stdout);
  return (value(preview.stdout).preview as Record<string, string>).confirm!;
}

test("raw get sends one bearer GET and redacts secret values while keeping every field", async () => {
  recordedResponse("GET /example/entities/things/v1", 200, {
    resources: [
      { id: "keep", client_secret: "hunter2", note: "visible" },
      { key: "api_key", value: "pair-secret", kind: "string" },
      { name: "retention_days", value: 30 },
    ],
  });
  const result = await run(
    getArgs("/example/entities/things/v1", "--query", "ids=one&ids=two"),
  );
  assert.equal(result.code, 0, result.stdout);
  const output = value(result.stdout);
  assert.equal(output.status, 200);
  assert.deepEqual(output.body, {
    resources: [
      { id: "keep", client_secret: "[redacted]", note: "visible" },
      { key: "api_key", value: "[redacted]", kind: "string" },
      { name: "retention_days", value: 30 },
    ],
  });
  assert.match(requests()[0]!.authorization, /^Bearer /);
  assert.equal(requests().length, 1);
  assert.equal(requests()[0]!.method, "GET");
  assert.equal(
    requests()[0]!.url,
    "/example/entities/things/v1?ids=one&ids=two",
  );
});

for (const path of [
  "/example/../devices",
  "/example//devices",
  "/example/things?x=1",
  "example/things",
  "/example/th ings",
])
  test(`raw get refuses ${path} before any request`, async () => {
    const result = await run(getArgs(path));
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

test("raw get translates an upstream refusal with its status and redacted body", async () => {
  recordedResponse("GET /example/entities/things/v1", 403, {
    errors: [{ code: 403, message: "access denied" }],
  });
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  const output = value(result.stdout);
  assert.equal(output.code, "SCOPE_DENIED");
  assert.equal(output.upstream_status, 403);
});

test("raw get refuses a binary response", async () => {
  dynamicResponse("GET /example/entities/things/v1", () => ({
    status: 200,
    headers: { "content-type": "application/octet-stream" },
    body: Buffer.from([0x37, 0x7a, 0x00, 0xff]),
  }));
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  assert.match(result.stdout, /binary/);
});

for (const [profile, why] of [
  ["reader", "no writes setting"],
  ["off", "allowWrites false"],
  ["other", "raw-write not listed"],
] as const)
  test(`raw write refuses a profile with ${why}, even to preview`, async () => {
    const result = await run(writeArgs(profile));
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "READ_ONLY_VIOLATION");
    assert.equal(wire.length, 0);
  });

test("raw write previews with an exact confirm value and sends nothing", async () => {
  const file = await body();
  const env = await state();
  const result = await run(writeArgs("ops", "--body-file", file), env);
  assert.equal(result.code, 0, result.stdout);
  const output = value(result.stdout);
  const preview = output.preview as Record<string, unknown>;
  assert.equal(preview.method, "PATCH");
  assert.equal(preview.path, "/example/entities/things/v1?ids=one&ids=two");
  assert.deepEqual(preview.body, { name: "synthetic", enabled: true });
  assert.match(String(preview.confirm), /^ops:PATCH sha256:/);
  assert.equal(wire.length, 0);
  await assert.rejects(readFile(env.FALCON_AXI_WRITE_LOG!));
});

test("raw write refuses a wrong confirm value before any request", async () => {
  const file = await body();
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", "yes"),
  );
  assert.equal(result.code, 2, result.stdout);
  assert.match(result.stdout, /--confirm must match/);
  assert.equal(wire.length, 0);
});

test("raw write refuses --confirm without --execute", async () => {
  const result = await run(writeArgs("ops", "--confirm", "yes"));
  assert.equal(result.code, 2, result.stdout);
  assert.equal(wire.length, 0);
});

for (const path of [
  "/mssp/entities/cid-groups/v1",
  "/real-time-response/entities/admin-command/v1",
  "/user-management/entities/users/v1",
  "/oauth2/token",
])
  test(`raw write previews ${path}`, async () => {
    const result = await run([
      "raw",
      "write",
      "--method",
      "POST",
      "--path",
      path,
      "--config",
      config,
      "--profile",
      "ops",
    ]);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(wire.length, 0);
  });

test("raw write sends the confirmed request once and journals intent before outcome", async () => {
  const file = await body();
  const env = await state();
  const confirm = await confirmValue("ops", file);
  recordedResponse(
    "PATCH /example/entities/things/v1",
    200,
    { resources: [{ id: "one" }] },
    true,
  );
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
    env,
  );
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(
    (value(result.stdout).preview as Record<string, unknown>).body,
    { name: "synthetic", enabled: true },
  );
  assert.deepEqual(value(result.stdout).body, { resources: [{ id: "one" }] });
  assert.equal(requests().length, 1);
  assert.equal(requests()[0]!.method, "PATCH");
  assert.equal(
    requests()[0]!.url,
    "/example/entities/things/v1?ids=one&ids=two",
  );
  assert.deepEqual(JSON.parse(requests()[0]!.body), {
    name: "synthetic",
    enabled: true,
  });
  const records = await journal(env);
  assert.deepEqual(
    records.map(({ phase, outcome }) => [phase, outcome]),
    [
      ["intent", "not_sent"],
      ["outcome", "responded"],
    ],
  );
  assert.equal(records[1]!.status, 200);
  assert.ok(!JSON.stringify(records).includes("synthetic"));
});

test("raw write changes its confirm value when the body changes", async () => {
  const file = await body();
  const first = await confirmValue("ops", file);
  await writeFile(file, JSON.stringify({ name: "other" }));
  assert.notEqual(await confirmValue("ops", file), first);
});

test("raw write preserves stdin body numbers and confirms the destination", async () => {
  const text = '{"number":9007199254740993}';
  const file = join(directory, "large-number.json");
  await writeFile(file, text);
  const preview = await run(writeArgs("ops", "--body-file", file));
  assert.match(preview.stdout, /9007199254740993/);
  assert.doesNotMatch(preview.stdout, /9007199254740992/);
  const confirm = await confirmValue("ops", file);
  const differentRegion = await run(
    writeArgs(
      "ops",
      "--body-file",
      file,
      "--region",
      "eu-1",
      "--execute",
      "--confirm",
      confirm,
    ),
  );
  assert.equal(differentRegion.code, 2, differentRegion.stdout);
  const differentTenant = await run(
    writeArgs(
      "ops",
      "--body-file",
      file,
      "--member-cid",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "--execute",
      "--confirm",
      confirm,
    ),
  );
  assert.equal(differentTenant.code, 2, differentTenant.stdout);
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run(
    writeArgs("ops", "--body-file", "-", "--execute", "--confirm", confirm),
    await state(),
    false,
    false,
    undefined,
    false,
    (child) => child.stdin!.end(text),
  );
  assert.equal(result.code, 0, result.stdout);
  assert.equal(requests()[0]!.body, text);
});

test("raw write redacts secret query values in preview and journal", async () => {
  const args = writeArgs(
    "ops",
    "--query",
    "password=hidden&password=other&token_count=5",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /hidden|other/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  assert.doesNotMatch(JSON.stringify(await journal(env)), /hidden|other/);
  assert.match(result.stdout, /token_count=5/);
});

test("raw write never executes under FALCON_AXI_READ_ONLY but still previews", async () => {
  const file = await body();
  const confirm = await confirmValue("ops", file);
  const env = await state();
  const refused = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
    { ...env, FALCON_AXI_READ_ONLY: "1" },
  );
  assert.equal(refused.code, 1, refused.stdout);
  assert.equal(value(refused.stdout).code, "READ_ONLY_VIOLATION");
  const preview = await run(writeArgs("ops", "--body-file", file), {
    ...env,
    FALCON_AXI_READ_ONLY: "1",
  });
  assert.equal(preview.code, 0, preview.stdout);
  assert.equal(wire.length, 0);
});

test("raw write records an upstream failure in the journal and reports it", async () => {
  const file = await body();
  const env = await state();
  const confirm = await confirmValue("ops", file);
  recordedResponse("PATCH /example/entities/things/v1", 503, {}, true);
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
    env,
  );
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "UPSTREAM_UNAVAILABLE");
  assert.match(result.stdout, /Reconcile the target before retrying/);
  assert.doesNotMatch(result.stdout, /Retry shortly/);
  assert.deepEqual(
    (value(result.stdout).preview as Record<string, unknown>).body,
    { name: "synthetic", enabled: true },
  );
  assert.equal(requests().length, 1);
  const records = await journal(env);
  assert.equal(records.at(-1)!.status, 503);
});

for (const status of [200, 403])
  test(`raw get redacts secret assignments in text response ${status}`, async () => {
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      headers: { "content-type": "text/plain" },
      body: Buffer.from("password: two words\ntoken_count=5"),
    }));
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.doesNotMatch(result.stdout, /two|words/);
    assert.match(result.stdout, /token_count=5/);
    assert.match(result.stdout, /\[redacted\]/);
  });

for (const status of [200, 403])
  test(`raw get preserves JSON null in response ${status}`, async () => {
    recordedResponse("GET /example/entities/things/v1", status, null);
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.equal(
      value(result.stdout)[status === 200 ? "body" : "upstream_body"],
      null,
    );
  });

test("raw write reports a failed outcome journal after sending", async () => {
  const shim = join(process.cwd(), ".typescript-build", "raw-fault.so");
  execFileSync("/usr/bin/gcc", [
    "-B/usr/bin/",
    "-shared",
    "-fPIC",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-o",
    shim,
    "tests/typescript/native-fault.c",
    "-ldl",
  ]);
  const file = await body();
  const confirm = await confirmValue("ops", file);
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
    {
      ...env,
      LD_PRELOAD: shim,
      FALCON_TEST_FILE: env.FALCON_AXI_WRITE_LOG,
      FALCON_TEST_FLUSH_NUMBER: "3",
    },
  );
  assert.equal(result.code, 1, result.stdout);
  assert.equal(requests().length, 1);
  assert.match(result.stdout, /was sent/);
  assert.match(result.stdout, /Reconcile the target before retrying/);
  assert.equal(value(result.stdout).upstream_status, 200);
});

test("raw output redacts exact secret pairs and preserves metadata", async () => {
  recordedResponse("GET /user-management/entities/users/v1", 200, {
    resources: [
      { key: "CID", data: "hidden", kind: "tenant" },
      { attribute: "customer_id", val: "hidden" },
      { name: "token_count", value: 5 },
      { field: "access_token", values: ["hidden"] },
    ],
  });
  const result = await run(getArgs("/user-management/entities/users/v1"));
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(value(result.stdout).body, {
    resources: [
      { key: "CID", data: "[redacted]", kind: "tenant" },
      { attribute: "customer_id", val: "[redacted]" },
      { name: "token_count", value: 5 },
      { field: "access_token", values: "[redacted]" },
    ],
  });
});
