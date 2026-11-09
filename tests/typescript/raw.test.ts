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
  "/example/%2e%2e/devices",
  "/example/%zz",
])
  test(`raw get refuses ${path} before any request`, async () => {
    const result = await run(getArgs(path));
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

test("raw get accepts URI path characters and long paths", async () => {
  const path = `/example/${"a".repeat(260)}%20x:@!$&'()*+,;=`;
  recordedResponse(`GET ${path}`, 200, { ok: true });
  const result = await run(getArgs(path));
  assert.equal(result.code, 0, result.stdout);
  assert.equal(requests()[0]!.url, path);
});

test("raw get does not replay a failed request", async () => {
  recordedResponse("GET /example/entities/things/v1", 503, {});
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  assert.equal(requests().length, 1);
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
    body: Buffer.from([0x37, 0x7a, 0xff]),
  }));
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  assert.match(result.stdout, /binary/);
});

test("raw get refuses a binary error body", async () => {
  dynamicResponse("GET /example/entities/things/v1", () => ({
    status: 403,
    body: Buffer.from([0x61, 0xff]),
  }));
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  assert.match(result.stdout, /binary/);
  assert.equal(value(result.stdout).upstream_body, undefined);
});

for (const status of [200, 403])
  test(`raw write reports a sent request with a binary ${status} response`, async () => {
    const file = await body();
    const confirm = await confirmValue("ops", file);
    dynamicResponse("PATCH /example/entities/things/v1", () => ({
      status,
      body: Buffer.from([0x61, 0]),
    }));
    const result = await run(
      writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
      await state(),
    );
    assert.equal(result.code, 1, result.stdout);
    assert.match(result.stdout, /binary/);
    assert.match(result.stdout, /was sent/);
    assert.match(result.stdout, /Reconcile the target before retrying/);
    assert.equal(value(result.stdout).status, status);
    assert.equal(value(result.stdout).upstream_body, undefined);
  });

test("raw get preserves a valid UTF-8 replacement character", async () => {
  recordedResponse("GET /example/entities/things/v1", 200, {
    description: "a�b",
  });
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(value(result.stdout).body, { description: "a�b" });
});

test("raw write preserves a valid UTF-8 replacement character", async () => {
  const file = await body();
  const confirm = await confirmValue("ops", file);
  recordedResponse(
    "PATCH /example/entities/things/v1",
    200,
    { description: "a�b" },
    true,
  );
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
    await state(),
  );
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(value(result.stdout).body, { description: "a�b" });
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

for (const text of [
  '{"role":"admin","role":"viewer"}',
  '{"nested":[{"role":"admin","role":"viewer"}]}',
])
  test("raw write rejects duplicate JSON members before preview", async () => {
    const file = join(directory, "duplicate-body.json");
    await writeFile(file, text);
    const args = writeArgs("ops", "--body-file", file);
    const preview = await run(args);
    assert.equal(preview.code, 2, preview.stdout);
    assert.equal(value(preview.stdout).code, "VALIDATION_ERROR");
    assert.equal(value(preview.stdout).preview, undefined);
    assert.equal(wire.length, 0);
  });

for (const status of [200, 403])
  test(`raw response ${status} associates duplicate pairs by position`, async () => {
    const pair =
      '{ "key":"api_key", "value":"hidden", "key":"retention_days", "value":30 }';
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(pair),
    }));
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.equal(
      value(result.stdout)[status === 200 ? "body" : "upstream_body"],
      '{ "key":"api_key", "value":"[redacted]", "key":"retention_days", "value":30 }',
    );
  });

for (const status of [200, 403])
  test(`raw response ${status} preserves duplicate JSON members`, async () => {
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(
        '{"items":[{"role":"admin","role":"viewer","token":"hidden"}]}',
      ),
    }));
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.equal(
      value(result.stdout)[status === 200 ? "body" : "upstream_body"],
      '{"items":[{"role":"admin","role":"viewer","token":"[redacted]"}]}',
    );
  });

test("raw output preserves bulk duplicate members while redacting secrets", async () => {
  const input = `{${'"password":"hidden","label":"visible",'.repeat(3000)}"tail":"end"}`;
  const expected = `{${'"password":"[redacted]","label":"visible",'.repeat(3000)}"tail":"end"}`;
  dynamicResponse("GET /example/entities/things/v1", () => ({
    status: 200,
    body: Buffer.from(input),
  }));
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 0, result.stdout);
  assert.equal(value(result.stdout).body, expected);
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

test("raw write rejects confirmation after the API client changes", async () => {
  const file = await body();
  const confirm = await confirmValue("ops", file);
  const document = JSON.parse(await readFile(config, "utf8")) as {
    profiles: { ops: { clientId: string } };
  };
  document.profiles.ops.clientId = "synthetic-different-client";
  await writeFile(config, JSON.stringify(document));
  const result = await run(
    writeArgs("ops", "--body-file", file, "--execute", "--confirm", confirm),
  );
  assert.equal(result.code, 2, result.stdout);
  assert.match(result.stdout, /--confirm must match/);
  assert.doesNotMatch(result.stdout, /synthetic-different-client/);
  assert.equal(wire.length, 0);
});

test("raw error preserves complete redacted serialized secret pairs", async () => {
  const body = JSON.stringify({
    key: "api_key",
    value: "secret-value",
    metadata: "x".repeat(2200),
  });
  recordedResponse("GET /example/entities/things/v1", 403, body);
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 1, result.stdout);
  assert.doesNotMatch(result.stdout, /secret-value/);
  assert.match(result.stdout, /\[redacted\]/);
  assert.equal(
    value(result.stdout).upstream_body,
    body.replace('"secret-value"', '"[redacted]"'),
  );
});

for (const method of ["GET", "PATCH"])
  test(`raw ${method} preserves a complete duplicate-member error`, async () => {
    const payload = `{"role":"admin","role":"viewer","password":"hidden","padding":"${"x".repeat(2200)}","tail":"visible"}`;
    dynamicResponse(`${method} /example/entities/things/v1`, () => ({
      status: 403,
      body: Buffer.from(payload),
    }));
    let result;
    if (method === "GET")
      result = await run(getArgs("/example/entities/things/v1"));
    else {
      const file = await body();
      const confirm = await confirmValue("ops", file);
      result = await run(
        writeArgs(
          "ops",
          "--body-file",
          file,
          "--execute",
          "--confirm",
          confirm,
        ),
        await state(),
      );
    }
    assert.equal(result.code, 1, result.stdout);
    assert.equal(
      value(result.stdout).upstream_body,
      payload.replace('"hidden"', '"[redacted]"'),
    );
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
    "password=hidden&password=other&filter=note%3A%20password%3A%27nestedsecret%27&url=https%3A%2F%2Fexample.invalid%2F%3Fsig%3Dsasvalue&token_count=5",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /hidden|other|nestedsecret|sasvalue/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  assert.doesNotMatch(
    JSON.stringify(await journal(env)),
    /hidden|other|nestedsecret|sasvalue/,
  );
  assert.match(
    decodeURIComponent(JSON.stringify(await journal(env))),
    /sig=\[redacted\]/,
  );
  assert.match(decodeURIComponent(requests()[0]!.url), /nestedsecret/);
  assert.match(result.stdout, /token_count=5/);
});

for (const name of ["key", "name", "field", "property", "attribute"])
  test(`raw write redacts query value when ${name} names a secret`, async () => {
    const query = new URLSearchParams([
      [name.toUpperCase(), "API_KEY"],
      ["value", "secret-value"],
      ["note", "visible"],
    ]);
    const args = writeArgs("ops", "--query", query.toString());
    const preview = await run(args);
    assert.equal(preview.code, 0, preview.stdout);
    assert.doesNotMatch(
      preview.stdout,
      /secret-value/,
    );
    const confirm = (value(preview.stdout).preview as Record<string, string>)
      .confirm!;
    const env = await state();
    recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
    const result = await run([...args, "--execute", "--confirm", confirm], env);
    assert.equal(result.code, 0, result.stdout);
    assert.doesNotMatch(
      JSON.stringify(await journal(env)),
      /secret-value/,
    );
    assert.match(decodeURIComponent(requests()[0]!.url), /secret-value/);
    assert.match(result.stdout, /note=visible/);
  });

test("raw write preserves non-secret query pairs", async () => {
  const result = await run(
    writeArgs("ops", "--query", "key=token_count&value=5"),
  );
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /key=token_count&value=5/);
});

test("raw write associates query pairs by position", async () => {
  const args = writeArgs(
    "ops",
    "--query",
    "key=api_key&note=visible&value=hidden&key=retention_days&value=30&key=api_key&key=retention_days&value=40",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /hidden/);
  assert.match(preview.stdout, /value=30/);
  assert.match(preview.stdout, /value=40/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  const records = JSON.stringify(await journal(env));
  assert.doesNotMatch(records, /hidden/);
  assert.match(records, /value=30/);
  assert.match(records, /value=40/);
});

test("raw write retains secret key association across name aliases", async () => {
  const args = writeArgs(
    "ops",
    "--query",
    "key=api_key&name=display&field=label&value=hidden&key=api_key&key=retention_days&value=30",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /hidden/);
  assert.match(preview.stdout, /name=display&field=label/);
  assert.match(preview.stdout, /value=30/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  const records = JSON.stringify(await journal(env));
  assert.doesNotMatch(records, /hidden/);
  assert.match(records, /name=display&field=label/);
  assert.match(records, /value=30/);
});

test("raw write redacts reversed query pairs in preview and journal", async () => {
  const args = writeArgs(
    "ops",
    "--query",
    "value=hidden&key=api_key&value=30&key=retention_days",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /hidden/);
  assert.match(preview.stdout, /value=30/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  const records = JSON.stringify(await journal(env));
  assert.doesNotMatch(records, /hidden/);
  assert.match(records, /value=30/);
});

test("raw write ignores non-pair query aliases", async () => {
  const args = writeArgs(
    "ops",
    "--query",
    "data=visible&key=api_key&value=hidden",
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.match(preview.stdout, /data=visible/);
  assert.doesNotMatch(preview.stdout, /hidden/);
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  const records = JSON.stringify(await journal(env));
  assert.match(records, /data=visible/);
  assert.doesNotMatch(records, /hidden/);
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
      body: Buffer.from(
        "password=alpha login failed, and password='two words' remains\ntoken_count=5",
      ),
    }));
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.doesNotMatch(result.stdout, /alpha|two words/);
    assert.match(
      result.stdout,
      /login failed, and password=\[redacted\] remains/,
    );
    assert.match(result.stdout, /token_count=5/);
    assert.match(result.stdout, /\[redacted\]/);
  });

test("raw output redacts nested secrets and preserves metadata", async () => {
  recordedResponse("GET /example/entities/things/v1", 200, {
    message: "note: password=hunter2",
    serialized: '{"password":"quotedsecret","label":"kept"}',
    metadata: "design=blue token_count=5",
    sas: "https://example.invalid/?sig=syntheticsignature&x=1",
    account: "AccountKey=accountsecret;name=visible",
  });
  const result = await run(getArgs("/example/entities/things/v1"));
  assert.equal(result.code, 0, result.stdout);
  assert.doesNotMatch(
    result.stdout,
    /hunter2|syntheticsignature|quotedsecret|accountsecret/,
  );
  assert.match(result.stdout, /design=blue token_count=5/);
  const body = value(result.stdout).body as Record<string, string>;
  assert.equal(body.sas, "https://example.invalid/?sig=[redacted]&x=1");
  assert.equal(body.account, "AccountKey=[redacted];name=visible");
  assert.match(body.serialized!, /password/);
  assert.match(body.serialized!, /label/);
});

for (const status of [200, 403])
  test(`raw response ${status} preserves serialized metadata bytes`, async () => {
    const untouched =
      ' { "label" : "visible", "label": "again", "count": 1e+02 } ';
    const pair =
      '{ "key" : "api_key", "value" : "secret-value", "label": 1, "label": 2 }';
    recordedResponse("GET /example/entities/things/v1", status, {
      untouched,
      pair,
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as Record<string, string>;
    assert.equal(body.untouched, untouched);
    assert.equal(
      body.pair,
      '{ "key" : "api_key", "value" : "[redacted]", "label": 1, "label": 2 }',
    );
  });

for (const status of [200, 403])
  test(`raw response ${status} replaces credential keys without collisions`, async () => {
    recordedResponse("GET /example/entities/things/v1", status, {
      pair: {
        "prefix-synthetic-s01-secret": "hidden",
        "[redacted-key-1]": "visible",
        "[redacted]": "other",
      },
      payload:
        '{ "prefix-synthetic-s01-secret" : "hidden", "[redacted-key-1]": "visible", "[redacted]": "other" }',
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { pair: unknown; payload: string };
    assert.deepEqual(body.pair, {
      "[redacted-key-2]": "[redacted]",
      "[redacted-key-1]": "visible",
      "[redacted]": "other",
    });
    assert.equal(
      body.payload,
      '{ "[redacted-key-2]" : "[redacted]", "[redacted-key-1]": "visible", "[redacted]": "other" }',
    );
    assert.doesNotMatch(result.stdout, /synthetic-s01-secret/);
  });

test("raw write preview replaces credential keys without collisions", async () => {
  const file = join(directory, "credential-key.json");
  const pair = {
    "prefix-synthetic-s01-secret": "hidden",
    "[redacted-key-1]": "visible",
    "[redacted]": "other",
  };
  await writeFile(file, JSON.stringify({ pair, payload: JSON.stringify(pair) }));
  const result = await run(writeArgs("ops", "--body-file", file));
  assert.equal(result.code, 0, result.stdout);
  const body = (
    value(result.stdout).preview as { body: { pair: unknown; payload: string } }
  ).body;
  const expected = {
    "[redacted-key-2]": "[redacted]",
    "[redacted-key-1]": "visible",
    "[redacted]": "other",
  };
  assert.deepEqual(body.pair, expected);
  assert.deepEqual(JSON.parse(body.payload), expected);
  assert.doesNotMatch(result.stdout, /synthetic-s01-secret/);
});

for (const status of [200, 403])
  test(`raw write ${status} redacts embedded credentials and intervening aliases`, async () => {
    const pair = {
      key: "api_key",
      name: "display label",
      value: "hidden-pair",
      "prefix-synthetic-s01-secret": "hidden-key",
      "[redacted-key-1]": "visible",
    };
    const expected = {
      key: "api_key",
      name: "display label",
      value: "[redacted]",
      "[redacted-key-2]": "[redacted]",
      "[redacted-key-1]": "visible",
    };
    const file = join(directory, "intervening-pair.json");
    await writeFile(
      file,
      JSON.stringify({ pair, serialized: JSON.stringify(pair) }),
    );
    const args = writeArgs("ops", "--body-file", file);
    const preview = await run(args);
    assert.equal(preview.code, 0, preview.stdout);
    const previewData = value(preview.stdout).preview as {
      body: { pair: unknown; serialized: string };
      confirm: string;
    };
    assert.deepEqual(previewData.body.pair, expected);
    assert.deepEqual(JSON.parse(previewData.body.serialized), expected);
    recordedResponse(
      "PATCH /example/entities/things/v1",
      status,
      { pair, serialized: JSON.stringify(pair) },
      true,
    );
    const result = await run(
      [...args, "--execute", "--confirm", previewData.confirm],
      await state(),
    );
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { pair: unknown; serialized: string };
    assert.deepEqual(body.pair, expected);
    assert.deepEqual(JSON.parse(body.serialized), expected);
    assert.doesNotMatch(
      result.stdout,
      /synthetic-s01-secret|hidden-pair|hidden-key/,
    );
  });

for (const status of [200, 403])
  test(`raw response ${status} redacts serialized pairs`, async () => {
    recordedResponse("GET /example/entities/things/v1", status, {
      payload:
        '[{"key":"api_key","value":"pairsecret","count":9007199254740993},{"name":"token_count","value":5}]',
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.doesNotMatch(result.stdout, /pairsecret/);
    assert.match(result.stdout, /9007199254740993/);
    assert.match(result.stdout, /token_count/);
    assert.match(result.stdout, /\[redacted\]/);
  });

test("raw write redacts serialized pairs in preview and journal", async () => {
  const pair =
    '{ "key" : "api_key", "value" : "pairsecret", "label": "visible", "label": 2 }';
  const file = join(directory, "pair-body.json");
  await writeFile(file, JSON.stringify({ payload: pair }));
  const args = writeArgs(
    "ops",
    "--body-file",
    file,
    "--query",
    new URLSearchParams({ filter: pair }).toString(),
  );
  const preview = await run(args);
  assert.equal(preview.code, 0, preview.stdout);
  assert.doesNotMatch(preview.stdout, /pairsecret/);
  assert.match(preview.stdout, /visible/);
  const previewBody = (
    value(preview.stdout).preview as { body: { payload: string } }
  ).body;
  assert.equal(
    previewBody.payload,
    '{ "key" : "api_key", "value" : "[redacted]", "label": "visible", "label": 2 }',
  );
  const confirm = (value(preview.stdout).preview as Record<string, string>)
    .confirm!;
  const env = await state();
  recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
  const result = await run([...args, "--execute", "--confirm", confirm], env);
  assert.equal(result.code, 0, result.stdout);
  assert.doesNotMatch(JSON.stringify(await journal(env)), /pairsecret/);
  assert.match(
    decodeURIComponent(JSON.stringify(await journal(env))),
    /visible/,
  );
  const recorded = (await journal(env))[0]!.path as string;
  assert.equal(
    new URL(`https://example.invalid${recorded}`).searchParams.get("filter"),
    '{ "key" : "api_key", "value" : "[redacted]", "label": "visible", "label": 2 }',
  );
});

test("raw write preview preserves metadata in serialized duplicate pairs", async () => {
  const pair =
    '{"key":"api_key","value":"hidden","key":"retention_days","value":30}';
  const file = join(directory, "serialized-pairs.json");
  await writeFile(file, JSON.stringify({ payload: pair }));
  const result = await run(writeArgs("ops", "--body-file", file));
  assert.equal(result.code, 0, result.stdout);
  const preview = value(result.stdout).preview as { body: { payload: string } };
  assert.equal(
    preview.body.payload,
    '{"key":"api_key","value":"[redacted]","key":"retention_days","value":30}',
  );
});

test("scopes distinguishes raw routes from registered commands", async () => {
  const result = await run(["scopes"]);
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /raw routes require the scopes Falcon documents/);
  assert.match(
    result.stdout,
    /gated raw writes under N5 can send caller-supplied GraphQL/,
  );
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
      { key: "CID", value: "hidden", kind: "tenant" },
      { attribute: "customer_id", value: "hidden" },
      { name: "token_count", value: 5 },
      { field: "access_token", value: ["hidden"] },
      { key: "api_key", value: "hidden", name: "retention_days", data: 30 },
    ],
  });
  const result = await run(getArgs("/user-management/entities/users/v1"));
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(value(result.stdout).body, {
    resources: [
      { key: "CID", value: "[redacted]", kind: "tenant" },
      { attribute: "customer_id", value: "[redacted]" },
      { name: "token_count", value: 5 },
      { field: "access_token", value: ["[redacted]"] },
      { key: "api_key", value: "[redacted]", name: "retention_days", data: 30 },
    ],
  });
});

for (const status of [200, 403])
  test(`raw response ${status} preserves structured secret metadata`, async () => {
    const structured = {
      password: {
        value: "hidden",
        expires: { value: "tomorrow" },
        nested: { val: "visible", label: "keep", token: "hidden" },
        tags: ["visible"],
      },
      key: "api_key",
      value: { value: "hidden", expires: "later" },
      token: ["hidden", { value: "hidden", expires: "soon" }],
    };
    const expected = {
      password: {
        value: "[redacted]",
        expires: { value: "tomorrow" },
        nested: { val: "visible", label: "keep", token: "[redacted]" },
        tags: ["visible"],
      },
      key: "api_key",
      value: { value: "[redacted]", expires: "later" },
      token: ["[redacted]", { value: "[redacted]", expires: "soon" }],
    };
    recordedResponse("GET /example/entities/things/v1", status, {
      structured,
      serialized: JSON.stringify(structured),
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { structured: unknown; serialized: string };
    assert.deepEqual(body.structured, expected);
    assert.deepEqual(JSON.parse(body.serialized), expected);
  });

test("raw write preview preserves structured secret metadata", async () => {
  const file = join(directory, "structured-secret.json");
  const structured = {
    password: { value: "hidden", expires: { value: "tomorrow" } },
  };
  await writeFile(
    file,
    JSON.stringify({ ...structured, serialized: JSON.stringify(structured) }),
  );
  const result = await run(writeArgs("ops", "--body-file", file));
  assert.equal(result.code, 0, result.stdout);
  const body = (value(result.stdout).preview as {
    body: { password: unknown; serialized: string };
  }).body;
  const expected = {
    password: { value: "[redacted]", expires: { value: "tomorrow" } },
  };
  assert.deepEqual(body.password, expected.password);
  assert.deepEqual(JSON.parse(body.serialized), expected);
});

for (const status of [200, 403])
  test(`raw response ${status} redacts reversed pairs and nested arrays`, async () => {
    const structured = {
      value: "hidden-pair",
      key: "api_key",
      token: [
        ["hidden-array"],
        [{ value: "hidden-object", expires: "tomorrow" }],
      ],
    };
    const serialized =
      '{"value":"hidden-pair","key":"api_key","value":30,"key":"retention_days","token":[["hidden-array"]]}';
    recordedResponse("GET /example/entities/things/v1", status, {
      structured,
      serialized,
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { structured: unknown; serialized: string };
    assert.deepEqual(body.structured, {
      value: "[redacted]",
      key: "api_key",
      token: [
        ["[redacted]"],
        [{ value: "[redacted]", expires: "tomorrow" }],
      ],
    });
    assert.equal(
      body.serialized,
      '{"value":"[redacted]","key":"api_key","value":30,"key":"retention_days","token":[["[redacted]"]]}',
    );
  });

test("raw write preview redacts reversed pairs and nested arrays", async () => {
  const file = join(directory, "reversed-pair.json");
  await writeFile(
    file,
    JSON.stringify({ value: "hidden-pair", key: "api_key", token: [["hidden-array"]] }),
  );
  const result = await run(writeArgs("ops", "--body-file", file));
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual((value(result.stdout).preview as { body: unknown }).body, {
    value: "[redacted]",
    key: "api_key",
    token: [["[redacted]"]],
  });
});

for (const status of [200, 403])
  test(`raw response ${status} ignores non-pair aliases`, async () => {
    const pair = { data: "visible", key: "api_key", value: "hidden" };
    recordedResponse("GET /example/entities/things/v1", status, {
      pair,
      serialized: JSON.stringify(pair),
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { pair: unknown; serialized: string };
    const expected = { data: "visible", key: "api_key", value: "[redacted]" };
    assert.deepEqual(body.pair, expected);
    assert.deepEqual(JSON.parse(body.serialized), expected);
  });

for (const status of [200, 403])
  test(`raw response ${status} redacts registered numeric credentials`, async () => {
    const serialized = '{"reference":1.23456789e8,"count":1.0}';
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(
        `{"reference":1.23456789e8,"serialized":${JSON.stringify(serialized)},"distinct":1.2345678900000001e8}`,
      ),
    }));
    const result = await run(getArgs("/example/entities/things/v1"), {
      ARTIUM_SECRET_0: "123456789",
    });
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.doesNotMatch(result.stdout, /123456789/);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { reference: string; serialized: string };
    assert.equal(body.reference, "[redacted]");
    assert.equal(body.serialized, '{"reference":"[redacted]","count":1.0}');
    assert.match(result.stdout, /1\.2345678900000001e8/);
  });

for (const status of [200, 403])
  test(`raw write preview and response ${status} redact numeric credentials`, async () => {
  const file = join(directory, "numeric-secret.json");
  await writeFile(file, '{"reference":1.23456789e8,"count":1.0}');
  const args = writeArgs("ops", "--body-file", file);
  const result = await run(args, {
    ARTIUM_SECRET_0: "123456789",
  });
  assert.equal(result.code, 0, result.stdout);
  assert.doesNotMatch(result.stdout, /123456789/);
  const body = (value(result.stdout).preview as {
    body: Record<string, unknown>;
  }).body;
  assert.equal(body.reference, "[redacted]");
  assert.match(result.stdout, /count: 1\.0/);
  const confirm = (value(result.stdout).preview as Record<string, string>).confirm!;
  dynamicResponse("PATCH /example/entities/things/v1", () => ({
    status,
    body: Buffer.from('{"reference":1.23456789e8,"count":1.0}'),
  }));
  const executed = await run([...args, "--execute", "--confirm", confirm], {
    ...(await state()),
    ARTIUM_SECRET_0: "123456789",
  });
  assert.equal(executed.code, status === 200 ? 0 : 1, executed.stdout);
  assert.doesNotMatch(executed.stdout, /123456789/);
  assert.equal(
    (value(executed.stdout)[status === 200 ? "body" : "upstream_body"] as Record<string, unknown>).reference,
    "[redacted]",
  );
  });

for (const status of [200, 403])
  test(`raw response ${status} preserves numeric credential substrings`, async () => {
    const serialized = '{"number":91234567890,"match":1.23456789e8}';
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(
        `{"number":91234567890,"match":1.23456789e8,"serialized":${JSON.stringify(serialized)}}`,
      ),
    }));
    const result = await run(getArgs("/example/entities/things/v1"), {
      ARTIUM_SECRET_0: "123456789",
    });
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as { number: number; match: string; serialized: string };
    assert.equal(body.number, 91234567890);
    assert.equal(body.match, "[redacted]");
    assert.equal(
      body.serialized,
      '{"number":91234567890,"match":"[redacted]"}',
    );
    assert.match(result.stdout, /91234567890/);
  });

for (const status of [200, 403])
  test(`raw write ${status} preserves numeric credential substrings`, async () => {
    const text = '{"number":91234567890,"match":1.23456789e8}';
    const file = join(directory, "numeric-substring.json");
    await writeFile(file, text);
    const args = writeArgs("ops", "--body-file", file);
    const env = { ...(await state()), ARTIUM_SECRET_0: "123456789" };
    const preview = await run(args, env);
    assert.equal(preview.code, 0, preview.stdout);
    const body = (value(preview.stdout).preview as {
      body: Record<string, unknown>;
    }).body;
    assert.equal(body.number, 91234567890);
    assert.equal(body.match, "[redacted]");
    const confirm = (value(preview.stdout).preview as Record<string, string>)
      .confirm!;
    dynamicResponse("PATCH /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(text),
    }));
    const result = await run([...args, "--execute", "--confirm", confirm], env);
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const response = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as Record<string, unknown>;
    assert.equal(response.number, 91234567890);
    assert.equal(response.match, "[redacted]");
    assert.match(result.stdout, /91234567890/);
  });

for (const status of [200, 403])
  test(`raw response ${status} preserves non-pair aliases and decimal text`, async () => {
    const text =
      '{"data":"visible","key":"api_key","value":"hidden","threshold":0.10000000000000001,"count":1.0}';
    dynamicResponse("GET /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(text),
    }));
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const body = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as Record<string, unknown>;
    assert.equal(body.data, "visible");
    assert.equal(body.value, "[redacted]");
    assert.equal(body.threshold, 0.1);
    assert.equal(body.count, 1);
    assert.match(result.stdout, /threshold: 0\.10000000000000001/);
    assert.match(result.stdout, /count: 1\.0/);
  });

for (const status of [200, 403])
  test(`raw write preserves decimal text in preview and response ${status}`, async () => {
    const text =
      '{"data":"visible","key":"api_key","value":"hidden","threshold":0.10000000000000001,"count":1.0}';
    const file = join(directory, "decimal-body.json");
    await writeFile(file, text);
    const args = writeArgs("ops", "--body-file", file);
    const preview = await run(args);
    assert.equal(preview.code, 0, preview.stdout);
    const previewBody = (value(preview.stdout).preview as {
      body: Record<string, unknown>;
    }).body;
    assert.equal(previewBody.value, "[redacted]");
    assert.equal(previewBody.threshold, 0.1);
    assert.equal(previewBody.count, 1);
    assert.match(preview.stdout, /threshold: 0\.10000000000000001/);
    assert.match(preview.stdout, /count: 1\.0/);
    const confirm = (value(preview.stdout).preview as Record<string, string>)
      .confirm!;
    dynamicResponse("PATCH /example/entities/things/v1", () => ({
      status,
      body: Buffer.from(text),
    }));
    const result = await run(
      [...args, "--execute", "--confirm", confirm],
      await state(),
    );
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    const responseBody = value(result.stdout)[
      status === 200 ? "body" : "upstream_body"
    ] as Record<string, unknown>;
    assert.equal(responseBody.value, "[redacted]");
    assert.equal(responseBody.threshold, 0.1);
    assert.equal(responseBody.count, 1);
    assert.match(result.stdout, /threshold: 0\.10000000000000001/);
    assert.match(result.stdout, /count: 1\.0/);
  });

for (const alias of ["value", "val", "values", "string_value"])
  test(`raw output redacts ${alias} pairs in either order`, async () => {
    const pairs = [
      { data: "visible", key: "api_key", [alias]: "hidden-forward" },
      { [alias]: "hidden-reverse", key: "api_key", data: "visible" },
    ];
    recordedResponse("GET /example/entities/things/v1", 200, {
      pairs,
      serialized: JSON.stringify(pairs),
    });
    const result = await run(getArgs("/example/entities/things/v1"));
    assert.equal(result.code, 0, result.stdout);
    assert.doesNotMatch(result.stdout, /hidden-forward|hidden-reverse/);
    const body = value(result.stdout).body as {
      pairs: Record<string, string>[];
      serialized: string;
    };
    assert.deepEqual(body.pairs.map((pair) => [pair.data, pair[alias]]), [
      ["visible", "[redacted]"],
      ["visible", "[redacted]"],
    ]);
    assert.deepEqual(JSON.parse(body.serialized), body.pairs);
  });

for (const alias of ["val", "values", "string_value"])
  test(`raw write redacts ${alias} query pairs in preview and journal`, async () => {
    const args = writeArgs(
      "ops",
      "--query",
      `data=visible&${alias}=hidden&key=api_key`,
    );
    const preview = await run(args);
    assert.equal(preview.code, 0, preview.stdout);
    assert.doesNotMatch(preview.stdout, /hidden/);
    assert.match(preview.stdout, /data=visible/);
    const confirm = (value(preview.stdout).preview as Record<string, string>)
      .confirm!;
    const env = await state();
    recordedResponse("PATCH /example/entities/things/v1", 200, {}, true);
    const result = await run([...args, "--execute", "--confirm", confirm], env);
    assert.equal(result.code, 0, result.stdout);
    const records = JSON.stringify(await journal(env));
    assert.doesNotMatch(records, /hidden/);
    assert.match(records, /data=visible/);
  });
