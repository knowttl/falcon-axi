import assert from "node:assert/strict";
import { test, beforeEach } from "node:test";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
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
  config = join(directory, "identity-rule-delete-profiles.json");
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
        ops: profile({
          allowWrites: true,
          operations: ["identity-rule-delete"],
        }),
        createOnly: profile({
          allowWrites: true,
          operations: ["identity-rule-create"],
        }),
      },
    }),
    { mode: 0o600 },
  );
});
const value = (stdout: string): Record<string, unknown> =>
  decode(stdout) as Record<string, unknown>;
const requests = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");
const target =
  "/identity-protection/entities/policy-rules/v1?ids=synthetic-rule";
function args(profile: string, id: string, ...rest: string[]): string[] {
  return [
    "identity",
    "rule",
    "delete",
    id,
    "--config",
    config,
    "--profile",
    profile,
    ...rest,
  ];
}
async function state(): Promise<NodeJS.ProcessEnv> {
  const path = await mkdtemp(join(directory, "identity-rule-delete-state-"));
  return { FALCON_AXI_WRITE_LOG: join(path, "writes.log") };
}
async function journal(
  env: NodeJS.ProcessEnv,
): Promise<Record<string, unknown>[]> {
  return (await readFile(env.FALCON_AXI_WRITE_LOG!, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}
async function confirmValue(id = "synthetic-rule"): Promise<string> {
  const preview = await run(args("ops", id));
  assert.equal(preview.code, 0, preview.stdout);
  return (value(preview.stdout).preview as { confirm: string }).confirm;
}

test("identity rule delete previews without reaching the transport", async () => {
  const result = await run(args("ops", "synthetic-rule"));
  assert.equal(result.code, 0, result.stdout);
  const preview = value(result.stdout).preview as Record<string, unknown>;
  assert.equal(preview.method, "DELETE");
  assert.equal(preview.path, target);
  assert.equal(wire.length, 0);
});

test("identity rule delete sends nothing for a missing or wrong confirm", async () => {
  const missing = await run(args("ops", "synthetic-rule", "--execute"));
  assert.equal(missing.code, 2, missing.stdout);
  assert.equal(value(missing.stdout).code, "VALIDATION_ERROR");
  const wrong = await run(
    args("ops", "synthetic-rule", "--execute", "--confirm", "nope"),
  );
  assert.equal(wrong.code, 2, wrong.stdout);
  assert.equal(value(wrong.stdout).code, "VALIDATION_ERROR");
  const other = await run(
    args(
      "ops",
      "synthetic-rule",
      "--execute",
      "--confirm",
      await confirmValue("synthetic-other"),
    ),
  );
  assert.equal(other.code, 2, other.stdout);
  assert.equal(value(other.stdout).code, "VALIDATION_ERROR");
  assert.equal(wire.length, 0);
});

test("identity rule delete rejects confirm without execute before any request", async () => {
  const result = await run(
    args("ops", "synthetic-rule", "--confirm", "previewed"),
  );
  assert.equal(result.code, 2, result.stdout);
  assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
  assert.equal(wire.length, 0);
});

test("identity rule delete never executes under FALCON_AXI_READ_ONLY but still previews", async () => {
  const confirm = await confirmValue();
  const refused = await run(
    args("ops", "synthetic-rule", "--execute", "--confirm", confirm),
    { FALCON_AXI_READ_ONLY: "1" },
  );
  assert.equal(refused.code, 1, refused.stdout);
  assert.equal(value(refused.stdout).code, "READ_ONLY_VIOLATION");
  reset();
  const preview = await run(args("ops", "synthetic-rule"), {
    FALCON_AXI_READ_ONLY: "1",
  });
  assert.equal(preview.code, 0, preview.stdout);
  assert.equal(wire.length, 0);
});

test("identity rule delete journals an executed write and sends one DELETE", async () => {
  const env = await state();
  const confirm = await confirmValue();
  recordedResponse("delete_policy_rules", 200, { resources: [] });
  const result = await run(
    args("ops", "synthetic-rule", "--execute", "--confirm", confirm),
    env,
  );
  assert.equal(result.code, 0, result.stdout);
  assert.equal(requests().length, 1);
  assert.equal(requests()[0]!.method, "DELETE");
  assert.equal(requests()[0]!.url, target);
  assert.equal(requests()[0]!.body, "");
  assert.equal(value(result.stdout).status, 200);
  const records = await journal(env);
  assert.deepEqual(
    records.map((record) => record.phase),
    ["intent", "outcome"],
  );
  assert.equal(records[0]!.outcome, "not_sent");
  assert.equal(records[1]!.outcome, "responded");
  assert.equal(records[1]!.status, 200);
});

for (const status of [200, 403])
  test(`identity rule delete preserves a ${status} text response`, async () => {
    const confirm = await confirmValue();
    dynamicResponse("delete_policy_rules", () => ({
      status,
      headers: { "content-type": "text/plain" },
      body: Buffer.from("plain response"),
    }));
    const result = await run(
      args("ops", "synthetic-rule", "--execute", "--confirm", confirm),
      await state(),
    );
    assert.equal(result.code, status === 200 ? 0 : 1, result.stdout);
    assert.equal(
      value(result.stdout)[status === 200 ? "body" : "upstream_body"],
      "plain response",
    );
  });

for (const id of ["bad id", "a/b", "a?ids=b", "a&ids=b", "../x", "a%2Fb"])
  test(`identity rule delete refuses the malformed identifier ${id} before any request`, async () => {
    const preview = await run(args("ops", id));
    assert.equal(preview.code, 2, preview.stdout);
    assert.equal(value(preview.stdout).code, "VALIDATION_ERROR");
    const execute = await run(
      args("ops", id, "--execute", "--confirm", await confirmValue()),
    );
    assert.equal(execute.code, 2, execute.stdout);
    assert.equal(value(execute.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

test("identity rule delete sends nothing for a profile that did not opt in", async () => {
  for (const profile of ["reader", "createOnly"]) {
    const result = await run(args(profile, "synthetic-rule"));
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "READ_ONLY_VIOLATION");
  }
  assert.equal(wire.length, 0);
});

test("identity rule delete reports a missing scope from the upstream refusal", async () => {
  const confirm = await confirmValue();
  recordedResponse("delete_policy_rules", 403, {
    errors: [{ code: 403, message: "access denied" }],
  });
  const result = await run(
    args("ops", "synthetic-rule", "--execute", "--confirm", confirm),
    await state(),
  );
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "SCOPE_DENIED");
  assert.equal(requests().length, 1);
});
