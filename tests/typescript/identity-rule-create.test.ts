import assert from "node:assert/strict";
import { test, beforeEach } from "node:test";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { decode } from "@toon-format/toon";
import { directory, run, reset, wire, recordedResponse } from "./s01.test.js";

let config: string;
beforeEach(async () => {
  reset();
  config = join(directory, "identity-rule-profiles.json");
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
          operations: ["identity-rule-create"],
        }),
        rawOnly: profile({ allowWrites: true, operations: ["raw-write"] }),
      },
    }),
    { mode: 0o600 },
  );
});
const value = (stdout: string): Record<string, unknown> =>
  decode(stdout) as Record<string, unknown>;
const requests = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");
const rule = {
  trigger: "access",
  simulationMode: false,
  name: "synthetic-rule-name",
  enabled: true,
  action: "BLOCK",
};
const canonical = JSON.stringify({
  action: "BLOCK",
  enabled: true,
  name: "synthetic-rule-name",
  simulationMode: false,
  trigger: "access",
});
async function bodyFile(body: unknown = rule): Promise<string> {
  const file = join(directory, "identity-rule-body.json");
  await writeFile(file, JSON.stringify(body));
  return file;
}
function args(profile: string, ...rest: string[]): string[] {
  return [
    "identity",
    "rule",
    "create",
    "--config",
    config,
    "--profile",
    profile,
    ...rest,
  ];
}
async function state(): Promise<NodeJS.ProcessEnv> {
  const path = await mkdtemp(join(directory, "identity-rule-state-"));
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
async function confirmValue(file: string): Promise<string> {
  const preview = await run(args("ops", "--body-file", file));
  assert.equal(preview.code, 0, preview.stdout);
  return (value(preview.stdout).preview as { confirm: string }).confirm;
}

test("identity rule create previews without reaching the transport", async () => {
  const file = await bodyFile();
  const result = await run(args("ops", "--body-file", file));
  assert.equal(result.code, 0, result.stdout);
  const preview = value(result.stdout).preview as Record<string, unknown>;
  assert.equal(preview.method, "POST");
  assert.equal(preview.path, "/identity-protection/entities/policy-rules/v1");
  assert.deepEqual(preview.body, JSON.parse(canonical));
  assert.equal(wire.length, 0);
});

test("identity rule create sends nothing for a missing or wrong confirm", async () => {
  const file = await bodyFile();
  const missing = await run(args("ops", "--body-file", file, "--execute"));
  assert.equal(missing.code, 2, missing.stdout);
  assert.equal(value(missing.stdout).code, "VALIDATION_ERROR");
  const wrong = await run(
    args("ops", "--body-file", file, "--execute", "--confirm", "nope"),
  );
  assert.equal(wrong.code, 2, wrong.stdout);
  assert.equal(value(wrong.stdout).code, "VALIDATION_ERROR");
  assert.equal(wire.length, 0);
});

test("identity rule create rejects confirm without execute before any request", async () => {
  const file = await bodyFile();
  const result = await run(
    args("ops", "--body-file", file, "--confirm", "previewed"),
  );
  assert.equal(result.code, 2, result.stdout);
  assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
  assert.equal(wire.length, 0);
});

test("identity rule create never executes under FALCON_AXI_READ_ONLY but still previews", async () => {
  const file = await bodyFile();
  const confirm = await confirmValue(file);
  const refused = await run(
    args("ops", "--body-file", file, "--execute", "--confirm", confirm),
    { FALCON_AXI_READ_ONLY: "1" },
  );
  assert.equal(refused.code, 1, refused.stdout);
  assert.equal(value(refused.stdout).code, "READ_ONLY_VIOLATION");
  reset();
  const preview = await run(args("ops", "--body-file", file), {
    FALCON_AXI_READ_ONLY: "1",
  });
  assert.equal(preview.code, 0, preview.stdout);
  assert.equal(wire.length, 0);
});

test("identity rule create journals an executed write and sends the canonical body once", async () => {
  const file = await bodyFile();
  const env = await state();
  const confirm = await confirmValue(file);
  recordedResponse("post_policy_rules", 200, {
    resources: [{ id: "synthetic-rule" }],
  });
  const result = await run(
    args("ops", "--body-file", file, "--execute", "--confirm", confirm),
    env,
  );
  assert.equal(result.code, 0, result.stdout);
  assert.equal(requests().length, 1);
  assert.equal(requests()[0]!.method, "POST");
  assert.equal(
    requests()[0]!.url,
    "/identity-protection/entities/policy-rules/v1",
  );
  assert.equal(requests()[0]!.body, canonical);
  const output = value(result.stdout);
  assert.equal(output.status, 200);
  const records = await journal(env);
  assert.deepEqual(
    records.map((record) => record.phase),
    ["intent", "outcome"],
  );
  assert.equal(records[0]!.outcome, "not_sent");
  assert.equal(records[1]!.outcome, "responded");
  assert.equal(records[1]!.status, 200);
  assert.equal(JSON.stringify(records).includes("synthetic-rule-name"), false);
});

test("identity rule create sends nothing for a malformed body or a profile that did not opt in", async () => {
  const malformed = await bodyFile({ ...rule, extra: true });
  const refused = await run(args("ops", "--body-file", malformed));
  assert.equal(refused.code, 2, refused.stdout);
  assert.equal(value(refused.stdout).code, "VALIDATION_ERROR");
  const file = await bodyFile();
  const optedOut = await run(args("rawOnly", "--body-file", file));
  assert.equal(optedOut.code, 1, optedOut.stdout);
  assert.equal(value(optedOut.stdout).code, "READ_ONLY_VIOLATION");
  assert.equal(wire.length, 0);
});

test("identity rule create reports a missing scope from the upstream refusal", async () => {
  const file = await bodyFile();
  const env = await state();
  const confirm = await confirmValue(file);
  recordedResponse("post_policy_rules", 403, {
    errors: [{ code: 403, message: "access denied" }],
  });
  const result = await run(
    args("ops", "--body-file", file, "--execute", "--confirm", confirm),
    env,
  );
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "SCOPE_DENIED");
  assert.equal(requests().length, 1);
});
