import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decode } from "@toon-format/toon";
import {
  prepareScenario,
  run,
  reset,
  recordedResponse,
  wire,
} from "./s01.test.js";
import type { Scenario } from "./s01.test.js";
import s06 from "../fixtures/migration/S06/contracts.json" with { type: "json" };
import s07 from "../fixtures/migration/S07/contracts.json" with { type: "json" };
import { operation } from "../../src/transport/operations.js";
import { dynamicResponse } from "./s01.test.js";
import "./s04-s05.test.js";
import { Cursor } from "../../src/cursor.js";
import { CliError } from "../../src/core.js";
import { malformed } from "../../src/response.js";
import diagnostics from "../diagnostics/response-diagnostics-vectors.json" with { type: "json" };
import { registerSecret } from "../../src/render.js";

// Validator-library annotations have no runtime producer in the candidate.
// Exercise the retained response-shape contract at the actual validation boundary.
for (const vector of diagnostics.filter((vector) => !("issues" in vector)))
  test(`S06/S07 diagnostic ${vector.name}`, () => {
    if ("secrets" in vector)
      for (const secret of vector.secrets) registerSecret(secret);
    assert.throws(
      () =>
        malformed(
          {
            status: vector.status,
            headers: { "content-type": vector.contentType ?? "" },
            body: vector.data,
          },
          "invalid response",
        ),
      (error) => {
        assert.ok(error instanceof CliError);
        // The vector supplies a custom redactor; the CLI's established marker is [redacted].
        const expected = JSON.parse(
          JSON.stringify(vector.expected).replaceAll(
            "***redacted***",
            "[redacted]",
          ),
        ) as unknown;
        assert.deepEqual(error.details, expected);
        return true;
      },
    );
  });

for (const row of [
  {
    name: "recon",
    args: ["recon-rule", "list"],
    op: "QueryRulesV1",
    position: 9999,
    query: undefined,
    rows: ["synthetic-deleted"],
    entity: "GetRulesV1",
  },
  {
    name: "data",
    args: ["classification", "list"],
    op: "queries_classification_get_v2",
    position: 10000,
    query: "[null,null]",
    rows: ["synthetic-deleted"],
    entity: "entities_classification_get_v2",
  },
])
  test(`S06/S07 pagination wall ${row.name}`, async () => {
    const cursor = new Cursor(
      {
        clientId: "synthetic-s01-client",
        clientSecret: "synthetic-s01-secret",
      },
      "https://api.crowdstrike.com",
      row.op,
      row.query,
    ).encode(row.position);
    reset();
    recordedResponse(row.op, 200, {
      resources: row.rows,
      meta: { pagination: { total: 10002 } },
    });
    recordedResponse(row.entity, 200, { resources: [] });
    const result = await run([...row.args, "--limit", "2", "--cursor", cursor]);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /pagination_limit/);
    assert.doesNotMatch(result.stdout, /continuation_cursor/);
    const request = wire.find((entry) =>
      entry.url.startsWith(operation(row.op).path),
    )!;
    assert.equal(
      new URL(request.url, "https://synthetic.invalid").searchParams.get(
        "limit",
      ),
      row.name === "recon" ? "1" : "2",
    );
  });

for (const name of [
  "actor-list-page",
  "indicator-list-page",
  "recon-rule-list",
  "policy-list-prevention",
  "exclusion-ml-list",
  "classification-list",
  "firewall-rule-list",
])
  test(`S06/S07 filter remedy ${name}`, async () => {
    const scenario = JSON.parse(
      readFileSync(resolve("tests/golden/scenarios", `${name}.json`), "utf8"),
    ) as Scenario;
    const op = scenario.responders![0]!.op;
    reset();
    recordedResponse(op, 400, { errors: [{ message: "invalid filter" }] });
    const result = await run([...scenario.argv, "--filter", "invalid"]);
    assert.equal(result.code, 2, result.stdout);
    assert.match(result.stdout, /FQL_INVALID/);
    assert.ok(result.stdout.includes(scenario.argv.slice(0, 2).join(" ")));
    assert.doesNotMatch(result.stdout, /falcon-axi detection list/);
  });

const scenarios = [...s06.goldenScenarioIds, ...s07.goldenScenarioIds].map(
  (name) =>
    JSON.parse(
      readFileSync(resolve("tests/golden/scenarios", `${name}.json`), "utf8"),
    ) as Scenario,
);
const examples = [...s06.operationIds, ...s07.operationIds].map((op) => {
  const scenario = scenarios.find(
    (entry) =>
      entry.exit_code === 0 &&
      entry.responders?.some((response) => {
        if (response.op !== op || !response.fixture) return false;
        const fixture = JSON.parse(
          readFileSync(resolve("tests/fixtures", response.fixture), "utf8"),
        ) as { response: { body: unknown } };
        const body = fixture.response.body;
        return Array.isArray(body)
          ? body.length > 0
          : typeof body === "object" &&
              body !== null &&
              "resources" in body &&
              Array.isArray(body.resources) &&
              body.resources.length > 0;
      }),
  );
  if (!scenario) throw new Error(`No retained success for ${op}`);
  return { op, scenario };
});

for (const { op, scenario } of examples) {
  test(`S06/S07 scope ${op}`, async () => {
    await prepareScenario({
      ...scenario,
      responders: scenario.responders!.map((entry) =>
        entry.op === op
          ? {
              op,
              response: {
                status: 403,
                body: { errors: [{ code: 403, message: "access denied" }] },
              },
            }
          : entry,
      ),
    });
    const result = await run(scenario.argv);
    assert.equal(result.code, 1, result.stdout);
    const value = decode(result.stdout) as Record<string, unknown>;
    assert.equal(value.code, "SCOPE_DENIED");
    assert.deepEqual(value.required_scopes, operation(op).scopes);
  });
  test(`S06/S07 malformed ${op}`, async () => {
    await prepareScenario({
      ...scenario,
      responders: scenario.responders!.map((entry) =>
        entry.op === op
          ? {
              op,
              response: {
                status: 200,
                body: { unexpected: "synthetic-private-value" },
              },
            }
          : entry,
      ),
    });
    const result = await run(scenario.argv);
    assert.equal(result.code, 1, result.stdout);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
    assert.doesNotMatch(result.stdout, /synthetic-private-value/);
  });
}

test("S06/S07 empty MITRE is explicit", async () => {
  const scenario = scenarios.find(
    (entry) => entry.name === "actor-show-mitre",
  )!;
  await prepareScenario({
    ...scenario,
    responders: scenario.responders!.map((entry) =>
      entry.op === "GetMitreReport"
        ? { op: entry.op, response: { status: 200, body: null } }
        : entry,
    ),
  });
  const result = await run(scenario.argv);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(
    (decode(result.stdout) as Record<string, unknown>).mitre,
    "0 ATT&CK mappings for this actor",
  );
});

for (const [name, body, empty] of [
  ["HTML", "<html>synthetic-private-value</html>", false],
  ["truncated JSON", '[{"synthetic-private-value":', false],
  ["empty bytes", "", false],
  ["whitespace", " \n", false],
  ["JSON null", "null", true],
  ["empty array", "[]", true],
] as const)
  test(`S06/S07 MITRE response bytes ${name}`, async () => {
    const scenario = scenarios.find(
      (entry) => entry.name === "actor-show-mitre",
    )!;
    await prepareScenario(scenario);
    dynamicResponse("GetMitreReport", () => ({
      status: 200,
      body: Buffer.from(body),
    }));
    const result = await run(scenario.argv);
    assert.equal(result.code, empty ? 0 : 1, result.stdout);
    if (empty)
      assert.equal(
        (decode(result.stdout) as Record<string, unknown>).mitre,
        "0 ATT&CK mappings for this actor",
      );
    else {
      assert.match(result.stdout, /UPSTREAM_ERROR/);
      assert.doesNotMatch(result.stdout, /0 ATT&CK mappings/);
    }
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-private-value/);
  });

test("S06/S07 malware redacts PEM before preview", async () => {
  const scenario = scenarios.find((entry) => entry.name === "malware-show")!;
  const slug = scenario.argv.at(-1)!;
  const description =
    "-----BEGIN PRIVATE KEY-----\n" +
    "synthetic-private-key-material".repeat(40) +
    "\n-----END PRIVATE KEY-----";
  await prepareScenario({
    ...scenario,
    responders: [
      {
        op: scenario.responders![0]!.op,
        response: {
          status: 200,
          body: { resources: [{ slug, description }] },
        },
      },
    ],
  });
  for (const args of [scenario.argv, [...scenario.argv, "--full"]]) {
    const result = await run(args);
    assert.equal(result.code, 0, result.stdout);
    const output = decode(result.stdout) as {
      malware: { description: string };
    };
    assert.equal(output.malware.description, "[redacted]");
    assert.doesNotMatch(
      result.stdout + result.stderr,
      /synthetic-private-key-material|PRIVATE KEY/,
    );
  }
});

test("S06/S07 identity rule filter uses REST names and values", async () => {
  reset();
  recordedResponse("get_policy_rules_query", 200, { resources: [] });
  const result = await run([
    "identity",
    "rule",
    "list",
    "--name",
    "Synthetic rule",
    "--enabled",
    "false",
    "--simulation-mode",
    "true",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const query = new URL(
    wire.find((request) =>
      request.url.startsWith(operation("get_policy_rules_query").path),
    )!.url,
    "https://synthetic.invalid",
  ).searchParams;
  assert.deepEqual(Object.fromEntries(query), {
    name: "Synthetic rule",
    enabled: "false",
    simulation_mode: "true",
  });
});

for (const row of [
  { args: ["sandbox", "show", "synthetic-report-01"], op: "GetSummaryReports" },
  {
    args: ["policy", "show", "synthetic-policy-01", "--type", "device-control"],
    op: "getDeviceControlPoliciesV2",
  },
])
  test(`S06/S07 exact detail ${row.op}`, async () => {
    reset();
    recordedResponse(row.op, 200, { resources: [{ id: "synthetic-other" }] });
    const result = await run(row.args);
    assert.equal(result.code, 1, result.stdout);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
    assert.doesNotMatch(result.stdout, /synthetic-other/);
  });

test("S06/S07 hydration loss preserves query cursor and total", async () => {
  reset();
  recordedResponse("exclusions_search_v2", 200, {
    resources: ["synthetic-deleted"],
    meta: { pagination: { total: 2 } },
  });
  recordedResponse("exclusions_get_v2", 200, { resources: [] });
  const result = await run([
    "exclusion",
    "list",
    "--type",
    "ml",
    "--limit",
    "1",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const value = decode(result.stdout) as Record<string, unknown>;
  assert.deepEqual(value.exclusions, []);
  assert.equal(value.count, "0 of 2 total");
  const payload = JSON.parse(
    Buffer.from(String(value.continuation_cursor), "base64url").toString(),
  ) as { position: number };
  assert.equal(payload.position, 1);
  reset();
  const changed = await run([
    "exclusion",
    "list",
    "--type",
    "ioa",
    "--cursor",
    String(value.continuation_cursor),
  ]);
  assert.equal(changed.code, 2, changed.stdout);
  assert.equal(
    wire.filter((request) => request.url !== "/oauth2/token").length,
    0,
  );
});

for (const name of ["recon-rule-list"])
  test(`S06/S07 raw entities ${name}`, async () => {
    const scenario = scenarios.find((entry) => entry.name === name)!;
    const responder = scenario.responders![1]!;
    const fixture = JSON.parse(
      readFileSync(resolve("tests/fixtures", responder.fixture!), "utf8"),
    ) as { response: { body: { resources: unknown[] } } };
    await prepareScenario({
      ...scenario,
      responders: [
        scenario.responders![0]!,
        {
          op: responder.op,
          response: { status: 200, body: fixture.response.body.resources },
        },
      ],
    });
    const result = await run(scenario.argv);
    assert.equal(result.code, 0, result.stdout);
    const expected = decode(
      readFileSync(resolve("tests/golden", `${name}.txt`), "utf8"),
    ) as Record<string, unknown>;
    const actual = decode(result.stdout) as Record<string, unknown>;
    assert.deepEqual(
      actual[name.startsWith("recon") ? "records" : "policies"],
      expected[name.startsWith("recon") ? "records" : "policies"],
    );
  });

for (const entry of [
  {
    argv: ["case", "list"],
    query: "queries_cases_get_v1",
    entity: "entities_cases_post_v2",
    key: "cases",
  },
  {
    argv: ["recon-rule", "list"],
    query: "QueryRulesV1",
    entity: "GetRulesV1",
    key: "records",
  },
  {
    argv: ["identity", "rule", "list"],
    query: "get_policy_rules_query",
    entity: "get_policy_rules",
    key: "rules",
  },
  {
    argv: ["classification", "list"],
    query: "queries_classification_get_v2",
    entity: "entities_classification_get_v2",
    key: "classifications",
  },
])
  test(`S06/S07 chunk hydration ${entry.query}`, async () => {
    reset();
    const ids = Array.from({ length: 205 }, (_, index) => `synthetic-${index}`);
    recordedResponse(entry.query, 200, {
      resources: ids,
      meta: { pagination: { total: 205 } },
    });
    dynamicResponse(entry.entity, (query, body) => ({
      status: 200,
      body: {
        resources: (Array.isArray(body.ids)
          ? (body.ids as string[])
          : query.getAll("ids")
        )
          .toReversed()
          .map((id) => ({ id, name: id })),
      },
    }));
    const result = await run(entry.argv);
    assert.equal(result.code, 0, result.stdout);
    const value = decode(result.stdout) as Record<string, unknown>;
    assert.deepEqual(
      (value[entry.key] as { id: string }[]).map((row) => row.id),
      ids,
    );
    assert.equal(value.count, "205 of 205 total");
    const sizes = wire
      .filter((request) => request.url.startsWith(operation(entry.entity).path))
      .map((request) =>
        operation(entry.entity).method === "POST"
          ? (JSON.parse(request.body) as { ids: string[] }).ids.length
          : new URL(
              request.url,
              "https://synthetic.invalid",
            ).searchParams.getAll("ids").length,
      );
    assert.deepEqual(sizes, [100, 100, 5]);
  });

test("S06/S07 firewall server token takes precedence and exhausts", async () => {
  reset();
  recordedResponse("query_rules", 200, {
    resources: ["synthetic-rule"],
    meta: { pagination: { total: 3, next: "synthetic-token" } },
  });
  recordedResponse("get_rules", 200, {
    resources: [{ id: "synthetic-rule", name: "Synthetic rule" }],
  });
  const first = await run(["firewall", "rule", "list", "--limit", "1"]);
  assert.equal(first.code, 0, first.stdout);
  const cursor = String(
    (decode(first.stdout) as Record<string, unknown>).continuation_cursor,
  );
  reset();
  recordedResponse("query_rules", 200, { resources: [] });
  const last = await run([
    "firewall",
    "rule",
    "list",
    "--limit",
    "1",
    "--cursor",
    cursor,
  ]);
  assert.equal(last.code, 0, last.stdout);
  assert.match(
    wire.find((request) =>
      request.url.startsWith(operation("query_rules").path),
    )!.url,
    /after=synthetic-token/,
  );
  assert.doesNotMatch(last.stdout, /continuation_cursor/);
});

test("S06/S07 missing indicator marker refuses incomplete continuation", async () => {
  reset();
  recordedResponse("QueryIntelIndicatorEntities", 200, {
    resources: [{ id: "synthetic-indicator" }],
    meta: { pagination: { total: 2 } },
  });
  const result = await run(["indicator", "list", "--limit", "1"]);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /no advancing indicator marker/);
});

for (const op of ["GetSummaryReports", "getDeviceControlPoliciesV2"])
  test(`S06/S07 incomplete hydration ${op}`, async () => {
    const scenario = examples.find((entry) => entry.op === op)!.scenario;
    await prepareScenario({
      ...scenario,
      responders: scenario.responders!.map((entry) =>
        entry.op === op
          ? { op, response: { status: 200, body: { resources: [] } } }
          : entry,
      ),
    });
    const result = await run(scenario.argv);
    assert.equal(result.code, 1, result.stdout);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
  });

for (const name of [
  "actor-show",
  "recon-notification-show",
  "firewall-rule-show",
  "malware-show",
])
  test(`S06/S07 redaction before preview ${name}`, async () => {
    const scenario = scenarios.find((entry) => entry.name === name)!;
    const op = scenario.responders![0]!.op;
    const id = scenario.argv.at(-1)!;
    const value = "🦅".repeat(900);
    await prepareScenario({
      ...scenario,
      responders: [
        {
          op,
          response: {
            status: 200,
            body: {
              resources: [
                {
                  id,
                  slug: id,
                  description: value,
                  cid: "synthetic-private-cid",
                  nested: {
                    content: value,
                    client_secret: "synthetic-private-secret",
                  },
                },
              ],
            },
          },
        },
      ],
    });
    const result = await run(scenario.argv);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /--full/);
    assert.doesNotMatch(result.stdout, /synthetic-private-(cid|secret)/);
    await prepareScenario({
      ...scenario,
      responders: [
        {
          op,
          response: {
            status: 200,
            body: { resources: [{ id, slug: id, description: value }] },
          },
        },
      ],
    });
    const full = await run([...scenario.argv, "--full"]);
    assert.equal(full.code, 0, full.stdout);
    assert.ok(full.stdout.includes(value));
  });

for (const argv of [
  ["sandbox", "list"],
  ["sandbox", "list", "--sha256", "bad"],
  ["policy", "list"],
  ["policy", "show", "synthetic", "--type", "prevention"],
  ["exclusion", "list", "--type", "certificate", "--limit", "101"],
  ["data-policy", "list"],
  ["classification", "list", "--sort", "unsupported.asc"],
  ["identity", "rule", "list", "--enabled", "yes"],
])
  test(`S06/S07 pre-auth ${argv.join(" ")}`, async () => {
    reset();
    const result = await run(argv);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(wire.length, 0);
  });

for (const { op, scenario } of examples.filter(
  ({ scenario, op }) =>
    (scenario.argv.includes("list") || scenario.argv.includes("members")) &&
    scenario.responders?.[0]?.op === op &&
    op !== "get_policy_rules_query",
)) {
  test(`S06/S07 continuation ${op}`, async () => {
    const first = scenario.responders![0]!;
    const body =
      first.response?.body ??
      (
        JSON.parse(
          await readFile(resolve("tests/fixtures", first.fixture!), "utf8"),
        ) as { response: { body: unknown } }
      ).response.body;
    const envelope = body as { resources: unknown[] };
    const row = envelope.resources[0];
    const args = [
      ...scenario.argv.filter(
        (_, index, args) =>
          args[index] !== "--limit" && args[index - 1] !== "--limit",
      ),
      "--limit",
      "1",
    ];
    await prepareScenario({
      ...scenario,
      responders: [
        {
          op,
          response: {
            status: 200,
            body: { resources: [row], meta: { pagination: { total: 2 } } },
          },
        },
        ...scenario.responders!.slice(1),
      ],
    });
    const firstResult = await run(args);
    assert.equal(firstResult.code, 0, firstResult.stdout);
    const cursor = String(
      (decode(firstResult.stdout) as Record<string, unknown>)
        .continuation_cursor,
    );
    assert.notEqual(cursor, "undefined");
    reset();
    recordedResponse(op, 200, { resources: [] });
    const result = await run([...args, "--cursor", cursor]);
    assert.equal(result.code, 0, result.stdout);
    assert.doesNotMatch(result.stdout, /continuation_cursor/);
    const request = wire.find((entry) =>
      entry.url.startsWith(operation(op).path),
    );
    assert.ok(request);
    const query = new URL(request.url, "https://synthetic.invalid")
      .searchParams;
    if (op === "QueryIntelIndicatorEntities")
      assert.match(query.get("filter")!, /_marker:>'/);
    else assert.equal(query.get("offset"), "1");
    reset();
    recordedResponse(op, 200, { resources: [] });
    const changed = await run([
      ...args,
      "--filter",
      "name:'different'",
      "--cursor",
      cursor,
    ]);
    assert.equal(changed.code, 2, changed.stdout);
    assert.equal(
      wire.filter((entry) => entry.url !== "/oauth2/token").length,
      0,
    );
  });
}

for (const name of [...s06.goldenScenarioIds, ...s07.goldenScenarioIds])
  test(`S06/S07 retained ${name}`, async () => {
    const scenario = JSON.parse(
      await readFile(resolve("tests/golden/scenarios", `${name}.json`), "utf8"),
    ) as Scenario;
    await prepareScenario(scenario);
    const result = await run(
      scenario.argv,
      process.env.S01_ACTIVE_PATH === "artium"
        ? {}
        : {
            FALCON_AXI_PROFILE: undefined,
            FALCON_AXI_CONFIG: "/nonexistent/falcon-axi/config.json",
            FALCON_AXI_CLIENT_ID: undefined,
            FALCON_AXI_CLIENT_SECRET: undefined,
            FALCON_CLIENT_ID: "synthetic-client-id",
            FALCON_CLIENT_SECRET: "synthetic-client-secret",
          },
    );
    assert.equal(result.code, scenario.exit_code, result.stdout);
    const reference = await readFile(
      resolve("tests/golden", `${name}.txt`),
      "utf8",
    );
    if (process.env.S01_ACTIVE_PATH !== "artium" || name.startsWith("help-")) {
      assert.equal(
        result.stdout,
        process.env.S01_ACTIVE_PATH === "artium"
          ? reference.replaceAll("falcon-axi ", "artium-axi falcon-axi ")
          : reference,
      );
      return;
    }
    const expected = decode(reference) as Record<string, unknown>;
    const actual = decode(result.stdout) as Record<string, unknown>;
    delete expected.continuation_cursor;
    delete actual.continuation_cursor;
    delete expected.help;
    delete actual.help;
    // Continuation help contains credential-bound migration cursor encodings.
    if (Array.isArray(expected.help))
      expected.help = expected.help.filter(
        (entry: unknown) =>
          typeof entry !== "string" || !entry.includes("--cursor ey"),
      );
    if (Array.isArray(actual.help))
      actual.help = actual.help.filter(
        (entry: unknown) =>
          typeof entry !== "string" || !entry.includes("--cursor ey"),
      );
    assert.deepEqual(actual, expected);
  });
