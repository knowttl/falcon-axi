import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolve } from "node:path";
import { decode } from "@toon-format/toon";
import { parse as parseGraphql, visit, Kind } from "graphql";
import {
  prepareScenario,
  run,
  reset,
  recordedResponse,
  tokenResponse,
  dynamicResponse,
  managedAudit,
  wire,
} from "./s01.test.js";
import type { Scenario } from "./s01.test.js";
import "./s06-s07.test.js";
import s08 from "../fixtures/migration/S08/contracts.json" with { type: "json" };
import s09 from "../fixtures/migration/S09/contracts.json" with { type: "json" };
import s10 from "../fixtures/migration/S10/contracts.json" with { type: "json" };
import cql from "../fixtures/migration/S08/cql-vectors.json" with { type: "json" };
import documents from "../../src/transport/documents.json" with { type: "json" };
import { document } from "../../src/transport/search-authority.js";
import { requestException } from "../../src/transport/https.js";
import { CliError, object } from "../../src/core.js";
import { operation } from "../../src/transport/operations.js";

const managed = process.env.S01_ACTIVE_PATH === "artium";
const requestId = "00000000-0000-4000-8000-000000000001";
const aid = "a".repeat(32);
const graph = "api_preempt_proxy_post_graphql";
const value = (stdout: string): Record<string, unknown> =>
  decode(stdout) as Record<string, unknown>;
const scenario = (name: string): Scenario =>
  JSON.parse(
    readFileSync(resolve("tests/golden/scenarios", `${name}.json`), "utf8"),
  ) as Scenario;
const fixture = (path: string): unknown =>
  (
    JSON.parse(readFileSync(resolve("tests/fixtures", path), "utf8")) as {
      response: { body: unknown };
    }
  ).response.body;
const creation = (args: string[]): string =>
  args[0] === "malquery"
    ? args.includes("--fuzzy")
      ? "PostMalQueryFuzzySearchV1"
      : "PostMalQueryExactSearchV1"
    : "StartSearchV1";
const scoped = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");

for (const id of [
  "abc",
  "a".repeat(31),
  "a".repeat(33),
  "g".repeat(32),
  "0".repeat(32),
])
  test(`live findings host show refuses invalid id ${id} before authentication`, async () => {
    reset();
    recordedResponse("PostDeviceDetailsV2", 400, {
      errors: [{ message: "synthetic invalid device id" }],
    });
    const result = await run(["host", "show", id]);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.match(result.stdout, /32-character hexadecimal device id/);
    assert.equal(wire.length, 0);
  });

for (const found of [true, false])
  test(`live findings host show valid synthetic id found=${found}`, async () => {
    reset();
    recordedResponse("PostDeviceDetailsV2", 200, {
      resources: found ? [{ device_id: aid, hostname: "SYNTHETIC-HOST" }] : [],
    });
    const result = await run(["host", "show", aid]);
    assert.equal(result.code, found ? 0 : 1, result.stdout);
    assert.match(result.stdout, found ? /SYNTHETIC-HOST/ : /NOT_FOUND/);
    assert.deepEqual(JSON.parse(scoped()[0]!.body), { ids: [aid] });
  });

test("live findings audit rejection retains UPSTREAM_ERROR with scope and request guidance", async () => {
  reset();
  recordedResponse("RTRAuditSessions", 400, {
    meta: { trace_id: requestId },
    errors: [{ message: "synthetic refusal" }],
  });
  const result = await run(["rtr", "audit", "list", "--limit", "3"]);
  assert.equal(result.code, 1, result.stdout);
  const data = value(result.stdout);
  assert.equal(data.code, "UPSTREAM_ERROR");
  assert.equal(data.trace_id, requestId);
  assert.match(result.stdout, /Real time response audit:read/);
  assert.match(result.stdout, /falcon-axi scopes/);
  assert.match(result.stdout, /request.*trace_id/);
  assert.equal(data.required_scopes, undefined);
  assert.doesNotMatch(result.stdout, /synthetic refusal/);
});

test("live findings audit scope denial names the audit scope", async () => {
  reset();
  recordedResponse("RTRAuditSessions", 403, {});
  const result = await run(["rtr", "audit", "list", "--limit", "3"]);
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "SCOPE_DENIED");
  assert.deepEqual(value(result.stdout).required_scopes, [
    "Real time response audit:read",
  ]);
});

for (const rows of [
  [],
  [{ id: "synthetic-audit-session", created_at: "2026-01-01T00:00:00Z" }],
])
  test(`live findings audit success with ${rows.length} rows`, async () => {
    reset();
    recordedResponse("RTRAuditSessions", 200, {
      resources: rows,
      meta: { pagination: { total: rows.length } },
    });
    const result = await run(["rtr", "audit", "list", "--limit", "3"]);
    assert.equal(result.code, 0, result.stdout);
    assert.match(
      result.stdout,
      rows.length ? /synthetic-audit-session/ : /0 audit_sessions/,
    );
  });

for (const [status, exitCode, field, expected, guidance] of [
  [200, 0, "state", "cancelled", /run the search again/],
  [
    400,
    1,
    "code",
    "NOT_FOUND",
    /stopped or expired job as well as for a wrong job id/,
  ],
  [404, 1, "code", "NOT_FOUND", /completed or cancelled job expires/],
] as const)
  test(`live findings search status after stop with synthetic ${status} response`, async () => {
    reset();
    recordedResponse("StopSearchV1", 204, null);
    const stopped = await run([
      "search",
      "stop",
      "synthetic-job",
      "--repository",
      "synthetic-repo",
    ]);
    assert.equal(stopped.code, 0, stopped.stdout);
    assert.match(stopped.stdout, /stopped job may no longer be queryable/);
    assert.doesNotMatch(stopped.stdout, /confirm the job reports cancelled/);
    recordedResponse("GetSearchStatusV1", status, {
      cancelled: true,
      meta: { trace_id: requestId },
    });
    const result = await run([
      "search",
      "status",
      "synthetic-job",
      "--repository",
      "synthetic-repo",
    ]);
    assert.equal(result.code, exitCode, result.stdout);
    const data = value(result.stdout);
    assert.equal(data[field], expected);
    assert.match(result.stdout, guidance);
    assert.deepEqual(
      scoped().map((request) => request.method),
      ["DELETE", "GET"],
    );
  });

test("live findings search status rejection preserves trace and avoids FQL advice", async () => {
  reset();
  recordedResponse("GetSearchStatusV1", 400, {
    meta: { trace_id: requestId },
    errors: [{ message: "synthetic query rejection" }],
  });
  const result = await run(["search", "status", "synthetic-job"]);
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "NOT_FOUND");
  assert.equal(value(result.stdout).trace_id, requestId);
  assert.match(
    result.stdout,
    /stopped or expired job as well as for a wrong job id/,
  );
  assert.doesNotMatch(result.stdout, /job was stopped\b(?! as well)/);
  assert.match(result.stdout, /same.*--repository/);
  assert.doesNotMatch(
    result.stdout,
    /Check the flags|FQL|synthetic query rejection/,
  );
});

for (const [slice, names] of [
  ["S08", s08.goldenScenarioIds],
  ["S09", s09.goldenScenarioIds],
  ["S10", s10.goldenScenarioIds],
] as const)
  for (const name of names)
    test(`${slice} retained ${name}`, async () => {
      const entry = scenario(name);
      await prepareScenario(entry);
      const result = await run(
        entry.argv,
        managed
          ? {}
          : {
              FALCON_AXI_PROFILE: undefined,
              FALCON_AXI_CONFIG: "/nonexistent/falcon-axi/config.json",
              FALCON_AXI_CLIENT_ID: undefined,
              FALCON_AXI_CLIENT_SECRET: undefined,
              FALCON_CLIENT_ID: "synthetic-client-id",
              FALCON_CLIENT_SECRET: "synthetic-client-secret",
              ...entry.envExtra,
            },
      );
      assert.equal(result.code, entry.exit_code, result.stdout);
      const reference = readFileSync(
        resolve("tests/golden", `${name}.txt`),
        "utf8",
      );
      if (!managed || name.startsWith("help-"))
        assert.equal(
          result.stdout,
          managed
            ? [s08, s09, s10]
                .flatMap((contract) => contract.commandNames)
                .reduce(
                  (text, command) =>
                    text.replaceAll(
                      `falcon-axi ${command}`,
                      `artium-axi falcon-axi ${command}`,
                    ),
                  reference,
                )
            : reference,
        );
      else {
        const expected = value(reference),
          actual = value(result.stdout);
        delete expected.help;
        delete actual.help;
        delete expected.continuation_cursor;
        delete actual.continuation_cursor;
        assert.deepEqual(actual, expected);
      }
    });

const creations = [
  ["search", "start", "--query", "* | head(1)"],
  ["search", "start", "--query", "* | head(1)", "--wait", "2"],
  ["identity", "activity", "synthetic.user$"],
  ["host", "usb", aid],
  ["malquery", "search", "--string", "SYNTHETIC"],
  ["malquery", "search", "--hex", "4D 5A", "--fuzzy"],
];
for (const args of creations)
  for (const fault of [
    "429-absent",
    "429-short",
    "500",
    "502",
    "503",
    "504",
    "drop",
    "truncate",
    "missing-id",
  ]) {
    const tier = args[0] === "malquery" ? "S10" : "S08";
    test(`${tier} no replay ${args.join(" ")} ${fault}`, async () => {
      reset();
      const op = creation(args);
      dynamicResponse(op, () => ({
        status: fault.startsWith("429")
          ? 429
          : /^5/.test(fault)
            ? Number(fault)
            : 200,
        headers:
          fault === "429-short"
            ? { "x-ratelimit-retryafter": String(Date.now() / 1000 + 0.01) }
            : {},
        body: {},
        ...(fault === "drop" || fault === "truncate" ? { fault } : {}),
      }));
      const result = await run(args);
      assert.equal(result.code, 1, result.stdout);
      assert.equal(scoped().length, 1, JSON.stringify(wire));
      assert.equal(scoped()[0]!.method, "POST");
      assert.doesNotMatch(
        result.stdout,
        /(?:no job exists|state: done|state: running|0 samples)/,
      );
    });
  }

const invalid = [
  {
    tier: "S08",
    args: ["search", "start", "--query", "*", "--repository", "../other"],
  },
  { tier: "S08", args: ["search", "status", "job/other"] },
  { tier: "S08", args: ["search", "status", "job", "--wait", "51"] },
  { tier: "S08", args: ["host", "usb", aid, "--wait", "1"] },
  { tier: "S08", args: ["identity", "activity", "user*", "--wait", "1"] },
  { tier: "S08", args: ["host", "usb", "bad"] },
  { tier: "S09", args: ["identity", "list", "--name", "*"] },
  { tier: "S09", args: ["identity", "list", "--email", "* *"] },
  { tier: "S09", args: ["identity", "list", "--type", "service"] },
  { tier: "S09", args: ["identity", "list", "--limit", "201"] },
  { tier: "S09", args: ["identity", "show", "bad"] },
  {
    tier: "S09",
    args: ["identity", "timeline", requestId, "--category", "unknown"],
  },
  { tier: "S09", args: ["identity", "assessment", "--domain", " "] },
  { tier: "S10", args: ["malquery", "show", "bad"] },
  { tier: "S10", args: ["malquery", "status", "bad"] },
  ...[
    [],
    ["--string", " "],
    ["--string", "a\nb"],
    ["--string", "é"],
    ["--string", "x".repeat(4097)],
    ["--hex", "abc"],
    ["--hex", "??"],
    ["--hex", "0g"],
    ["--hex", "00".repeat(4097)],
    ["--string", "valid", "--limit", "101"],
    ["--body", "{}"],
    ["--yara", "rule x {}"],
  ].map((flags) => ({ tier: "S10", args: ["malquery", "search", ...flags] })),
];
for (const [index, row] of invalid.entries())
  test(`${row.tier} pre-auth ${index}`, async () => {
    reset();
    const result = await run(row.args);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });
for (const [tier, args] of [
  ["S08", ["search", "start", "--query", "("]],
  ["S09", ["identity", "show", "bad"]],
] as const)
  test(`${tier} help bypasses validation`, async () => {
    reset();
    assert.equal((await run([...args, "--help"])).code, 0);
    assert.equal(wire.length, 0);
  });

for (const args of creations.filter((args) => !args.includes("--wait")))
  test(`${args[0] === "malquery" ? "S10" : "S08"} READ_ONLY ${args.join(" ")}`, async () => {
    reset();
    const result = await run(args, { FALCON_AXI_READ_ONLY: "1" });
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "READ_ONLY_VIOLATION");
    assert.equal(wire.length, 0);
  });

for (const [
  index,
  row,
] of cql.cases.test_structural_errors_have_actionable_diagnostics_before_authentication.entries())
  test(`S08 CQL structural ${index}`, async () => {
    const [query, message, line, column, expected] = row;
    reset();
    const result = await run(["search", "start", "--query", String(query)]);
    assert.equal(result.code, 2, result.stdout);
    assert.deepEqual(value(result.stdout).diagnostics, [
      { line, column, message, expected },
    ]);
    assert.equal(wire.length, 0);
  });
for (const [
  index,
  query,
] of cql.cases.test_valid_or_ambiguous_queries_reach_the_server_unchanged.entries())
  test(`S08 literal query ${index}`, async () => {
    reset();
    recordedResponse("StartSearchV1", 200, { id: "synthetic-job" });
    assert.equal((await run(["search", "start", "--query", query])).code, 0);
    assert.equal(
      (JSON.parse(scoped()[0]!.body) as { queryString: string }).queryString,
      query,
    );
  });
for (const [index, query] of [
  ...cql.cases.test_pre_auth_errors_never_echo_submitted_query_text,
  ...cql.cases.test_every_structural_failure_omits_private_query_content.map(
    (suffix) => `private_query_field=private_query_value | ${suffix}`,
  ),
  ...cql.cases.test_nested_empty_stages_fail_before_authentication,
  ...cql.cases.test_comma_cannot_end_an_assignment_without_an_expression,
].entries())
  test(`S08 CQL privacy ${index}`, async () => {
    reset();
    const result = await run(["search", "start", "--query", query]);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(wire.length, 0);
    assert.doesNotMatch(
      result.stdout,
      /synthetic-tenant|private_|#repo.cid|eyJzeW50aGV0aWM/,
    );
  });

test("S08 fixed query projections and literal subjects", async () => {
  reset();
  recordedResponse("StartSearchV1", 200, { id: "synthetic-job" });
  const result = await run([
    "identity",
    "activity",
    "user.name$",
    "--since",
    "7d",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const body = JSON.parse(scoped()[0]!.body) as {
    queryString: string;
    start: number;
    end: number;
  };
  assert.ok(
    body.queryString.includes(
      "SourceAccountSamAccountName=/^user\\.name\\$$/i",
    ),
  );
  assert.doesNotMatch(body.queryString, /Ticket|ObjectGuid/);
  assert.match(body.queryString, /limit=200/);
  assert.equal(body.end - body.start, 7 * 86400000);
});
test("S08 wait completion carries warnings and redacts tenant fields", async () => {
  reset();
  recordedResponse("StartSearchV1", 200, { id: "synthetic-job" });
  recordedResponse("GetSearchStatusV1", 200, {
    done: true,
    events: [
      {
        cid: "synthetic-tenant",
        "#repo.cid": "synthetic-tenant",
        name: "event",
      },
    ],
    metaData: {
      processedEvents: 10,
      eventCount: 1,
      filterQuery: { queryString: "other=value" },
    },
    warnings: [{ code: "synthetic", message: "Review this filter" }],
  });
  const result = await run([
    "search",
    "start",
    "--query",
    "* | head(1)",
    "--wait",
    "2",
  ]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(value(result.stdout).state, "done");
  assert.match(result.stdout, /normalized filter differs/);
  assert.doesNotMatch(result.stdout, /synthetic-tenant/);
  assert.equal(scoped().length, 2);
});
test("S08 warnings preserve safe messages", async () => {
  reset();
  recordedResponse("GetSearchStatusV1", 200, {
    done: true,
    events: [],
    warnings: [{ code: "synthetic", message: "synthetic-s01-secret" }],
  });
  const result = await run(["search", "status", "job"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /warnings/);
  assert.doesNotMatch(result.stdout, /synthetic-s01-secret/);
});
test("S08 repository recovery survives wait expiry and polling error", async () => {
  reset();
  recordedResponse("StartSearchV1", 200, { id: "synthetic-job" });
  recordedResponse("GetSearchStatusV1", 200, { done: false });
  const args = [
    "search",
    "start",
    "--query",
    "*",
    "--repository",
    "synthetic repo",
    "--wait",
    "1",
  ];
  const running = await run(args);
  assert.equal(running.code, 0, running.stdout);
  assert.equal(value(running.stdout).state, "running");
  assert.match(running.stdout, /--repository 'synthetic repo'/);
  assert.ok(running.elapsed < 1800);
  reset();
  recordedResponse("StartSearchV1", 200, { id: "synthetic-job" });
  recordedResponse("GetSearchStatusV1", 403, {});
  const failed = await run(args);
  assert.equal(failed.code, 1);
  assert.equal(value(failed.stdout).search_id, "synthetic-job");
  assert.equal(value(failed.stdout).repository, "synthetic repo");
});
test("S08 wait acquisition bounds retry hints and known-job failures", async () => {
  reset();
  dynamicResponse("GetSearchStatusV1", () => ({
    status: 429,
    body: {},
    headers: { "x-ratelimit-retryafter": String(Date.now() / 1000 + 30) },
  }));
  const result = await run(["search", "status", "known-job", "--wait", "1"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(value(result.stdout).state, "running");
  assert.equal(value(result.stdout).search_id, "known-job");
  assert.equal(scoped().length, 1);
  assert.ok(result.elapsed < 1800);
});
test("S08 repeat stop returns NOT_FOUND without creating a job", async () => {
  reset();
  recordedResponse("StopSearchV1", 204, null);
  assert.equal((await run(["search", "stop", "synthetic-job"])).code, 0);
  assert.deepEqual(
    scoped().map((request) => request.method),
    ["DELETE"],
  );
  reset();
  recordedResponse("StopSearchV1", 404, {});
  const result = await run(["search", "stop", "synthetic-job"]);
  assert.equal(result.code, 1, result.stdout);
  assert.equal(value(result.stdout).code, "NOT_FOUND");
  assert.deepEqual(
    scoped().map((request) => request.method),
    ["DELETE"],
  );
});
test("S08 wait acquisition settles while response bytes keep arriving", async () => {
  reset();
  dynamicResponse("GetSearchStatusV1", () => ({
    status: 200,
    body: {},
    fault: "stream",
  }));
  const result = await run(["search", "status", "known-job", "--wait", "1"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(value(result.stdout).state, "running");
  assert.equal(value(result.stdout).search_id, "known-job");
  assert.equal(scoped().length, 1);
  assert.ok(result.elapsed < 1800, `settlement: ${result.elapsed}ms`);
});
test("S08 query rejection retains CQL guidance", async () => {
  reset();
  recordedResponse("StartSearchV1", 400, {
    errors: [
      { message: "synthetic rejection" },
      { message: "synthetic-s01-secret" },
    ],
  });
  const result = await run(["search", "start", "--query", "*"]);
  assert.equal(result.code, 2);
  assert.match(result.stdout, /CQL/);
  assert.match(result.stdout, /synthetic rejection/);
  assert.doesNotMatch(result.stdout, /FQL_INVALID|synthetic-s01-secret/);
});
for (const [op, args] of [
  ["StartSearchV1", ["search", "start", "--query", "*"]],
  ["GetSearchStatusV1", ["search", "status", "job"]],
  [
    "PostMalQueryFuzzySearchV1",
    ["malquery", "search", "--string", "SYNTHETIC", "--fuzzy"],
  ],
  ["GetMalQueryMetadataV1", ["malquery", "show", "0".repeat(64)]],
] as const)
  test(`${args[0] === "malquery" ? "S10" : "S08"} scope ${op}`, async () => {
    reset();
    recordedResponse(op, 403, {});
    const result = await run([...args]);
    assert.equal(result.code, 1);
    assert.deepEqual(
      value(result.stdout).required_scopes,
      operation(op).scopes,
    );
    if (op === "PostMalQueryFuzzySearchV1")
      assert.match(result.stdout, /licensing.*N4/s);
  });

test("S09 document registry parses only fixed read roots and declared variables", () => {
  assert.equal(Object.keys(documents).length, 6);
  for (const [name, entry] of Object.entries(documents)) {
    const parsed = parseGraphql(entry.text);
    assert.equal(parsed.definitions.length, 1);
    const definition = parsed.definitions[0]!;
    assert.equal(definition.kind, Kind.OPERATION_DEFINITION);
    if (definition.kind !== Kind.OPERATION_DEFINITION)
      throw new Error("not query");
    assert.equal(definition.operation, "query");
    assert.equal(definition.selectionSet.selections.length, 1);
    const root = definition.selectionSet.selections[0]!;
    assert.equal(root.kind, Kind.FIELD);
    if (root.kind !== Kind.FIELD) throw new Error("not field");
    assert.equal(
      root.name.value,
      name === "identity_assessment"
        ? "securityAssessment"
        : name === "identity_timeline"
          ? "timeline"
          : "entities",
    );
    const variables = new Set<string>();
    visit(parsed, {
      Variable(node) {
        variables.add(node.name.value);
      },
    });
    assert.deepEqual([...variables].sort(), [...entry.variables].sort());
    const resolved = document(name);
    assert.ok(Object.isFrozen(resolved));
    assert.ok(Object.isFrozen(resolved.variables));
    assert.throws(() => {
      (resolved as { text: string }).text = "mutation { delete }";
    });
  }
});
for (const [name, authority] of [
  ["raw", { body: { query: "query { entities { nodes { entityId } } }" } }],
  ["mutation", { document: "mutation { delete }", variables: {} }],
  [
    "fragment",
    { document: "fragment x on Entity { entityId }", variables: {} },
  ],
  [
    "extra-root",
    {
      document: "query { entities { nodes { entityId } } delete }",
      variables: {},
    },
  ],
  [
    "undeclared",
    { document: "identity_list", variables: { mutation: "delete" } },
  ],
  ["body", { document: "identity_list", variables: {}, body: {} }],
] as const)
  test(`S09 authority refusal ${name}`, async () => {
    reset();
    await assert.rejects(
      async () =>
        requestException(
          graph,
          "https://api.crowdstrike.com",
          "synthetic-token",
          authority,
          false,
          new AbortController().signal,
        ),
      { code: "READ_ONLY_VIOLATION" },
    );
    assert.equal(wire.length, 0);
  });
test("S08 authority refusal rejects path keys and unrelated operations", async () => {
  for (const [op, authority] of [
    ["StartSearchV1", { repository: "search-all", id: "forged", body: {} }],
    ["GetSearchStatusV1", { repository: "search-all", id: "../other" }],
    ["PostDeviceDetailsV2", { document: "identity_list", variables: {} }],
  ] as const) {
    reset();
    await assert.rejects(
      async () =>
        requestException(
          op,
          "https://api.crowdstrike.com",
          "token",
          authority,
          false,
          new AbortController().signal,
        ),
      CliError,
    );
    assert.equal(wire.length, 0);
  }
});
for (const type of [undefined, "user", "endpoint"])
  test(`S09 document variables ${type ?? "all"}`, async () => {
    reset();
    recordedResponse(graph, 200, fixture("identity/entities-page.json"));
    const name = 'synthetic" } mutation { delete } #';
    const args = [
      "identity",
      "list",
      "--name",
      name,
      "--email",
      "synthetic@example.invalid",
      "--domain",
      "synthetic.invalid",
    ];
    if (type) args.push("--type", type);
    const result = await run(args, { FALCON_AXI_READ_ONLY: "1" });
    assert.equal(result.code, 0, result.stdout);
    // The expected request is written out independently of the production
    // builder: the committed document text, and literal variables.
    const observed = JSON.parse(scoped()[0]!.body) as {
      query: string;
      variables: unknown;
    };
    assert.equal(
      observed.query,
      documents[
        type === "user"
          ? "identity_list_users"
          : type === "endpoint"
            ? "identity_list_endpoints"
            : "identity_list"
      ].text,
    );
    assert.deepEqual(observed.variables, {
      first: 20,
      name,
      email: "synthetic@example.invalid",
      domains: ["synthetic.invalid"],
    });
    const types: string[] = [];
    visit(parseGraphql(observed.query), {
      Argument(node) {
        if (node.name.value === "types" && node.value.kind === Kind.LIST)
          types.push(
            ...node.value.values.map((item) =>
              item.kind === Kind.ENUM ? item.value : "",
            ),
          );
      },
    });
    assert.deepEqual(
      types,
      type === "user" ? ["USER"] : type === "endpoint" ? ["ENDPOINT"] : [],
    );
  });
test("S09 shell continuation preserves exact filters and context", async () => {
  reset();
  recordedResponse(graph, 200, {
    data: {
      entities: {
        nodes: [{ entityId: requestId }],
        pageInfo: { hasNextPage: true, endCursor: "synthetic-after" },
      },
    },
  });
  const pattern = "synthetic $value 'quoted' `literal`";
  const result = await run([
    "identity",
    "list",
    "--name",
    pattern,
    "--limit",
    "1",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const output = value(result.stdout),
    help = output.help as string[];
  const command = /`(.*)`/.exec(help.at(-1)!)![1]!;
  recordedResponse(graph, 200, { data: { entities: { nodes: [] } } });
  const next = await run([], {}, false, false, command);
  assert.equal(next.code, 0, next.stdout);
  const body = JSON.parse(scoped().at(-1)!.body) as {
    variables: Record<string, unknown>;
  };
  assert.equal(body.variables.name, pattern);
  assert.equal(body.variables.after, "synthetic-after");
  reset();
  const wrong = await run([
    "identity",
    "list",
    "--name",
    "different",
    "--cursor",
    String(output.continuation_cursor),
  ]);
  assert.equal(value(wrong.stdout).code, "VALIDATION_ERROR");
  assert.equal(scoped().length, 0);
});
test("S09 timeline continuation retains window and categories", async () => {
  reset();
  recordedResponse(graph, 200, {
    data: {
      timeline: {
        nodes: [{ eventType: "AUTH", timestamp: "synthetic" }],
        pageInfo: { hasNextPage: true, endCursor: "after-events" },
      },
    },
  });
  const args = [
    "identity",
    "timeline",
    requestId,
    "--since",
    "24h",
    "--category",
    "threat,audit",
    "--limit",
    "1",
  ];
  const first = await run(args);
  assert.equal(first.code, 0, first.stdout);
  const original = JSON.parse(scoped()[0]!.body) as {
    variables: Record<string, unknown>;
  };
  const cursor = String(value(first.stdout).continuation_cursor);
  reset();
  recordedResponse(graph, 200, fixture("identity/timeline-last-page.json"));
  const last = await run([...args, "--cursor", cursor]);
  assert.equal(last.code, 0, last.stdout);
  const continued = JSON.parse(scoped()[0]!.body) as {
    variables: Record<string, unknown>;
  };
  assert.equal(continued.variables.startTime, original.variables.startTime);
  assert.deepEqual(continued.variables.categories, ["THREAT", "AUDIT"]);
  assert.equal(continued.variables.after, "after-events");
  assert.doesNotMatch(last.stdout, /continuation_cursor/);
  reset();
  const wrong = await run([...args, "--since", "7d", "--cursor", cursor]);
  assert.equal(wrong.code, 2);
  assert.equal(scoped().length, 0);
});
test("S09 association cap expands independently of the incident cap", async () => {
  for (const full of [false, true]) {
    reset();
    recordedResponse(graph, 200, {
      data: {
        entities: {
          nodes: [
            {
              entityId: requestId,
              associations: Array.from({ length: 26 }, (_, index) => ({
                bindingType: "LOCAL_ADMIN",
                accountName: `user-${index}`,
              })),
              openIncidents: {
                nodes: [{ type: "synthetic" }],
                pageInfo: { hasNextPage: true },
              },
            },
          ],
        },
      },
    });
    const result = await run([
      "identity",
      "show",
      requestId,
      ...(full ? ["--full"] : []),
    ]);
    assert.equal(result.code, 0, result.stdout);
    const detail = value(result.stdout).identity as Record<string, unknown>;
    assert.equal((detail.associations as unknown[]).length, full ? 26 : 25);
    assert.equal(detail.open_incidents_partial, true);
  }
});
for (const name of [
  "identity_assessment",
  "identity_list",
  "identity_timeline",
])
  for (const status of [200, 400, 403])
    test(`S09 error response ${name} ${status}`, async () => {
      reset();
      recordedResponse(graph, status, {
        data: { entities: { nodes: [] } },
        errors: [{ message: "invalid query synthetic-s01-secret" }],
      });
      const args =
        name === "identity_assessment"
          ? ["identity", "assessment"]
          : name === "identity_timeline"
            ? ["identity", "timeline", requestId]
            : ["identity", "list"];
      const result = await run(args);
      assert.equal(result.code, 1, result.stdout);
      assert.doesNotMatch(
        result.stdout,
        /FQL_INVALID|0 identities|0 security assessments|synthetic-s01-secret/,
      );
      if (status === 403)
        assert.deepEqual(value(result.stdout).required_scopes, [
          "Identity Protection GraphQL:write",
          ...document(name).readScopes,
        ]);
    });

for (const body of [
  null,
  { yara_rule: "rule x {}" },
  { patterns: [{ type: "wide", value: "x" }], options: { limit: 20 } },
  { patterns: [{ type: "hex", value: "??" }], options: { limit: 20 } },
  { patterns: [{ type: "ascii", value: "x" }], options: { limit: 101 } },
  { patterns: [{ type: "ascii", value: "x" }], options: { limit: true } },
  {
    patterns: [{ type: "ascii", value: "x" }],
    options: { limit: 20, app: "hunt" },
  },
])
  test(`S10 authority refusal ${JSON.stringify(body)}`, async () => {
    reset();
    await assert.rejects(
      async () =>
        requestException(
          "PostMalQueryExactSearchV1",
          "https://api.crowdstrike.com",
          "token",
          { body },
          false,
          new AbortController().signal,
        ),
      { code: "READ_ONLY_VIOLATION" },
    );
    assert.equal(wire.length, 0);
  });
test("S10 canonical body sends literal patterns and bounded results", async () => {
  reset();
  recordedResponse(
    "PostMalQueryFuzzySearchV1",
    200,
    fixture("malquery/fuzzy.json"),
  );
  const result = await run([
    "malquery",
    "search",
    "--string",
    "SYNTHETIC",
    "--hex",
    "4D 5A",
    "--fuzzy",
    "--limit",
    "1",
  ]);
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(JSON.parse(scoped()[0]!.body), {
    patterns: [
      { type: "ascii", value: "SYNTHETIC" },
      { type: "hex", value: "4d5a" },
    ],
    options: { limit: 1 },
  });
  assert.equal(value(result.stdout).partial, true);
});
test("S10 bounded status preserves request identity and unknown total", async () => {
  reset();
  recordedResponse("GetMalQueryRequestV1", 200, {
    meta: { reqid: requestId, status: "done" },
    resources: [{ sha256: "0".repeat(64) }, { sha256: "1".repeat(64) }],
  });
  const result = await run(["malquery", "status", requestId, "--limit", "1"], {
    FALCON_AXI_READ_ONLY: "1",
  });
  assert.equal(result.code, 0, result.stdout);
  assert.equal((value(result.stdout).samples as unknown[]).length, 1);
  assert.equal(value(result.stdout).partial, true);
  assert.match(result.stdout, /total unknown/);
  assert.equal(scoped().length, 1);
  assert.doesNotMatch(scoped()[0]!.url, /limit=/);
});
for (const [name, args, op, body] of [
  [
    "metadata",
    ["malquery", "show", "0".repeat(64)],
    "GetMalQueryMetadataV1",
    { resources: [{ sha256: "1".repeat(64) }] },
  ],
  ["quota", ["malquery", "quota"], "GetMalQueryQuotasV1", { meta: {} }],
  [
    "status",
    ["malquery", "status", requestId],
    "GetMalQueryRequestV1",
    {
      meta: { reqid: "00000000-0000-4000-8000-000000000002", status: "done" },
      resources: [],
    },
  ],
] as const)
  test(`S10 malformed ${name} cannot claim absence`, async () => {
    reset();
    recordedResponse(op, 200, body);
    const result = await run([...args]);
    assert.equal(result.code, 1);
    assert.equal(value(result.stdout).code, "UPSTREAM_ERROR");
  });
test("S10 authority refusal excludes wider operations and query parameters", async () => {
  for (const op of [
    "PostMalQueryHuntV1",
    "GetMalQueryDownloadV1",
    "RTR_ExecuteCommand",
  ]) {
    reset();
    await assert.rejects(
      async () =>
        requestException(
          op,
          "https://api.crowdstrike.com",
          "token",
          { body: {} },
          false,
          new AbortController().signal,
        ),
      CliError,
    );
    assert.equal(wire.length, 0);
  }
  const forged: Record<string, unknown> = {
    body: { patterns: [{ type: "ascii", value: "x" }], options: { limit: 20 } },
    query: { limit: 1000 },
  };
  await assert.rejects(
    async () =>
      requestException(
        "PostMalQueryExactSearchV1",
        "https://api.crowdstrike.com",
        "token",
        forged,
        false,
        new AbortController().signal,
      ),
    CliError,
  );
});

if (managed) {
  test("H18 managed MalQuery capability is independent of RTR and audited as unknown", async () => {
    const args = ["malquery", "search", "--string", "SYNTHETIC"];
    reset();
    const denied = await run(args, { S08_HOST_OPERATIONS: "rtr run" });
    assert.equal(denied.code, 1, denied.stdout);
    assert.equal(value(denied.stdout).code, "READ_ONLY_VIOLATION");
    assert.equal(wire.length, 0);
    reset();
    recordedResponse(
      "PostMalQueryExactSearchV1",
      200,
      fixture("malquery/exact.json"),
    );
    const allowed = await run(args, { S08_HOST_OPERATIONS: "malquery search" });
    assert.equal(allowed.code, 0, allowed.stdout);
    assert.equal(scoped().length, 1);
    const audit = await managedAudit();
    assert.ok(object(audit[0]));
    assert.equal(audit[0].action, "unknown");
    reset();
    const rtrOnly = await run(["search", "start", "--query", "*"], {
      S08_HOST_OPERATIONS: "malquery search",
    });
    assert.equal(value(rtrOnly.stdout).code, "READ_ONLY_VIOLATION");
    assert.equal(wire.length, 0);
  });
}

const bom = "\uFEFF";
const readQuery = "query Read { field }";
for (const [name, query, code] of [
  ["mutation", "mutation { field }", "READ_ONLY_VIOLATION"],
  ["subscription", "subscription { field }", "READ_ONLY_VIOLATION"],
  [
    "mixed mutation",
    "query Read { field }\nmutation Write { field }",
    "VALIDATION_ERROR",
  ],
  [
    "mixed subscription",
    "query Read { field }\nsubscription Watch { field }",
    "VALIDATION_ERROR",
  ],
  ["named mutation", "mutation Write { field }", "READ_ONLY_VIOLATION"],
  ["named subscription", "subscription Watch { field }", "READ_ONLY_VIOLATION"],
  [
    "fragment mutation",
    "mutation Write { ...Fields }\nfragment Fields on Query { field }",
    "READ_ONLY_VIOLATION",
  ],
  [
    "leading fragment mutation",
    "fragment Fields on Query { field }\nmutation Write { ...Fields }",
    "READ_ONLY_VIOLATION",
  ],
  [
    "leading fragment subscription",
    "fragment Fields on Query { field }\nsubscription Watch { ...Fields }",
    "READ_ONLY_VIOLATION",
  ],
  ["commented mutation", "# query\nmutation { field }", "READ_ONLY_VIOLATION"],
  [
    "commented subscription",
    "# query\nsubscription { field }",
    "READ_ONLY_VIOLATION",
  ],
  ["spaced mutation", "mutation\n\n { field }", "READ_ONLY_VIOLATION"],
  ["spaced subscription", "subscription\n\n { field }", "READ_ONLY_VIOLATION"],
  ["bom mutation", `${bom}mutation { field }`, "READ_ONLY_VIOLATION"],
  ["bom subscription", `${bom}subscription { field }`, "READ_ONLY_VIOLATION"],
  ["unicode keyword", "\\u006dutation { field }", "VALIDATION_ERROR"],
  ["unicode subscription", "\\u0073ubscription { field }", "VALIDATION_ERROR"],
  ["unparsed", "query {", "VALIDATION_ERROR"],
  ["fragment only", "fragment Fields on Query { field }", "VALIDATION_ERROR"],
] as const)
  test(`identity graphql refuses ${name} before authentication`, async () => {
    reset();
    recordedResponse(graph, 200, { data: { field: "synthetic" } });
    const result = await run([
      "identity",
      "graphql",
      "--query",
      query,
      "--variables",
      '{"id":"mutation { delete }"}',
    ]);
    assert.equal(
      result.code,
      code === "VALIDATION_ERROR" ? 2 : 1,
      result.stdout,
    );
    assert.equal(value(result.stdout).code, code);
    assert.equal(wire.length, 0);
  });

for (const [name, query] of [
  ["string mutation", 'query { field(note: "mutation { delete }") }'],
  ["commented query", "# mutation { delete }\nquery { field }"],
  ["spaced query", "query\n\n { \n field \n }"],
  ["named query", "query mutation { field }"],
  ["field named mutation", "query { mutation }"],
  ["bom query", `${bom}query { field }`],
  ["unicode string", 'query { field(note: "\\u006dutation") }'],
  ["type definition", "type T { f: String } query { field }"],
] as const)
  test(`identity graphql sends ${name}`, async () => {
    reset();
    recordedResponse(graph, 200, {
      data: { field: "synthetic-field", client_secret: "synthetic-s01-secret" },
    });
    const result = await run(["identity", "graphql", "--query", query], {
      FALCON_AXI_READ_ONLY: "1",
    });
    assert.equal(result.code, 0, result.stdout);
    const body = JSON.parse(scoped()[0]!.body) as {
      query: string;
      variables: unknown;
    };
    assert.equal(body.query, query.replace(/^\uFEFF/, ""));
    assert.deepEqual(body.variables, {});
    assert.match(result.stdout, /synthetic-field/);
    assert.doesNotMatch(result.stdout, /synthetic-s01-secret/);
  });

for (const query of [
  "query A { field } query B { field }",
  "type T { f: String } query A { field } query B { field }",
])
  test("identity graphql refuses two query operations before authentication", async () => {
    reset();
    recordedResponse(graph, 200, { data: { field: "synthetic-field" } });
    const result = await run(["identity", "graphql", "--query", query]);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.match(result.stdout, /exactly one operation/);
    assert.equal(wire.length, 0);
  });

test("identity graphql sends variables separately from the document", async () => {
  reset();
  recordedResponse(graph, 200, { data: { field: "synthetic-field" } });
  const query = "query Read($id: String) { field(id: $id) }";
  const hostile = "mutation { delete }";
  const result = await run([
    "identity",
    "graphql",
    "--query",
    query,
    "--variables",
    JSON.stringify({ id: hostile }),
  ]);
  assert.equal(result.code, 0, result.stdout);
  const body = JSON.parse(scoped()[0]!.body) as {
    query: string;
    variables: { id: string };
  };
  assert.equal(body.query, query);
  assert.equal(body.variables.id, hostile);
  assert.equal(body.query.includes(hostile), false);
});

for (const variables of ["[", "null", "1", '"text"', "{"])
  test(`identity graphql refuses variables ${variables} before authentication`, async () => {
    reset();
    const result = await run([
      "identity",
      "graphql",
      "--query",
      readQuery,
      "--variables",
      variables,
    ]);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

test("identity graphql reads a query file and refuses a missing file", async () => {
  const directory = mkdtempSync(join(tmpdir(), "identity-graphql-"));
  const path = join(directory, "query.graphql");
  try {
    writeFileSync(path, `${bom}query { field }`);
    reset();
    recordedResponse(graph, 200, { data: { field: "synthetic-field" } });
    const result = await run([
      "identity",
      "graphql",
      "--query",
      `@${path}`,
      "--variables",
      '{"id":"synthetic"}',
    ]);
    assert.equal(result.code, 0, result.stdout);
    const body = JSON.parse(scoped()[0]!.body) as {
      query: string;
      variables: unknown;
    };
    assert.equal(body.query, "query { field }");
    assert.deepEqual(body.variables, { id: "synthetic" });
    reset();
    const missing = await run([
      "identity",
      "graphql",
      "--query",
      `@${join(directory, "missing.graphql")}`,
    ]);
    assert.equal(missing.code, 2, missing.stdout);
    assert.equal(wire.length, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("identity graphql sends the query file validated before authentication", async () => {
  const directory = mkdtempSync(join(tmpdir(), "identity-graphql-"));
  const path = join(directory, "query.graphql");
  try {
    writeFileSync(path, readQuery);
    reset();
    tokenResponse(
      200,
      { access_token: "synthetic-s01-token", expires_in: 1800 },
      {},
      () => writeFileSync(path, "query Replacement { field }"),
    );
    recordedResponse(graph, 200, { data: { field: "synthetic" } });
    const result = await run(["identity", "graphql", "--query", `@${path}`]);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(JSON.parse(scoped()[0]!.body).query, readQuery);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("identity graphql reports scope denial and GraphQL errors", async () => {
  reset();
  recordedResponse(graph, 403, {});
  const denied = await run(["identity", "graphql", "--query", readQuery]);
  assert.equal(denied.code, 1, denied.stdout);
  assert.deepEqual(value(denied.stdout).required_scopes, [
    "Identity Protection GraphQL:write",
  ]);
  reset();
  recordedResponse(graph, 200, {
    data: { field: "synthetic-field" },
    errors: [{ message: "synthetic-s01-secret" }],
  });
  const failed = await run(["identity", "graphql", "--query", readQuery]);
  assert.equal(failed.code, 1, failed.stdout);
  assert.equal(value(failed.stdout).code, "UPSTREAM_ERROR");
  assert.doesNotMatch(failed.stdout, /synthetic-s01-secret|synthetic-field/);
});

for (const data of [null, [], false, 1, "text"])
  test(`identity graphql rejects non-object data ${JSON.stringify(data)}`, async () => {
    reset();
    recordedResponse(graph, 200, { data });
    const result = await run(["identity", "graphql", "--query", readQuery]);
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "UPSTREAM_ERROR");
  });

for (const errors of [null, false, 0, "", {}])
  test(`identity graphql rejects non-array errors ${JSON.stringify(errors)}`, async () => {
    reset();
    recordedResponse(graph, 200, { data: { field: "synthetic" }, errors });
    const result = await run(["identity", "graphql", "--query", readQuery]);
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "UPSTREAM_ERROR");
  });

test("identity graphql accepts an empty errors array", async () => {
  reset();
  recordedResponse(graph, 200, { data: { field: "synthetic" }, errors: [] });
  const result = await run(["identity", "graphql", "--query", readQuery]);
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /synthetic/);
});

test("identity graphql sink refuses an invalid serialized body", async () => {
  reset();
  await assert.rejects(
    async () =>
      requestException(
        graph,
        "https://api.crowdstrike.com",
        "synthetic-token",
        { query: readQuery, variables: { toJSON: () => [] } },
        false,
        new AbortController().signal,
      ),
    (error: unknown) =>
      error instanceof CliError &&
      error.code === "READ_ONLY_VIOLATION" &&
      error.message === "request body authority was refused",
  );
  assert.equal(wire.length, 0);
});

for (const query of ["mutation { field }", "subscription { field }", "query {"])
  test(`identity graphql sink refuses serialized ${query}`, async () => {
    reset();
    const stringify = JSON.stringify;
    let request: ReturnType<typeof requestException>;
    try {
      JSON.stringify = ((value: unknown) =>
        stringify(
          object(value) && value.query === readQuery
            ? { ...value, query }
            : value,
        )) as typeof JSON.stringify;
      request = requestException(
        graph,
        "https://api.crowdstrike.com",
        "synthetic-token",
        { query: readQuery, variables: {} },
        false,
        new AbortController().signal,
      );
    } finally {
      JSON.stringify = stringify;
    }
    await assert.rejects(
      request,
      (error: unknown) =>
        error instanceof CliError &&
        error.code === "READ_ONLY_VIOLATION" &&
        error.message === "request body authority was refused",
    );
    assert.equal(wire.length, 0);
  });

const pageQuery = `query Page($first: Int, $after: Cursor, $name: String) {
  entities(first: $first, after: $after, primaryDisplayNamePattern: $name) {
    nodes { entityId }
    pageInfo { hasNextPage endCursor }
  }
}`;
const pageArgs = JSON.stringify({ name: "synthetic", first: 1 });
const pageIds = [
  "00000000-0000-4000-8000-000000000001",
  "00000000-0000-4000-8000-000000000002",
  "00000000-0000-4000-8000-000000000003",
  "00000000-0000-4000-8000-000000000004",
  "00000000-0000-4000-8000-000000000005",
  "00000000-0000-4000-8000-000000000006",
  "00000000-0000-4000-8000-000000000007",
  "00000000-0000-4000-8000-000000000008",
  "00000000-0000-4000-8000-000000000009",
  "00000000-0000-4000-8000-000000000010",
];
const pageData = (
  nodes: unknown[],
  hasNextPage: boolean,
  endCursor: unknown,
  key = "entities",
  rows: "nodes" | "edges" = "nodes",
): { data: Record<string, unknown> } => ({
  data: {
    [key]: {
      [rows]: nodes,
      pageInfo: { hasNextPage, endCursor },
    },
  },
});
const sent = (): { query: string; variables: Record<string, unknown> } =>
  JSON.parse(scoped().at(-1)!.body) as {
    query: string;
    variables: Record<string, unknown>;
  };

test("identity graphql sets first from the page limit", async () => {
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[0] }], false, null),
  );
  const limited = await run(
    [
      "identity",
      "graphql",
      "--query",
      pageQuery,
      "--variables",
      pageArgs,
      "--limit",
      "5",
    ],
    { FALCON_AXI_READ_ONLY: "1" },
  );
  assert.equal(limited.code, 0, limited.stdout);
  assert.equal(scoped().length, 1);
  assert.equal(sent().query, pageQuery);
  assert.deepEqual(sent().variables, { name: "synthetic", first: 5 });
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[0] }], false, null),
  );
  const defaults = await run([
    "identity",
    "graphql",
    "--query",
    pageQuery,
    "--variables",
    pageArgs,
  ]);
  assert.equal(defaults.code, 0, defaults.stdout);
  assert.equal(sent().variables.first, 20);
  assert.equal(sent().query, pageQuery);
});

for (const [name, query, flag] of [
  ["no connection", "query { field }", "--cursor"],
  [
    "nested connection",
    "query Nested($first: Int, $after: Cursor) { viewer { entities(first: $first, after: $after) { pageInfo { hasNextPage endCursor } } } }",
    "--all",
  ],
  [
    "two connections",
    "query Two($first: Int, $after: Cursor) { entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage endCursor } } other: entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage endCursor } } }",
    "--limit",
  ],
  [
    "literal arguments",
    "query { entities(first: 10, after: null) { pageInfo { hasNextPage endCursor } } }",
    "--cursor",
  ],
  [
    "pageInfo without endCursor",
    "query Missing($first: Int, $after: Cursor) { entities(first: $first, after: $after) { pageInfo { hasNextPage } } }",
    "--all",
  ],
] as const)
  test(`identity graphql refuses paging for ${name}`, async () => {
    reset();
    recordedResponse(graph, 200, { data: { field: "synthetic" } });
    const args = ["identity", "graphql", "--query", query, flag];
    if (flag === "--limit") args.push("5");
    if (flag === "--cursor") args.push("synthetic-cursor");
    const result = await run(args);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
    assert.match(result.stdout, /exactly one top-level connection/);
    assert.equal(wire.length, 0);
  });

for (const [name, selection, alias] of [
  [
    "pageInfo",
    "nodes { entityId } info: pageInfo { hasNextPage endCursor }",
    "info",
  ],
  [
    "hasNextPage",
    "nodes { entityId } pageInfo { more: hasNextPage endCursor }",
    "more",
  ],
  [
    "endCursor",
    "nodes { entityId } pageInfo { hasNextPage cursor: endCursor }",
    "cursor",
  ],
  [
    "nodes",
    "items: nodes { entityId } pageInfo { hasNextPage endCursor }",
    "items",
  ],
  [
    "edges",
    "items: edges { node { entityId } } pageInfo { hasNextPage endCursor }",
    "items",
  ],
] as const)
  test(`identity graphql pages aliased ${name}`, async () => {
    reset();
    const query = `query Page($first: Int, $after: Cursor) { entities(first: $first, after: $after) { ${selection} } }`;
    let calls = 0;
    dynamicResponse(graph, (_query, body) => {
      calls += 1;
      assert.equal(
        (body.variables as Record<string, unknown>).after,
        calls === 1 ? undefined : "next",
      );
      const info = {
        [name === "hasNextPage" ? alias : "hasNextPage"]: calls === 1,
        [name === "endCursor" ? alias : "endCursor"]:
          calls === 1 ? "next" : null,
      };
      const rows =
        name === "edges"
          ? [{ node: { entityId: pageIds[calls - 1] } }]
          : [{ entityId: pageIds[calls - 1] }];
      return {
        status: 200,
        body: {
          data: {
            entities: {
              [name === "pageInfo" ? alias : "pageInfo"]: info,
              [name === "nodes" || name === "edges" ? alias : "nodes"]: rows,
            },
          },
        },
      };
    });
    const result = await run([
      "identity",
      "graphql",
      "--query",
      query,
      "--all",
    ]);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(calls, 2);
    const data = value(result.stdout).data as Record<
      string,
      Record<string, unknown[]>
    >;
    assert.equal(
      data.entities![name === "nodes" || name === "edges" ? alias : "nodes"]!
        .length,
      2,
    );
  });

for (const [name, query] of [
  [
    "split pageInfo",
    `query Page($first: Int, $after: Cursor) { entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage } pageInfo { endCursor } } }`,
  ],
] as const)
  test(`identity graphql refuses ${name}`, async () => {
    reset();
    const result = await run([
      "identity",
      "graphql",
      "--query",
      query,
      "--all",
    ]);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(wire.length, 0);
  });

for (const [name, query] of [
  [
    "connection",
    `entities(first: $first, after: $after) @skip(if: true) { nodes { entityId } pageInfo { hasNextPage endCursor } }`,
  ],
  [
    "pageInfo",
    `entities(first: $first, after: $after) { nodes { entityId } pageInfo @skip(if: true) { hasNextPage endCursor } }`,
  ],
  [
    "hasNextPage",
    `entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage @skip(if: true) endCursor } }`,
  ],
  [
    "endCursor",
    `entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage endCursor @skip(if: true) } }`,
  ],
  [
    "nodes",
    `entities(first: $first, after: $after) { nodes @skip(if: true) { entityId } pageInfo { hasNextPage endCursor } }`,
  ],
  [
    "edges",
    `entities(first: $first, after: $after) { edges @skip(if: true) { node { entityId } } pageInfo { hasNextPage endCursor } }`,
  ],
  [
    "fragment",
    `... on Query @skip(if: true) { entities(first: $first, after: $after) { nodes { entityId } pageInfo { hasNextPage endCursor } } }`,
  ],
] as const)
  for (const flag of ["--limit", "--cursor", "--all"])
    test(`identity graphql refuses a directive on ${name} with ${flag}`, async () => {
      reset();
      const document = `query Page($first: Int, $after: Cursor) { ${query} }`;
      const args = ["identity", "graphql", "--query", document, flag];
      if (flag === "--limit") args.push("5");
      if (flag === "--cursor") args.push("synthetic-cursor");
      const result = await run(args);
      assert.equal(result.code, 2, result.stdout);
      assert.match(result.stdout, /directive @skip/);
      assert.equal(wire.length, 0);
    });

test("identity graphql pages merged selections and both row representations", async () => {
  reset();
  const query = `query Page($first: Int, $after: Cursor) {
      entities(first: $first, after: $after) {
        nodes { entityId } edges { node { entityId } }
        pageInfo { hasNextPage endCursor }
      }
      ...More
    } fragment More on Query { entities(first: $first, after: $after) { nodes { entityId } } }`;
  let calls = 0;
  dynamicResponse(graph, () => {
    calls += 1;
    return {
      status: 200,
      body: {
        data: {
          entities:
            calls === 1
              ? {
                  nodes: null,
                  edges: [{ node: { entityId: pageIds[0] } }],
                  pageInfo: { hasNextPage: true, endCursor: "next" },
                }
              : {
                  nodes: [{ entityId: pageIds[1] }],
                  edges: null,
                  pageInfo: { hasNextPage: false, endCursor: null },
                },
        },
      },
    };
  });
  const result = await run(["identity", "graphql", "--query", query, "--all"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(scoped().length, 2);
  assert.deepEqual((value(result.stdout).data as any).entities.nodes, [
    { entityId: pageIds[1] },
  ]);
  assert.deepEqual((value(result.stdout).data as any).entities.edges, [
    { node: { entityId: pageIds[0] } },
  ]);
});

test("identity graphql refuses a limit above the identity list ceiling", async () => {
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[0] }], false, null),
  );
  const result = await run([
    "identity",
    "graphql",
    "--query",
    pageQuery,
    "--limit",
    "201",
  ]);
  assert.equal(result.code, 2, result.stdout);
  assert.equal(value(result.stdout).code, "VALIDATION_ERROR");
  assert.equal(wire.length, 0);
});

test("identity graphql continues a Relay page and rejects a cursor for a different document", async () => {
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[0] }], true, "synthetic-after"),
  );
  const args = [
    "identity",
    "graphql",
    "--query",
    pageQuery,
    "--variables",
    pageArgs,
    "--limit",
    "1",
  ];
  const first = await run(args);
  assert.equal(first.code, 0, first.stdout);
  const cursor = String(value(first.stdout).continuation_cursor);
  assert.equal(sent().variables.first, 1);
  assert.equal(sent().variables.after, undefined);
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[1] }], false, null),
  );
  const second = await run([...args, "--cursor", cursor]);
  assert.equal(second.code, 0, second.stdout);
  assert.equal(sent().variables.after, "synthetic-after");
  assert.equal(sent().variables.name, "synthetic");
  assert.equal(sent().query, pageQuery);
  assert.equal(value(second.stdout).continuation_cursor, undefined);
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[1] }], false, null),
  );
  const replay = await run([...args, "--cursor", cursor]);
  assert.equal(replay.code, 0, replay.stdout);
  assert.equal(sent().variables.after, "synthetic-after");
  reset();
  const changed = await run([
    "identity",
    "graphql",
    "--query",
    pageQuery.replace("$name: String", "$name: String, $extra: String"),
    "--variables",
    pageArgs,
    "--limit",
    "1",
    "--cursor",
    cursor,
  ]);
  assert.equal(changed.code, 2, changed.stdout);
  assert.equal(value(changed.stdout).code, "VALIDATION_ERROR");
  assert.equal(scoped().length, 0);
});

test("identity graphql --all spends the row budget and ignores --limit", async () => {
  reset();
  let calls = 0;
  dynamicResponse(graph, (_query, body) => {
    calls += 1;
    const variables = (body.variables ?? {}) as Record<string, unknown>;
    assert.equal(body.query, pageQuery);
    if (calls === 1) {
      assert.equal(variables.first, 10);
      assert.equal(variables.after, undefined);
      return {
        status: 200,
        body: pageData([{ entityId: pageIds[0] }], true, "page-2"),
      };
    }
    assert.equal(calls, 2);
    assert.equal(variables.first, 9);
    assert.equal(variables.after, "page-2");
    return {
      status: 200,
      body: pageData(
        pageIds.slice(1).map((entityId) => ({ entityId })),
        true,
        "page-3",
      ),
    };
  });

  const result = await run(
    [
      "identity",
      "graphql",
      "--query",
      pageQuery,
      "--variables",
      pageArgs,
      "--all",
      "--max-rows",
      "10",
      "--limit",
      "1",
    ],
    { FALCON_AXI_READ_ONLY: "1" },
  );
  assert.equal(result.code, 0, result.stdout);
  assert.equal(calls, 2);
  const data = value(result.stdout).data as {
    entities: { nodes: { entityId: string }[] };
  };
  assert.deepEqual(data.entities.nodes, [
    { entityId: pageIds[0] },
    { entityId: pageIds[1] },
    { entityId: pageIds[2] },
    { entityId: pageIds[3] },
    { entityId: pageIds[4] },
    { entityId: pageIds[5] },
    { entityId: pageIds[6] },
    { entityId: pageIds[7] },
    { entityId: pageIds[8] },
    { entityId: pageIds[9] },
  ]);
  assert.equal(value(result.stdout).partial, true);
  assert.equal(value(result.stdout).stop_reason, "max_rows");
  assert.match(
    result.stdout,
    /Raise --max-rows, or follow continuation_cursor/,
  );
});

test("identity graphql pages a fragment spread and an aliased edge connection", async () => {
  const spread = `fragment Connection on Query {
  entities(first: $first, after: $after) {
    nodes { entityId }
    pageInfo { hasNextPage endCursor }
  }
}
query Page($first: Int, $after: Cursor) { ...Connection }`;
  reset();
  recordedResponse(
    graph,
    200,
    pageData([{ entityId: pageIds[0] }], false, null),
  );
  const fragmented = await run([
    "identity",
    "graphql",
    "--query",
    spread,
    "--limit",
    "2",
  ]);
  assert.equal(fragmented.code, 0, fragmented.stdout);
  assert.equal(sent().query, spread);
  assert.deepEqual(sent().variables, { first: 2 });
  const aliased = `query Page($first: Int, $after: Cursor) {
  items: entities(first: $first, after: $after) {
    edges { node { entityId } }
    pageInfo { endCursor hasNextPage }
  }
}`;
  reset();
  recordedResponse(
    graph,
    200,
    pageData(
      [{ node: { entityId: pageIds[0] } }],
      false,
      null,
      "items",
      "edges",
    ),
  );
  const alias = await run([
    "identity",
    "graphql",
    "--query",
    aliased,
    "--limit",
    "2",
  ]);
  assert.equal(alias.code, 0, alias.stdout);
  assert.equal(sent().query, aliased);
  assert.deepEqual(sent().variables, { first: 2 });
});

test("identity graphql rejects a cursor repeated after another page", async () => {
  reset();
  let calls = 0;
  dynamicResponse(graph, () => ({
    status: 200,
    body: pageData(
      [{ entityId: pageIds[calls++] }],
      true,
      ["a", "b", "a"][calls - 1],
    ),
  }));
  const result = await run([
    "identity",
    "graphql",
    "--query",
    pageQuery,
    "--all",
  ]);
  assert.equal(result.code, 1, result.stdout);
  assert.match(result.stdout, /repeated its cursor/);
  assert.equal(calls, 3);
});

test("identity graphql rejects an empty final page in a walk", async () => {
  reset();
  let calls = 0;
  dynamicResponse(graph, () => ({
    status: 200,
    body:
      calls++ === 0
        ? pageData([{ entityId: pageIds[0] }], true, "next")
        : pageData([], false, null),
  }));
  const result = await run([
    "identity",
    "graphql",
    "--query",
    pageQuery,
    "--all",
  ]);
  assert.equal(result.code, 1, result.stdout);
  assert.match(result.stdout, /without rows/);
});

for (const [name, body, pattern] of [
  ["omitted endCursor", pageData([], true, null), /omitted endCursor/],
  [
    "repeated cursor",
    pageData([{ entityId: pageIds[0] }], true, "same"),
    /repeated its cursor/,
  ],
  ["empty page", pageData([], true, "next"), /without rows/],
] as const)
  test(`identity graphql stops an ${name} walk`, async () => {
    reset();
    recordedResponse(graph, 200, body);
    const result = await run([
      "identity",
      "graphql",
      "--query",
      pageQuery,
      "--variables",
      name === "repeated cursor"
        ? JSON.stringify({ name: "synthetic", after: "same" })
        : pageArgs,
      "--all",
    ]);
    assert.equal(result.code, 1, result.stdout);
    assert.equal(value(result.stdout).code, "UPSTREAM_ERROR");
    assert.match(result.stdout, pattern);
    assert.equal(scoped().length, 1);
  });
