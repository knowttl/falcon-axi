import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decode } from "@toon-format/toon";
import { parse as parseGraphql, visit, Kind } from "graphql";
import {
  prepareScenario,
  run,
  reset,
  recordedResponse,
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
    "UPSTREAM_ERROR",
    /stopped or expired job may no longer be queryable/,
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
  assert.equal(value(result.stdout).code, "UPSTREAM_ERROR");
  assert.equal(value(result.stdout).trace_id, requestId);
  assert.match(
    result.stdout,
    /stopped or expired job may no longer be queryable/,
  );
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
