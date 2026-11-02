import "./s02-s03.test.js";
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { decode } from "@toon-format/toon";
import {
  run,
  reset,
  prepareScenario,
  recordedResponse,
  dynamicResponse,
  wire,
} from "./s01.test.js";
import type { Scenario } from "./s01.test.js";
import s04 from "../fixtures/migration/S04/contracts.json" with { type: "json" };
import s05 from "../fixtures/migration/S05/contracts.json" with { type: "json" };
import { operation } from "../../src/transport/operations.js";
import { Cursor } from "../../src/cursor.js";
import { createHmac } from "node:crypto";
import { commands } from "../../src/metadata.js";

const document = (value: string): Record<string, unknown> =>
  decode(value) as Record<string, unknown>;
const scenario = async (name: string): Promise<Scenario> =>
  JSON.parse(
    await readFile(resolve("tests/golden/scenarios", `${name}.json`), "utf8"),
  ) as Scenario;
const dataRequests = () =>
  wire.filter((request) => request.url !== "/oauth2/token");

for (const entry of [
  {
    args: ["rtr", "session", "list"],
    query: "RTR_ListAllSessions",
    hydrate: "RTR_ListSessions",
    key: "sessions",
    empty: "0 sessions matching this query",
    next: 1,
  },
  {
    args: ["ioc", "list"],
    query: "indicator_search_v1",
    hydrate: "indicator_get_v1",
    key: "iocs",
    empty: "0 custom IOCs matching this query",
    next: "synthetic-next",
  },
  {
    args: ["iot", "list"],
    query: "query_iot_hostsV2",
    hydrate: "get_iot_hosts",
    key: "iot",
    empty: "0 IoT assets matching this query",
    next: "synthetic-next",
  },
]) {
  test(`review R2 ${entry.key} preserves an array after complete hydration loss`, async () => {
    reset();
    recordedResponse(entry.query, 200, {
      resources: ["synthetic-deleted"],
      meta: { pagination: { total: 2, after: "synthetic-next" } },
    });
    recordedResponse(entry.hydrate, 200, { resources: [] });
    const result = await run([...entry.args, "--limit", "1"]);
    assert.equal(result.code, 0, result.stdout);
    const value = document(result.stdout);
    assert.deepEqual(value[entry.key], []);
    assert.equal(value.count, "0 of 2 total");
    assert.equal(
      (
        JSON.parse(
          Buffer.from(
            String(value.continuation_cursor),
            "base64url",
          ).toString(),
        ) as { position: string | number }
      ).position,
      entry.next,
    );
  });

  test(`review R2 ${entry.key} retains definitive empty-query output`, async () => {
    reset();
    recordedResponse(entry.query, 200, { resources: [] });
    const result = await run(entry.args);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(document(result.stdout)[entry.key], entry.empty);
  });
}

for (const replay of [false, true])
  test(`review R1 empty FileVantage page terminates continuation with replay=${replay}`, async () => {
    reset();
    recordedResponse("highVolumeQueryChanges", 200, {
      resources: ["synthetic-change"],
      meta: { pagination: { after: "synthetic-next" } },
    });
    recordedResponse("getChanges", 200, {
      resources: [{ id: "synthetic-change" }],
    });
    const first = await run(["file-change", "list"]);
    assert.equal(first.code, 0, first.stdout);
    const cursor = String(document(first.stdout).continuation_cursor);
    reset();
    recordedResponse("highVolumeQueryChanges", 200, {
      resources: [],
      meta: { pagination: { after: "synthetic-next" } },
    });
    const result = await run([
      "file-change",
      "list",
      ...(replay ? ["--cursor", cursor] : []),
    ]);
    assert.equal(result.code, 0, result.stdout);
    const value = document(result.stdout);
    assert.equal(value.continuation_cursor, undefined);
    assert.equal(
      value.file_changes,
      "no file changes; this can mean no matching data or a tenant without Falcon FileVantage licensing",
    );
    assert.deepEqual(value.help, undefined);
  });

if (process.env.S01_ACTIVE_PATH === "artium")
  for (const name of [
    ...s04.goldenScenarioIds,
    ...s05.goldenScenarioIds,
  ].filter(
    (name) =>
      !name.startsWith("help-") &&
      !["cve-show-without-id", "unknown-vuln-subcommand"].includes(name),
  ))
    test(`S04/S05 managed retained ${name}`, async () => {
      const entry = await scenario(name);
      await prepareScenario(entry);
      const result = await run(entry.argv);
      assert.equal(result.code, entry.exit_code, result.stdout);
      const expected = document(
        await readFile(resolve("tests/golden", `${name}.txt`), "utf8"),
      );
      const actual = document(result.stdout);
      delete expected.help;
      delete actual.help;
      delete expected.continuation_cursor;
      delete actual.continuation_cursor;
      assert.deepEqual(actual, expected);
    });

for (const name of [
  "account-list-page",
  "asset-list",
  "application-list",
  "login-list",
  "host-group-list",
  "host-group-members",
  "identity-sensor-list",
  "iot-list",
  "vuln-list-page",
  "cve-list-page",
  "cloud-asset-list",
  "iom-list",
  "cloud-risk-list",
  "container-list-page",
  "image-list-page",
  "image-vulnerabilities-page",
  "serverless-list-page",
  "shield-list",
])
  test(`S04/S05 continuation replay ${name}`, async () => {
    const entry = await scenario(name);
    if (name === "shield-list") entry.argv.push("--limit", "1");
    else entry.argv.push("--filter", "name:'lab`x a'");
    if (name === "iot-list")
      entry.responders!.find(
        (responder) => responder.op === "query_iot_hostsV2",
      )!.response = {
        status: 200,
        body: {
          resources: ["synthetic-iot-01"],
          meta: { pagination: { after: "synthetic-iot-next" } },
        },
      };
    await prepareScenario(entry);
    const first = await run(entry.argv);
    assert.equal(first.code, 0, first.stdout);
    const output = document(first.stdout);
    const firstQuery = new URL(
      dataRequests()[0]!.url,
      "https://api.crowdstrike.com",
    ).searchParams;
    assert.equal(typeof output.continuation_cursor, "string");
    const cursor = JSON.parse(
      Buffer.from(String(output.continuation_cursor), "base64url").toString(),
    ) as { operation: string; position: string | number; model: string };
    const hint = (output.help as string[]).find((hint) =>
      hint.includes("--cursor"),
    )!;
    const command = hint.slice(hint.indexOf("`") + 1, hint.lastIndexOf("`"));
    await prepareScenario(entry);
    const second = await run([], {}, false, false, command);
    assert.equal(second.code, 0, second.stdout);
    const request = dataRequests().find((request) =>
      request.url.startsWith(operation(cursor.operation).path + "?"),
    )!;
    const query = new URL(request.url, "https://api.crowdstrike.com")
      .searchParams;
    assert.equal(query.get("filter"), firstQuery.get("filter"));
    assert.equal(
      query.get(cursor.model === "token" ? "after" : "offset"),
      String(cursor.position),
    );
    assert.equal(
      query.get("limit"),
      entry.argv.includes("--limit")
        ? entry.argv[entry.argv.indexOf("--limit") + 1]
        : "20",
    );
    const changed = [
      ...entry.argv,
      "--cursor",
      String(output.continuation_cursor),
      name === "shield-list" ? "--impact" : "--filter",
      name === "shield-list" ? "low" : "id:'changed'",
    ];
    reset();
    const refused = await run(changed);
    assert.equal(refused.code, 2, refused.stdout);
    assert.match(refused.stdout, /cursor does not continue/);
    assert.equal(dataRequests().length, 0);
  });

for (const entry of [
  { args: ["account", "list"], op: "query_accounts" },
  { args: ["asset", "list"], op: "combined_hosts" },
  { args: ["application", "list"], op: "combined_applications" },
  { args: ["login", "list"], op: "query_logins" },
  { args: ["host-group", "list"], op: "queryCombinedHostGroups" },
  { args: ["identity", "sensor", "list"], op: "QuerySensorsByFilter" },
  { args: ["iot", "list"], op: "query_iot_hostsV2" },
  { args: ["sensor-usage", "list"], op: "GetSensorUsageWeekly" },
  {
    args: ["vuln", "list", "--status", "open"],
    op: "combinedQueryVulnerabilities",
  },
  { args: ["cve", "list"], op: "QueryVulnerabilities" },
  { args: ["cloud-asset", "list"], op: "cloud_security_assets_queries" },
  { args: ["iom", "list"], op: "cspm_evaluations_iom_queries" },
  { args: ["cloud-risk", "list"], op: "combined_cloud_risks" },
  { args: ["container", "list"], op: "ReadContainerCombined" },
  { args: ["image", "list"], op: "GetCombinedImages" },
  { args: ["image", "vulnerabilities"], op: "ReadCombinedVulnerabilities" },
  {
    args: ["serverless", "list", "--filter", "severity:'HIGH'"],
    op: "GetCombinedVulnerabilitiesSARIF",
  },
  { args: ["shield", "list"], op: "GetSecurityChecksV3" },
])
  test(`S04/S05 malformed success refuses ${entry.op}`, async () => {
    reset();
    recordedResponse(entry.op, 200, { resources: false });
    const result = await run(entry.args);
    assert.equal(result.code, 1, result.stdout);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
    assert.ok(!result.stdout.includes("continuation_cursor"));
  });

for (const noun of ["account", "vuln"])
  for (const knownTotal of [false, true])
    test(`S04/S05 bounded walk ${noun} known total ${knownTotal}`, async () => {
      reset();
      const op =
        noun === "account" ? "query_accounts" : "combinedQueryVulnerabilities";
      dynamicResponse(op, (query) => {
        const offset =
          noun === "account"
            ? Number(query.get("offset"))
            : query.get("after")
              ? 2
              : 0;
        const size = Number(query.get("limit"));
        const rows = Array.from(
          { length: Math.min(size, 3 - offset) },
          (_, index) => ({
            id: `synthetic-${offset + index}`,
            username: `user-${offset + index}`,
            cve: { id: "CVE-2026-0001", severity: "HIGH" },
            host_info: { hostname: "SYNTHETIC" },
          }),
        );
        return {
          status: 200,
          body: {
            meta: {
              pagination: {
                ...(knownTotal ? { total: 3 } : {}),
                ...(offset === 0 ? { after: "opaque-next" } : {}),
              },
            },
            resources: noun === "account" ? rows.map((row) => row.id) : rows,
          },
        };
      });
      dynamicResponse("get_accounts", (query) => ({
        status: 200,
        body: {
          resources: query
            .getAll("ids")
            .slice()
            .reverse()
            .map((id) => ({ id, username: id })),
        },
      }));
      const args = [
        noun,
        "list",
        ...(noun === "vuln" ? ["--status", "open"] : []),
        "--all",
        "--max-rows",
        "2",
        "--limit",
        "1",
      ];
      const first = await run(args);
      assert.equal(first.code, 0, first.stdout);
      const output = document(first.stdout);
      assert.equal(output.count, `2 of ${knownTotal ? "3" : "unknown"} total`);
      assert.equal(output.partial, true);
      assert.equal(output.stop_reason, "max_rows");
      const query = new URL(
        dataRequests()[0]!.url,
        "https://api.crowdstrike.com",
      ).searchParams;
      assert.equal(query.get("limit"), "2");
      const next = await run([
        ...args,
        "--cursor",
        String(output.continuation_cursor),
      ]);
      assert.equal(next.code, 0, next.stdout);
      const final = document(next.stdout);
      assert.equal(final.count, `1 of ${knownTotal ? "3" : "unknown"} total`);
      assert.equal(final.partial, undefined);
      assert.equal(final.continuation_cursor, undefined);
      assert.match(next.stdout, /synthetic-2/);
    });

for (const [noun, query, entity] of [
  [
    "cloud-asset",
    "cloud_security_assets_queries",
    "cloud_security_assets_entities_get",
  ],
  ["iom", "cspm_evaluations_iom_queries", "cspm_evaluations_iom_entities"],
] as const)
  test(`S04/S05 hydration batches ${noun} at 100 preserving query order`, async () => {
    reset();
    recordedResponse(query, 200, {
      resources: Array.from(
        { length: 101 },
        (_, index) => `synthetic-${index}`,
      ),
      meta: { pagination: { total: 101 } },
    });
    dynamicResponse(entity, (query) => ({
      status: 200,
      body: {
        resources: query
          .getAll("ids")
          .reverse()
          .map((id) => ({ id })),
      },
    }));
    const result = await run([noun, "list", "--limit", "101"]);
    assert.equal(result.code, 0, result.stdout);
    const rows = document(result.stdout)[
      noun === "iom" ? "ioms" : "cloud_assets"
    ] as { id: string }[];
    assert.deepEqual(
      rows.map((row) => row.id),
      Array.from({ length: 101 }, (_, index) => `synthetic-${index}`),
    );
    assert.equal(
      dataRequests().filter((request) =>
        request.url.startsWith(operation(entity).path + "?"),
      ).length,
      2,
    );
  });

for (const noun of ["application", "shield"])
  test(`S04/S05 recursive preview ${noun} redacts before Unicode truncation and replays current page`, async () => {
    reset();
    const op =
      noun === "application" ? "combined_applications" : "GetSecurityChecksV3";
    const row = {
      id: "synthetic-preview",
      nested: {
        description: "😀".repeat(900),
        client_secret: "CANARY-private",
        key: "-----BEGIN PRIVATE KEY-----\nCANARY-key\n-----END PRIVATE KEY-----",
      },
      exact_integer: {
        toJSON: () =>
          (
            JSON as typeof JSON & { rawJSON: (value: string) => unknown }
          ).rawJSON("9007199254740993"),
      },
    };
    // Delivery serializes native bigint to its original JSON number lexeme.
    recordedResponse(
      op,
      200,
      noun === "application" ? { resources: [row] } : [row],
    );
    const args =
      noun === "application"
        ? [noun, "list"]
        : [noun, "show", "synthetic-preview"];
    const result = await run(args);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /9007199254740993/);
    assert.match(result.stdout, /900 chars total/);
    assert.ok(!result.stdout.includes("CANARY-"));
    const hint = (document(result.stdout).help as string[]).find((hint) =>
      hint.includes("--full"),
    )!;
    const full = await run(
      [],
      {},
      false,
      false,
      hint.slice(hint.indexOf("`") + 1, hint.lastIndexOf("`")),
    );
    assert.equal(full.code, 0, full.stdout);
    assert.ok(!full.stdout.includes("truncated"));
    assert.ok(!full.stdout.includes("CANARY-"));
  });

for (const [name, op] of [
  ["account-list-page", "get_accounts"],
  ["asset-show", "get_hosts"],
  ["login-list", "get_logins"],
  ["identity-sensor-list", "GetSensorDetails"],
  ["iot-list", "get_iot_hosts"],
  ["cloud-asset-list", "cloud_security_assets_entities_get"],
  ["iom-list", "cspm_evaluations_iom_entities"],
  ["cve-list-page", "GetVulnerabilities"],
  ["vuln-show", "getVulnerabilities"],
] as const)
  test(`S04/S05 entity scope refusal ${op} fails instead of claiming empty rows`, async () => {
    const entry = await scenario(name);
    entry.responders!.find((responder) => responder.op === op)!.response = {
      status: 403,
      body: {
        resources: false,
        errors: [{ message: "synthetic scope refusal" }],
      },
    };
    await prepareScenario(entry);
    const result = await run(entry.argv);
    assert.equal(result.code, 1, result.stdout);
    const value = document(result.stdout);
    assert.equal(value.code, "SCOPE_DENIED");
    assert.deepEqual(value.required_scopes, operation(op).scopes);
  });

for (const name of [
  "account-list-page",
  "asset-list",
  "application-list",
  "login-list",
  "host-group-members",
  "identity-sensor-list",
  "iot-list",
  "cloud-asset-list",
  "iom-list",
  "cloud-risk-list",
  "cve-list-page",
  "vuln-list-page",
  "container-list-page",
  "image-list-page",
  "image-vulnerabilities-page",
  "serverless-list-page",
  "sensor-usage-list",
])
  test(`S04/S05 rejected filter remedy ${name} names the originating command`, async () => {
    const entry = await scenario(name);
    entry.responders![0]!.response = {
      status: 400,
      body: { errors: [{ message: "synthetic filter rejected" }] },
    };
    await prepareScenario(entry);
    const result = await run(entry.argv);
    assert.equal(result.code, 2, result.stdout);
    assert.equal(document(result.stdout).code, "FQL_INVALID");
    assert.ok(
      result.stdout.includes(
        `falcon-axi ${entry.argv.slice(0, entry.argv[0] === "identity" ? 3 : 2).join(" ")} --help`,
      ),
      result.stdout,
    );
  });

for (const args of [
  ["account", "list", "--filter", " \t\n"],
  ["vuln", "list", "--since", "yesterday"],
  ["vuln", "list", "--filter", "status:'*'"],
  ["application", "list", "--fields", "id,missing"],
  ["shield", "list", "--impact", "severe"],
  ["identity", "sensor", "show"],
  ["identity", "sensor", "list", "--limit", "201"],
  ["iot", "list", "--limit", "101"],
  ["serverless", "list", "--filter", " "],
  ["account", "list", "--max-rows", "3"],
  ["vuln", "list", "--all", "--max-rows", "0"],
  ["cve", "show", "CVE-２０２６-０００１"],
])
  test(`S04/S05 pre-authentication input refusal ${args.join(" ")}`, async () => {
    reset();
    assert.equal((await run(args)).code, 2);
    assert.equal(wire.length, 0);
    const help = await run([...args, "--help"]);
    assert.equal(help.code, 0, help.stdout);
    assert.equal(wire.length, 0);
  });

test("S04/S05 application fields replace the raw row and preserve missing optional fields as null", async () => {
  await prepareScenario(await scenario("application-list"));
  const result = await run([
    "application",
    "list",
    "--fields",
    "name,host,is_normalized,category",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const row = (
    document(result.stdout).applications as Record<string, unknown>[]
  )[0]!;
  assert.deepEqual(Object.keys(row), [
    "name",
    "host",
    "is_normalized",
    "category",
  ]);
  assert.equal(row.name, "Synthetic Browser");
  assert.equal(row.is_normalized, false);
  assert.equal(row.category, null);
  assert.equal(
    (row.host as Record<string, unknown>).hostname,
    "SYNTHETIC-HOST",
  );
});

test("S04/S05 Spotlight fields add only needed facets in requested order", async () => {
  await prepareScenario(await scenario("vuln-list-page"));
  const result = await run([
    "vuln",
    "list",
    "--status",
    "open",
    "--fields",
    "status,base_score,remediation,status",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const row = (
    document(result.stdout).vulnerabilities as Record<string, unknown>[]
  )[0]!;
  assert.deepEqual(Object.keys(row), [
    "id",
    "cve",
    "severity",
    "hostname",
    "status",
    "base_score",
    "remediation",
  ]);
  assert.equal(row.base_score, "9.8");
  assert.deepEqual(
    new URL(
      dataRequests()[0]!.url,
      "https://api.crowdstrike.com",
    ).searchParams.getAll("facet"),
    ["cve", "host_info", "remediation"],
  );
});

for (const name of [
  "container-list-page",
  "image-list-page",
  "image-vulnerabilities-page",
])
  test(`S04/S05 inventory window ${name} shrinks the final request and refuses exhaustion`, async () => {
    const entry = await scenario(name);
    await prepareScenario(entry);
    const first = await run(entry.argv);
    assert.equal(first.code, 0, first.stdout);
    const cursor = String(document(first.stdout).continuation_cursor);
    const decoded = JSON.parse(Buffer.from(cursor, "base64url").toString()) as {
      operation: string;
    };
    const fields =
      name === "container-list-page"
        ? { container_id: "synthetic-last" }
        : name === "image-list-page"
          ? { image_id: "synthetic-last" }
          : { cve_id: "CVE-2026-0001" };
    const sort =
      name === "container-list-page"
        ? "container_name.asc"
        : name === "image-list-page"
          ? "image_id.asc"
          : "cve_id.asc";
    // The shared cursor primitive supplies a valid boundary position for synthetic public replay.
    const context = new Cursor(
      {
        clientId: "synthetic-s01-client",
        clientSecret: "synthetic-s01-secret",
      },
      "https://api.crowdstrike.com",
      decoded.operation,
      undefined,
      "offset",
      sort,
    );
    recordedResponse(decoded.operation, 200, {
      resources: [fields],
      meta: { pagination: { total: 10001 } },
    });
    dynamicResponse(decoded.operation, () => ({
      status: 200,
      body: { resources: [fields], meta: { pagination: { total: 10001 } } },
    }));
    const final = await run([...entry.argv, "--cursor", context.encode(9999)]);
    assert.equal(final.code, 0, final.stdout);
    assert.equal(document(final.stdout).stop_reason, "pagination_limit");
    assert.equal(document(final.stdout).continuation_cursor, undefined);
    assert.equal(
      new URL(
        dataRequests().at(-1)!.url,
        "https://api.crowdstrike.com",
      ).searchParams.get("limit"),
      "1",
    );
    reset();
    const exhausted = await run([
      ...entry.argv,
      "--cursor",
      context.encode(10000),
    ]);
    assert.equal(exhausted.code, 1, exhausted.stdout);
    assert.equal(document(exhausted.stdout).code, "PAGINATION_LIMIT");
    assert.equal(dataRequests().length, 0);
  });

for (const [name, op] of [
  ["vuln-show", "getVulnerabilities"],
  ["cve-show", "GetVulnerabilities"],
] as const)
  test(`S04/S05 detail identity ${name} selects the requested resource and refuses misattribution`, async () => {
    const entry = await scenario(name);
    const requested = entry.argv[2]!;
    const identity = name === "cve-show" ? "cve" : "id";
    reset();
    recordedResponse(op, 200, {
      resources: [{ [identity]: "synthetic-other" }, { [identity]: requested }],
    });
    const found = await run(entry.argv);
    assert.equal(found.code, 0, found.stdout);
    assert.ok(!found.stdout.includes("synthetic-other"));
    reset();
    recordedResponse(op, 200, {
      resources: [{ [identity]: "synthetic-other" }],
    });
    const refused = await run(entry.argv);
    assert.equal(refused.code, 1, refused.stdout);
    assert.equal(document(refused.stdout).code, "UPSTREAM_ERROR");
  });

test("S04/S05 deleted account hydration advances the query cursor with an honest empty page", async () => {
  reset();
  recordedResponse("query_accounts", 200, {
    resources: ["synthetic-deleted"],
    meta: { pagination: { total: 2 } },
  });
  recordedResponse("get_accounts", 404, {});
  const result = await run(["account", "list", "--limit", "1"]);
  assert.equal(result.code, 0, result.stdout);
  const value = document(result.stdout);
  assert.equal(value.count, "0 of 2 total");
  assert.deepEqual(value.accounts, []);
  assert.equal(
    (
      JSON.parse(
        Buffer.from(String(value.continuation_cursor), "base64url").toString(),
      ) as { position: number }
    ).position,
    1,
  );
});

test("S04/S05 host-group member cursor rejects a different group", async () => {
  const entry = await scenario("host-group-members");
  await prepareScenario(entry);
  const result = await run(entry.argv);
  assert.equal(result.code, 0, result.stdout);
  reset();
  const changed = [...entry.argv];
  changed[2] = "synthetic-other-group";
  const refused = await run([
    ...changed,
    "--cursor",
    String(document(result.stdout).continuation_cursor),
  ]);
  assert.equal(refused.code, 2, refused.stdout);
  assert.equal(dataRequests().length, 0);
});

test("S04/S05 sensor usage retains zero metrics and has no paging parameters", async () => {
  reset();
  recordedResponse("GetSensorUsageWeekly", 200, [
    { period: "30", metrics: { linux: 0, windows: 3 } },
  ]);
  const result = await run(["sensor-usage", "list", "--filter", "period:'30'"]);
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(document(result.stdout), {
    count: 1,
    usage: [{ period: "30", metrics: { linux: 0, windows: 3 } }],
  });
  assert.deepEqual(
    [
      ...new URL(dataRequests()[0]!.url, "https://api.crowdstrike.com")
        .searchParams,
    ],
    [["filter", "period:'30'"]],
  );
});

test("S04/S05 account query refuses an array without a resources envelope", async () => {
  reset();
  recordedResponse("query_accounts", 200, []);
  const result = await run(["account", "list"]);
  assert.equal(result.code, 1, result.stdout);
  assert.equal(document(result.stdout).code, "UPSTREAM_ERROR");
});

test("S04/S05 host-group cursor preserves commas inside the filter context", async () => {
  reset();
  recordedResponse("queryCombinedGroupMembers", 200, {
    resources: [{ device_id: "synthetic-device" }],
    meta: { pagination: { total: 2 } },
  });
  const result = await run([
    "host-group",
    "members",
    "synthetic-group",
    "--filter",
    "name:'a,b'",
    "--limit",
    "1",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const payload = JSON.parse(
    Buffer.from(
      String(document(result.stdout).continuation_cursor),
      "base64url",
    ).toString(),
  ) as { fingerprint: string };
  const expected = createHmac("sha256", "synthetic-s01-secret")
    .update(
      JSON.stringify({
        client_id: "synthetic-s01-client",
        member_cid: null,
        model: "offset",
        operation: "queryCombinedGroupMembers",
        origin: "https://api.crowdstrike.com",
        position: 1,
        query: `[["synthetic-group"], "name:'a,b'"]`,
        sort: null,
      }),
    )
    .digest("hex");
  assert.equal(payload.fingerprint, expected);
});

// Expected query contexts are written out as Python's json.dumps emitted them:
// ASCII-only escapes, compact separators except where the origin used the default.
for (const entry of [
  {
    name: "identity list",
    args: ["identity", "list", "--name", "caf\u00e9,\u{1f600}"],
    operation: "api_preempt_proxy_post_graphql",
    responses: [
      {
        data: {
          entities: {
            nodes: [{ entityId: "synthetic-id" }],
            pageInfo: { hasNextPage: true, endCursor: "synthetic-after" },
          },
        },
      },
    ],
    model: "token",
    position: "synthetic-after",
    query: '[null,"caf\\u00e9,\\ud83d\\ude00",null,null]',
  },
  {
    name: "data-policy list",
    args: [
      "data-policy",
      "list",
      "--platform",
      "win",
      "--filter",
      "name:'caf\u00e9,x'",
    ],
    operation: "queries_policy_get_v2",
    responses: [
      { resources: ["synthetic-policy"], meta: { pagination: { total: 2 } } },
      { resources: [{ id: "synthetic-policy" }] },
    ],
    model: "offset",
    position: 1,
    query: '["name:\'caf\\u00e9,x\'","win"]',
  },
  {
    name: "policy list",
    args: [
      "policy",
      "list",
      "--type",
      "prevention",
      "--filter",
      "name:'caf\u00e9,x'",
    ],
    operation: "queryCombinedPreventionPolicies",
    responses: [
      {
        resources: [{ id: "synthetic-policy" }],
        meta: { pagination: { total: 2 } },
      },
    ],
    model: "offset",
    position: 1,
    query: "[\"name:'caf\\u00e9,x'\",null]",
  },
  {
    name: "policy members",
    args: ["policy", "members", "synthetic-policy", "--type", "prevention"],
    operation: "queryCombinedPreventionPolicyMembers",
    responses: [
      {
        resources: [{ device_id: "synthetic-device" }],
        meta: { pagination: { total: 2 } },
      },
    ],
    model: "offset",
    position: 1,
    query: '[null,"synthetic-policy"]',
  },
  {
    name: "ioc hosts",
    args: ["ioc", "hosts", "domain:caf\u00e9,x.example.invalid"],
    operation: "DevicesRanOn",
    responses: [
      {
        resources: ["synthetic-device-01"],
        meta: { pagination: { total: 2 } },
      },
    ],
    model: "offset",
    position: 1,
    query: '["domain", "caf\\u00e9,x.example.invalid", null]',
  },
  {
    name: "ioc processes",
    args: [
      "ioc",
      "processes",
      "domain:example.invalid",
      "--host",
      "synthetic-device-01",
    ],
    operation: "ProcessesRanOn",
    responses: [
      {
        resources: ["pid:synthetic-device-01:1234"],
        meta: { pagination: { total: 2 } },
      },
    ],
    model: "offset",
    position: 1,
    query: '["domain", "example.invalid", "synthetic-device-01"]',
  },
] as const)
  test(`S04/S05 ${entry.name} cursor keeps the Python-compatible query context`, async () => {
    reset();
    for (const [index, body] of entry.responses.entries())
      recordedResponse(
        index === 0 ? entry.operation : "entities_policy_get_v2",
        200,
        body,
      );
    const result = await run([...entry.args, "--limit", "1"]);
    assert.equal(result.code, 0, result.stdout);
    const payload = JSON.parse(
      Buffer.from(
        String(document(result.stdout).continuation_cursor),
        "base64url",
      ).toString(),
    ) as { fingerprint: string };
    const expected = createHmac("sha256", "synthetic-s01-secret")
      .update(
        JSON.stringify({
          client_id: "synthetic-s01-client",
          member_cid: null,
          model: entry.model,
          operation: entry.operation,
          origin: "https://api.crowdstrike.com",
          position: entry.position,
          query: entry.query,
          sort: null,
        }),
      )
      .digest("hex");
    assert.equal(payload.fingerprint, expected);
  });

test("S04/S05 missing sensor identifier points to the shipped sensor inventory", async () => {
  reset();
  const result = await run(["identity", "sensor", "show"]);
  assert.equal(result.code, 2, result.stdout);
  assert.deepEqual(document(result.stdout).help, [
    `Run \`${process.env.S01_ACTIVE_PATH === "artium" ? "artium-axi falcon-axi" : "falcon-axi"} identity sensor list\` to see current sensor identifiers`,
  ]);
  assert.equal(wire.length, 0);
});

const suggestedCommands = (help: unknown): string[][] =>
  (help as string[]).flatMap((line) =>
    [...line.matchAll(/`(?:artium-axi )?falcon-axi ([^`<]*)`/g)].map((match) =>
      match[1]!.trim().split(" "),
    ),
  );

for (const command of commands.filter((command) => command.positional))
  test(`S04/S05 missing identifier for ${command.name} suggests only shipped commands`, async () => {
    reset();
    const result = await run(command.name.split(" "));
    assert.equal(result.code, 2, result.stdout);
    for (const suggested of suggestedCommands(document(result.stdout).help)) {
      const check = await run([...suggested, "--help"]);
      assert.equal(check.code, 0, `${suggested.join(" ")}: ${check.stdout}`);
    }
  });

for (const entry of [
  {
    args: ["firewall", "rule", "show", "synthetic-rule"],
    op: "get_rules",
    expected: "firewall rule list",
  },
  {
    args: ["ioa", "group", "list"],
    op: "query_rule_groups_full",
    expected: "ioa group list",
  },
  {
    args: ["identity", "rule", "show", "synthetic-rule"],
    op: "get_policy_rules",
    expected: "identity rule list",
  },
  {
    args: ["image", "vulnerabilities"],
    op: "ReadCombinedVulnerabilities",
    expected: "image list",
  },
  {
    args: ["exclusion", "show", "synthetic-exclusion", "--type", "ml"],
    op: "exclusions_get_v2",
    expected: "exclusion list --type ml",
  },
  {
    args: ["data-policy", "show", "synthetic-policy"],
    op: "entities_policy_get_v2",
    expected: "data-policy list --help",
  },
  {
    args: ["process", "tree", "synthetic-graph"],
    op: "combined_summary_get",
    expected: "ioc processes",
  },
  {
    args: ["malquery", "status", "00000000-0000-4000-8000-000000000000"],
    op: "GetMalQueryRequestV1",
    expected: "malquery search --help",
  },
])
  test(`S04/S05 ${entry.args.slice(0, 3).join(" ")} 404 suggests a shipped command`, async () => {
    reset();
    recordedResponse(entry.op, 404, {});
    const result = await run(entry.args);
    assert.equal(result.code, 1, result.stdout);
    const output = document(result.stdout);
    assert.equal(output.code, "NOT_FOUND");
    const suggested = suggestedCommands(output.help);
    assert.ok(
      JSON.stringify(output.help).includes(`falcon-axi ${entry.expected}`),
      JSON.stringify(output.help),
    );
    for (const words of suggested) {
      const check = await run([...words, "--help"]);
      assert.equal(check.code, 0, `${words.join(" ")}: ${check.stdout}`);
    }
    assert.ok(!JSON.stringify(output.help).includes("quota"));
  });

test("S04/S05 a continuation that hides a CID filter says how to replay it", async () => {
  reset();
  dynamicResponse("ReadContainerCombined", () => ({
    status: 200,
    body: {
      resources: [{ container_id: "synthetic-container" }],
      meta: { pagination: { total: 2 } },
    },
  }));
  const result = await run([
    "container",
    "list",
    "--filter",
    "cid:'synthetic-child-cid'",
    "--limit",
    "1",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const help = document(result.stdout).help as string[];
  assert.ok(help.some((line) => line.includes("--filter '<original-filter>'")));
  assert.equal(
    help.filter((line) => line.startsWith("Replace <original-filter>")).length,
    1,
  );
  assert.ok(!result.stdout.includes("synthetic-child-cid"));
});
