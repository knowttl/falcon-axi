import assert from "node:assert/strict";
import { test } from "node:test";
import { decode } from "@toon-format/toon";
import { writeFile, chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";
import replay from "../migration/replay-cases.json" with { type: "json" };
import { CliError } from "../../src/core.js";
import { loadProfiles } from "../../src/credentials.js";
import {
  run,
  reset,
  recordings,
  dynamicResponse,
  recordedResponse,
  wire,
  prepareScenario,
  directory,
} from "./s01.test.js";

interface Document {
  [key: string]: unknown;
  help?: string[];
  continuation_cursor?: string;
}
const document = (stdout: string): Document => decode(stdout) as Document;
const dataRequests = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");
test("SR-022 quoted unknown command cannot enter the inherited-budget probe", async () => {
  reset();
  const result = await run(["search status synthetic-job", "--wait", "1"]);
  assert.equal(result.code, 2);
  assert.equal(wire.length, 0);
});
if (process.env.S01_ACTIVE_PATH === "artium")
  for (const flags of [
    ["--region", "us-2"],
    ["--config", "/synthetic/config.json"],
    ["--profile", "synthetic"],
    ["--allow-unknown-origin"],
    ["--no-member-cid"],
  ])
    test(`Managed connection override is refused before execution: ${flags[0]}`, async () => {
      reset();
      const result = await run(
        ["detection", "list", ...flags],
        {},
        false,
        false,
        undefined,
        true,
      );
      assert.notEqual(result.code, 0);
      assert.equal(wire.length, 0);
    });
test("SR-125 IPv6 observations preserve all colons and the selected host", async () => {
  reset();
  recordedResponse("ProcessesRanOn", 200, {
    resources: ["pid:00000000000000000000000000000001:1234"],
  });
  const result = await run([
    "ioc",
    "processes",
    "ipv6:2001:db8::1",
    "--host",
    "synthetic-device",
  ]);
  assert.equal(result.code, 0, result.stdout);
  const query = new URL(dataRequests()[0]!.url, "https://api.crowdstrike.com")
    .searchParams;
  assert.equal(query.get("type"), "ipv6");
  assert.equal(query.get("value"), "2001:db8::1");
  assert.equal(query.get("device_id"), "synthetic-device");
});
for (const noun of ["detection", "host"])
  test(`SR-197 all ignores the single-page limit and preserves request cost: ${noun}`, async () => {
    reset();
    dynamicResponse(
      noun === "host" ? "QueryDevicesByFilter" : "GetQueriesAlertsV2",
      (query) => ({
        status: 200,
        body: {
          meta: { pagination: { total: 1001 } },
          resources: Array.from(
            {
              length: Math.min(
                Number(query.get("limit")),
                1001 - Number(query.get("offset")),
              ),
            },
            (_, index) => `synthetic-${Number(query.get("offset")) + index}`,
          ),
        },
      }),
    );
    dynamicResponse(
      noun === "host" ? "PostDeviceDetailsV2" : "PostEntitiesAlertsV2",
      (_query, body) => ({
        status: 200,
        body: {
          resources: (
            body[noun === "host" ? "ids" : "composite_ids"] as string[]
          ).map((id) => ({
            [noun === "host" ? "device_id" : "composite_id"]: id,
          })),
        },
      }),
    );
    const result = await run([noun, "list", "--all", "--limit", "1"]);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /count: 1000 of 1001 total/);
    assert.equal(wire.length, 3);
    assert.equal(
      new URL(
        dataRequests()[0]!.url,
        "https://api.crowdstrike.com",
      ).searchParams.get("limit"),
      "1000",
    );
  });

test("SR-072 network history has a definitive empty result and posts one identity", async () => {
  reset();
  recordedResponse("QueryGetNetworkAddressHistoryV1", 200, []);
  const result = await run(["host", "network", "synthetic-device-01"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(
    document(result.stdout).network_history,
    "0 network address history entries",
  );
  assert.deepEqual(JSON.parse(dataRequests()[0]!.body), {
    ids: ["synthetic-device-01"],
  });
});
for (const entry of [
  {
    operation: "GetQueriesAlertsV2",
    args: ["detection", "list"],
    fixtures: ["alerts/query-page.json", "alerts/hydrate-page.json"],
    command: "detection list",
    example: "severity_name:'High'",
  },
  {
    operation: "PostEntitiesAlertsV2",
    args: ["detection", "list"],
    fixtures: ["alerts/query-page.json", "alerts/hydrate-page.json"],
    command: "detection list",
    example: "severity_name:'High'",
  },
  {
    operation: "QueryDevicesByFilter",
    args: ["host", "list"],
    fixtures: ["hosts/query-page.json", "hosts/details-page.json"],
    command: "host list",
    example: "hostname:'WIN-*'",
  },
  {
    operation: "PostDeviceDetailsV2",
    args: ["host", "list"],
    fixtures: ["hosts/query-page.json", "hosts/details-page.json"],
    command: "host list",
    example: "hostname:'WIN-*'",
  },
  {
    operation: "QueryDeviceLoginHistoryV2",
    args: ["host", "logins", "synthetic-device-01"],
    fixtures: [],
    command: "host list",
    example: "hostname:'WIN-*'",
  },
  {
    operation: "QueryGetNetworkAddressHistoryV1",
    args: ["host", "network", "synthetic-device-01"],
    fixtures: [],
    command: "host list",
    example: "hostname:'WIN-*'",
  },
  {
    operation: "RTR_ListAllSessions",
    args: ["rtr", "session", "list"],
    fixtures: [],
    command: "rtr session list",
    example: "hostname:'SYNTHETIC-*'",
  },
  {
    operation: "indicator_search_v1",
    args: ["ioc", "list"],
    fixtures: [],
    command: "ioc list",
    example: "type:'domain'",
  },
])
  test(`SR-068/SR-085 filter rejection teaches its own domain: ${entry.operation}`, async () => {
    reset();
    await recordings(entry.fixtures);
    dynamicResponse(entry.operation, () => ({
      status: 400,
      body: { errors: [{ message: "invalid FQL filter" }] },
    }));
    const result = await run(entry.args);
    assert.equal(result.code, 2, result.stdout);
    assert.match(result.stdout, /FQL_INVALID/);
    assert.ok(result.stdout.includes(`${entry.command} --help`));
    assert.ok(result.stdout.includes(entry.example));
  });
test("SR-068 missing network history points to host identifiers", async () => {
  reset();
  recordedResponse("QueryGetNetworkAddressHistoryV1", 404, {});
  const result = await run(["host", "network", "synthetic-device-01"]);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /NOT_FOUND/);
  assert.ok(result.stdout.includes("falcon-axi host list"));
});

if (process.env.S01_ACTIVE_PATH !== "artium") {
  for (const selection of [
    {
      args: ["--profile", "A"],
      environment: { FALCON_AXI_PROFILE: "B" },
      profile: "A",
      client: "CANARY-id-A",
    },
    {
      args: [],
      environment: { FALCON_AXI_PROFILE: "B" },
      profile: "B",
      client: "CANARY-id-B",
    },
    {
      args: [],
      environment: { FALCON_AXI_PROFILE: undefined },
      profile: "env",
      client: "synthetic-wrong-server-id",
    },
    {
      args: [],
      environment: {
        FALCON_AXI_PROFILE: undefined,
        FALCON_AXI_CLIENT_ID: undefined,
        FALCON_AXI_CLIENT_SECRET: undefined,
      },
      profile: "A",
      client: "CANARY-id-A",
    },
  ])
    test(`C05 profile selection preserves ${selection.profile} identity: ${selection.client} ${selection.args.join(" ")}`, async () => {
      reset();
      const path = join(directory, "precedence.json");
      await writeFile(
        path,
        JSON.stringify({
          version: 1,
          defaultProfile: "A",
          profiles: {
            A: {
              clientId: "CANARY-id-A",
              clientSecret: { env: "ARTIUM_SECRET_0" },
            },
            B: {
              clientId: "CANARY-id-B",
              clientSecret: { env: "ARTIUM_SECRET_0" },
            },
          },
        }),
        { mode: 0o600 },
      );
      const result = await run(
        ["auth", "status", "--config", path, ...selection.args],
        selection.environment,
      );
      assert.equal(result.code, 0, result.stdout);
      assert.equal(document(result.stdout).profile, selection.profile);
      assert.equal(
        new URLSearchParams(wire.at(-1)!.body).get("client_id"),
        selection.client,
      );
    });
  test("C12 omitted SecretRef resolves the standard secret only", async () => {
    reset();
    const path = join(directory, "omitted-reference.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: { artium: { clientId: "CANARY-omitted-ref" } },
      }),
      { mode: 0o600 },
    );
    const result = await run(["auth", "status", "--config", path]);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(
      new URLSearchParams(wire[0]!.body).get("client_secret"),
      "synthetic-wrong-server-secret",
    );
    assert.equal(
      document(result.stdout).client_secret_source,
      "env:FALCON_AXI_CLIENT_SECRET",
    );
  });
  test("C05 complete environment identity ignores malformed unused config", async () => {
    reset();
    const path = join(directory, "unused-malformed.json");
    await writeFile(path, "{", { mode: 0o600 });
    const result = await run(["auth", "status"], {
      FALCON_AXI_PROFILE: undefined,
      FALCON_AXI_CONFIG: path,
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(document(result.stdout).profile, "env");
  });
  for (const selected of ["environment", "default"])
    test(`C04 profile list uses ${selected} config precedence`, async () => {
      reset();
      const root = join(directory, `config-${selected}`);
      await mkdir(join(root, "falcon-axi"), { recursive: true });
      const alternate = join(root, "alternate.json");
      await writeFile(
        join(root, "falcon-axi/config.json"),
        JSON.stringify({
          version: 1,
          profiles: { default_file: { clientId: "CANARY-local-id" } },
        }),
        { mode: 0o600 },
      );
      await writeFile(
        alternate,
        JSON.stringify({
          version: 1,
          profiles: { environment_file: { clientId: "CANARY-local-id" } },
        }),
        { mode: 0o600 },
      );
      const result = await run(["profile", "list"], {
        FALCON_AXI_CONFIG: selected === "environment" ? alternate : undefined,
        XDG_CONFIG_HOME: root,
      });
      assert.equal(result.code, 0, result.stdout);
      assert.deepEqual(document(result.stdout).profiles, [`${selected}_file`]);
      assert.equal(wire.length, 0);
    });
  test("C19 an explicit deprecated SecretRef consumes its named variable", async () => {
    reset();
    const path = join(directory, "explicit-alias.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          artium: {
            clientId: "CANARY-alias-id",
            clientSecret: { env: "FALCON_CLIENT_SECRET" },
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = await run(["auth", "status", "--config", path], {
      FALCON_CLIENT_SECRET: "CANARY-alias-secret",
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(
      new URLSearchParams(wire[0]!.body).get("client_secret"),
      "CANARY-alias-secret",
    );
    assert.equal(
      document(result.stdout).client_secret_source,
      "env:FALCON_CLIENT_SECRET",
    );
    assert.ok(!(result.stdout + result.stderr).includes("CANARY-alias-secret"));
  });
  test("C06 sole profile resolves without a selector", async () => {
    reset();
    const path = join(directory, "sole.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          sole: {
            clientId: "CANARY-sole",
            clientSecret: { env: "ARTIUM_SECRET_0" },
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = await run(["auth", "status", "--config", path], {
      FALCON_AXI_PROFILE: undefined,
      FALCON_AXI_CLIENT_ID: undefined,
      FALCON_AXI_CLIENT_SECRET: undefined,
    });
    assert.equal(result.code, 0, result.stdout);
    assert.equal(document(result.stdout).profile, "sole");
  });
  test("C14 loose secret is refused while a reference-only config may be 0644", async () => {
    reset();
    const path = join(directory, "reference-only.json");
    const secret = join(directory, "loose-secret");
    await writeFile(secret, "CANARY-permissions", { mode: 0o600 });
    await chmod(secret, 0o640);
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          artium: {
            clientId: "CANARY-permissions-id",
            clientSecret: { file: secret },
          },
        },
      }),
      { mode: 0o600 },
    );
    await chmod(path, 0o644);
    assert.equal((await run(["profile", "list", "--config", path])).code, 0);
    const result = await run(["auth", "status", "--config", path]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /CONFIG_INSECURE/);
    assert.equal(wire.length, 0);
  });
  test("C15 Windows refusal of an unprotected file names the icacls repair", async () => {
    const path = join(directory, "windows-config.json");
    await writeFile(path, JSON.stringify({ version: 1, profiles: {} }), {
      mode: 0o600,
    });
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    const searchPath = process.env.PATH;
    Object.defineProperty(process, "platform", { value: "win32" });
    process.env.PATH = directory;
    try {
      await assert.rejects(loadProfiles(path), (error: CliError) => {
        assert.equal(error.code, "CONFIG_INSECURE");
        assert.match(error.help.join("\n"), /icacls ".+" \/inheritance:r /);
        return true;
      });
    } finally {
      Object.defineProperty(process, "platform", platform);
      process.env.PATH = searchPath;
    }
  });
  test("SR-148 invalid READ_ONLY fails closed before credentials", async () => {
    reset();
    const result = await run(["auth", "status"], {
      FALCON_AXI_READ_ONLY: "yes",
    });
    assert.equal(result.code, 2);
    assert.match(result.stdout, /CONFIG_INVALID/);
    assert.equal(wire.length, 0);
  });
}

for (const command of [
  ["detection", "list"],
  ["host", "list"],
  ["host", "logins", "synthetic-device-01"],
])
  for (const authenticated of [false, true])
    test(`SR-022 invalid input precedes credentials: ${command.join(" ")} ${authenticated}`, async () => {
      reset();
      const result = await run([...command, "--since", "yesterday"], {
        FALCON_AXI_CONFIG: authenticated ? undefined : "/missing",
        FALCON_AXI_CLIENT_ID: authenticated ? "synthetic-id" : undefined,
      });
      assert.equal(result.code, 2);
      assert.match(result.stdout, /--since/);
      assert.equal(wire.length, 0);
    });
for (const command of [
  ["detection", "list"],
  ["host", "list"],
  ["host", "logins", "synthetic-device-01"],
])
  test(`SR-027 help bypasses invalid values without authentication: ${command.join(" ")}`, async () => {
    reset();
    const result = await run([...command, "--since", "yesterday", "--help"]);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /--since/);
    assert.equal(wire.length, 0);
  });
for (const noun of ["detection", "host"])
  for (const fields of ["unexpected", "status,,hostname"])
    test(`SR-079 field validation precedes authentication: ${noun} ${fields}`, async () => {
      reset();
      const result = await run([noun, "list", "--fields", fields]);
      assert.equal(result.code, 2);
      assert.match(result.stdout, /fields/);
      assert.equal(wire.length, 0);
    });
for (const values of [
  { name: "known total", total: 5 },
  { name: "unknown total", total: undefined },
])
  test(`SR-134 hydration loss advances by queried identities: ${values.name}`, async () => {
    reset();
    recordedResponse("GetQueriesAlertsV2", 200, {
      resources: ["D1", "D2"],
      ...(values.total === undefined
        ? {}
        : { meta: { pagination: { total: values.total } } }),
    });
    recordedResponse("PostEntitiesAlertsV2", 200, {
      resources: [{ composite_id: "D2", severity_name: "High" }],
    });
    const first = await run(["detection", "list", "--limit", "2"]);
    assert.equal(first.code, 0, first.stdout);
    assert.match(first.stdout, /count: 1 of/);
    const token = document(first.stdout).continuation_cursor;
    assert.ok(token);
    const next = await run([
      "detection",
      "list",
      "--limit",
      "2",
      "--cursor",
      token,
    ]);
    assert.equal(next.code, 0, next.stdout);
    assert.match(dataRequests().at(-2)!.url, /offset=2/);
  });

for (const noun of ["detection", "host"])
  test(`SR-201 deleted hydration at the wall is a pagination error: ${noun}`, async () => {
    await prepareScenario({
      name: "deleted-wall",
      argv: [],
      exit_code: 1,
      responders:
        noun === "detection"
          ? [
              {
                op: "GetQueriesAlertsV2",
                generate: { kind: "ids", count: 10000, total: 41892 },
              },
              {
                op: "PostEntitiesAlertsV2",
                generate: { kind: "hydrate", take: 0 },
              },
            ]
          : [
              {
                op: "QueryDevicesByFilter",
                generate: { kind: "host-ids", total: 41892 },
              },
              {
                op: "PostDeviceDetailsV2",
                response: { status: 200, body: { resources: [] } },
              },
            ],
    });
    const result = await run([
      noun,
      "list",
      "--all",
      "--max-rows",
      noun === "detection" ? "10000" : "9999",
    ]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /PAGINATION_LIMIT/);
    assert.match(result.stdout, /Narrow the filter/);
    assert.ok(!result.stdout.includes("continuation_cursor"));
  });

for (const changes of [
  ["--filter", "other:'query'"],
  ["--region", "us-2"],
  ["--member-cid", "synthetic-other-member"],
])
  test(`SR-054 cursor refuses changed context: ${changes[0]}`, async () => {
    reset();
    const first = await run(["detection", "list", "--limit", "2"]);
    const token = document(first.stdout).continuation_cursor;
    assert.ok(token);
    wire.length = 0;
    const result = await run([
      "detection",
      "list",
      "--limit",
      "2",
      "--cursor",
      token,
      ...changes,
    ]);
    assert.equal(result.code, 2);
    assert.equal(dataRequests().length, 0);
  });
test("SR-054 tampered cursor cannot move its position", async () => {
  reset();
  const first = await run(["detection", "list", "--limit", "2"]);
  const payload = JSON.parse(
    Buffer.from(
      document(first.stdout).continuation_cursor!,
      "base64url",
    ).toString(),
  ) as { position: number };
  payload.position++;
  wire.length = 0;
  const result = await run([
    "detection",
    "list",
    "--cursor",
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
  ]);
  assert.equal(result.code, 2);
  assert.equal(dataRequests().length, 0);
});

for (const form of ["envelope", "array"])
  test(`SR-081 incomplete FileVantage hydration never returns partial rows: ${form}`, async () => {
    reset();
    await recordings(["filevantage/query.json"]);
    recordedResponse(
      "getChanges",
      200,
      form === "array"
        ? [{ id: "synthetic-change-02" }]
        : { resources: [{ id: "synthetic-change-02" }] },
    );
    const result = await run(["file-change", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
    assert.ok(!result.stdout.includes("file_changes"));
    assert.ok(!result.stdout.includes("continuation_cursor"));
  });
test("SR-081 FileVantage batches at 500 and restores query order", async () => {
  reset();
  const ids = Array.from(
    { length: 1001 },
    (_, index) => `synthetic-change-${index}`,
  );
  recordedResponse("highVolumeQueryChanges", 200, { resources: ids });
  dynamicResponse("getChanges", (query) => ({
    status: 200,
    body: {
      resources: query
        .getAll("ids")
        .reverse()
        .map((id) => ({ id, entity_path: `/synthetic/${id}` })),
    },
  }));
  const result = await run(["file-change", "list", "--limit", "1001"]);
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(document(result.stdout).change_ids, ids);
  assert.deepEqual(
    dataRequests()
      .filter((request) => request.url.startsWith("/filevantage/entities/"))
      .map(
        (request) =>
          new URL(
            request.url,
            "https://api.crowdstrike.com",
          ).searchParams.getAll("ids").length,
      ),
    [500, 500, 1],
  );
});

for (const lookup of [
  {
    name: "ambiguous",
    resources: ["first", "second"],
    total: 2,
    code: "VALIDATION_ERROR",
  },
  {
    name: "incomplete",
    resources: ["first"],
    total: undefined,
    code: "UPSTREAM_ERROR",
  },
  { name: "empty", resources: [], total: 0, code: "NOT_FOUND" },
])
  test(`SR-101 hostname ${lookup.name} refuses history`, async () => {
    reset();
    recordedResponse("QueryDevicesByFilter", 200, {
      resources: lookup.resources,
      ...(lookup.total === undefined
        ? {}
        : { meta: { pagination: { total: lookup.total } } }),
    });
    const result = await run(["host", "logins", "--hostname", "SYNTHETIC-*"]);
    assert.equal(result.code, lookup.code === "VALIDATION_ERROR" ? 2 : 1);
    assert.match(result.stdout, new RegExp(`code: ${lookup.code}`));
    assert.equal(dataRequests().length, 1);
  });

test("SR-101 hostname history failure retains the resolved device", async () => {
  reset();
  recordedResponse("QueryDevicesByFilter", 200, {
    resources: ["synthetic-resolved-device"],
    meta: { pagination: { total: 1 } },
  });
  recordedResponse("QueryDeviceLoginHistoryV2", 403, {
    errors: [{ code: 403, message: "access denied" }],
  });
  const result = await run(["host", "logins", "--hostname", "SYNTHETIC-*"]);
  assert.equal(result.code, 1);
  assert.match(result.stdout, /device_id: synthetic-resolved-device/);
  assert.match(result.stdout, /partial: true/);
  assert.match(result.stdout, /stop_reason: history_failed/);
});

for (const partial of [
  {
    name: "AID login history",
    args: ["host", "logins", "synthetic-device-01"],
    operation: "QueryDeviceLoginHistoryV2",
    body: { resources: [{ device_id: "synthetic-device-01" }] },
    message: "Falcon returned partial host login history",
    requests: 1,
  },
  {
    name: "AID network history",
    args: ["host", "network", "synthetic-device-01"],
    operation: "QueryGetNetworkAddressHistoryV1",
    body: { resources: [{ device_id: "synthetic-device-01", history: [] }] },
    message: "Falcon returned partial host network history",
    requests: 1,
  },
  {
    name: "hostname lookup",
    args: ["host", "network", "--hostname", "SYNTHETIC-*"],
    operation: "QueryDevicesByFilter",
    body: {
      resources: ["synthetic-device-01"],
      meta: { pagination: { total: 1 } },
    },
    message: "Falcon returned a partial hostname lookup; history was not read",
    requests: 1,
  },
])
  test(`SR-106 ${partial.name} with resources and errors discloses partial`, async () => {
    reset();
    recordedResponse(partial.operation, 200, {
      ...partial.body,
      errors: [{ code: 500, message: "synthetic partial failure" }],
    });
    const result = await run(partial.args);
    assert.equal(result.code, 1, result.stdout);
    const output = document(result.stdout);
    assert.equal(output.code, "UPSTREAM_ERROR");
    assert.equal(output.error, partial.message);
    assert.equal(output.partial, true);
    assert.equal(dataRequests().length, partial.requests);
  });

test("SR-141 tree cycle stops without refetching its process", async () => {
  reset();
  dynamicResponse("combined_summary_get", (query) => ({
    status: 200,
    body: {
      resources: [
        {
          id: query.get("ids"),
          properties: { ImageFileName: "synthetic-cycle.exe" },
          edges: { parent_process: [{ id: query.get("ids") }] },
        },
      ],
    },
  }));
  recordedResponse("combined_edges_get", 200, { resources: [] });
  const result = await run(["process", "tree", "synthetic-graph"]);
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /cycle detected; ancestry stopped/);
  assert.equal(
    dataRequests().filter((request) =>
      request.url.startsWith("/threatgraph/combined/processes/summary/"),
    ).length,
    1,
  );
});
test("SR-141 tree stops after five ancestors", async () => {
  reset();
  dynamicResponse("combined_summary_get", (query) => {
    const id = query.get("ids")!;
    return {
      status: 200,
      body: {
        resources: [
          {
            id,
            properties: { ImageFileName: `synthetic-${id}.exe` },
            edges: { parent_process: [{ id: String(Number(id) + 1) }] },
          },
        ],
      },
    };
  });
  recordedResponse("combined_edges_get", 200, { resources: [] });
  const result = await run(["process", "tree", "0"]);
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.stdout, /depth limit reached; at most 5 ancestors shown/);
  assert.equal(
    dataRequests().filter((request) =>
      request.url.startsWith("/threatgraph/combined/processes/summary/"),
    ).length,
    6,
  );
});
test("SR-142 full child continuation preserves complete command lines", async () => {
  reset();
  recordedResponse("combined_summary_get", 200, {
    resources: [
      {
        id: "synthetic-graph",
        properties: { ImageFileName: "synthetic-root.exe" },
        edges: {},
      },
    ],
  });
  dynamicResponse("combined_edges_get", (query) => ({
    status: 200,
    body: {
      resources: [
        {
          id: query.has("offset") ? "synthetic-child-2" : "synthetic-child-1",
          properties: { CommandLine: "x".repeat(900) },
        },
      ],
      ...(query.has("offset")
        ? {}
        : { meta: { pagination: { next_page: "synthetic-next" } } }),
    },
  }));
  const first = await run(["process", "tree", "synthetic-graph", "--full"]);
  assert.equal(first.code, 0, first.stdout);
  const value = document(first.stdout);
  assert.ok(
    value.help!.find((hint) => hint.includes("--cursor"))!.includes("--full"),
  );
  const second = await run([
    "process",
    "tree",
    "synthetic-graph",
    "--full",
    "--cursor",
    value.continuation_cursor!,
  ]);
  assert.equal(second.code, 0, second.stdout);
  assert.deepEqual(
    (document(second.stdout).children as { id: string; cmdline: string }[]).map(
      (row) => [row.id, row.cmdline],
    ),
    [["synthetic-child-2", "x".repeat(900)]],
  );
});
test("SR-062 missing process context is stated explicitly", async () => {
  reset();
  recordedResponse("PostEntitiesAlertsV2", 200, {
    resources: [{ composite_id: "synthetic-alert" }],
  });
  const result = await run(["detection", "process", "synthetic-alert"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(
    document(result.stdout).processes,
    "no process recorded for this detection",
  );
});
test("SR-062 ancestor-only context is retained", async () => {
  reset();
  recordedResponse("PostEntitiesAlertsV2", 200, {
    resources: [
      {
        composite_id: "synthetic-alert",
        parent_details: { filename: "synthetic-parent.exe" },
      },
    ],
  });
  const result = await run(["detection", "process", "synthetic-alert"]);
  assert.equal(result.code, 0, result.stdout);
  assert.ok(
    (
      document(result.stdout).processes as {
        relation: string;
        filename: string;
      }[]
    ).some(
      (row) =>
        row.relation === "parent" && row.filename === "synthetic-parent.exe",
    ),
  );
});
for (const malformed of [
  {
    resources: [{ name: "severity", buckets: [{ label: "High", count: -1 }] }],
  },
  { resources: [{ name: "severity", buckets: false }] },
])
  test(`SR-064 malformed aggregate never claims zero: ${JSON.stringify(malformed)}`, async () => {
    reset();
    recordedResponse("PostAggregatesAlertsV2", 200, malformed);
    const result = await run(["detection", "summary"]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /UPSTREAM_ERROR/);
    assert.ok(!result.stdout.includes("0 detections"));
  });
test("SR-064 omitted aggregate buckets are disclosed", async () => {
  reset();
  recordedResponse("PostAggregatesAlertsV2", 200, {
    resources: [
      {
        name: "severity",
        buckets: [{ label: "High", count: 2 }],
        sum_other_doc_count: 3,
      },
    ],
  });
  const result = await run(["detection", "summary"]);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(document(result.stdout).other_count, 3);
});
for (const entry of [
  {
    args: ["process", "show", "pid:00000000000000000000000000000001:1234"],
    operation: "entities_processes",
    body: [
      {
        process_id: "pid:00000000000000000000000000000001:1234",
        command_line: `${"x".repeat(795)}synthetic-s01-secret`,
      },
    ],
  },
  {
    args: ["rtr", "session", "show", "synthetic-session"],
    operation: "RTR_ListSessions",
    body: {
      resources: [
        {
          id: "synthetic-session",
          command_line: `${"x".repeat(795)}synthetic-s01-secret`,
          client_secret: "CANARY-hidden-value",
        },
      ],
    },
  },
])
  test(`SR-140/SR-173 redaction precedes detail previews: ${entry.operation}`, async () => {
    reset();
    recordedResponse(entry.operation, 200, entry.body);
    const result = await run(entry.args);
    assert.equal(result.code, 0, result.stdout);
    assert.ok(!result.stdout.includes("synthetic-s01"));
    assert.ok(!result.stdout.includes("CANARY-hidden-value"));
    assert.match(result.stdout, /truncated/);
  });

for (const value of ["hostname:'lab`x'", "hostname:'a b'"])
  test(`SR-011/SR-191 continuation survives actual shell replay: ${value}`, async () => {
    reset();
    const first = await run([
      "detection",
      "list",
      "--limit",
      "2",
      "--filter",
      value,
    ]);
    const hint = document(first.stdout).help!.find((hint) =>
      hint.includes("--cursor"),
    )!;
    const command = hint.slice(hint.indexOf("`") + 1, hint.lastIndexOf("`"));
    const next = await run([], {}, false, false, command);
    assert.equal(next.code, 0, next.stdout);
    const requests = dataRequests().filter((request) =>
      request.url.startsWith("/alerts/queries/"),
    );
    assert.equal(
      new URL(
        requests.at(-1)!.url,
        "https://api.crowdstrike.com",
      ).searchParams.get("filter"),
      value,
    );
    assert.equal(
      new URL(
        requests.at(-1)!.url,
        "https://api.crowdstrike.com",
      ).searchParams.get("offset"),
      "2",
    );
  });

if (process.env.S01_ACTIVE_PATH !== "artium")
  for (const [noun, flag, value, empty] of replay.cases as [
    string,
    string,
    string,
    boolean,
  ][])
    for (const context of replay.contexts)
      test(`SR-191 retained shell matrix ${noun} ${flag} ${JSON.stringify(value)} ${empty} ${context.join(" ")}`, async () => {
        reset();
        await recordings(
          noun === "host"
            ? ["hosts/query-page.json", "hosts/details-page.json"]
            : ["alerts/query-page.json", "alerts/hydrate-page.json"],
        );
        // Empty responses precede the retained normal page without changing the production path.
        if (empty)
          dynamicResponse(
            noun === "host" ? "QueryDevicesByFilter" : "GetQueriesAlertsV2",
            () => ({ status: 200, body: { resources: [] } }),
          );
        const first = await run([
          noun,
          "list",
          `--${flag}`,
          value,
          "--since",
          "24h",
          "--limit",
          "2",
          ...context,
        ]);
        assert.equal(first.code, 0, first.stdout);
        const hint = document(first.stdout).help!.find((hint) =>
          hint.includes(empty ? "widen the window" : "--cursor"),
        )!;
        const command = hint.slice(
          hint.indexOf("`") + 1,
          hint.lastIndexOf("`"),
        );
        const second = await run([], {}, false, false, command);
        assert.equal(second.code, 0, second.stdout);
        const queries = dataRequests().filter((request) =>
          request.url.startsWith(
            noun === "host" ? "/devices/queries/" : "/alerts/queries/",
          ),
        );
        assert.equal(queries.length, 2);
        const original = new URL(
          queries[0]!.url,
          "https://api.crowdstrike.com",
        ).searchParams.get("filter")!;
        const latest = new URL(
          queries[1]!.url,
          "https://api.crowdstrike.com",
        ).searchParams.get("filter")!;
        assert.ok(original.includes(value));
        assert.equal(
          latest,
          empty
            ? original.replace(
                "now-24h",
                noun === "host" ? "now-30d" : "now-7d",
              )
            : original,
        );
        assert.equal(queries[1]!.host, queries[0]!.host);
      });
