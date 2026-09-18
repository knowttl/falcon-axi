import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../../src/cli.js";
import { encodeCursor } from "../../src/cursor.js";
import { ALERTS_WALL, HYDRATE_CHUNK } from "../../src/detection.js";
import { CREDENTIAL_ENV, fixture, RecordedTransport, response, serve } from "../support/recorded.js";

const QUERY_PAGE = fixture("alerts/query-page.json");
const HYDRATE_PAGE = fixture("alerts/hydrate-page.json");

test("detection list renders the four-field schema in query-step order", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)]);
  const result = await run(["detection", "list", "--limit", "2"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^count: 2 of 384 total$/m);
  assert.match(result.stdout, /^detections\[2\]\{id,severity,tactic,hostname\}:$/m);
  const rows = result.stdout.split("\n").filter(line => /^ {2}"?ldt:/.test(line));
  assert.equal(rows.length, 2);
  // The query step returned agent-01 first; the hydrate fixture returns agent-02 first.
  assert.ok(rows[0]?.includes("ldt:synthetic-agent-01:1001"));
  assert.ok(rows[0]?.includes("High"));
  assert.ok(rows[1]?.includes("ldt:synthetic-agent-02:1002"));
  assert.match(result.stdout, /help\[\d+\]: "Run `falcon-axi detection show <id>` for the full detection"/);
  assert.match(result.stdout, /^continuation_cursor: /m);
});

test("shorthand flags compose one FQL filter and reach the query step", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)]);
  await run(["detection", "list", "--severity", "high", "--status", "new", "--since", "24h", "--limit", "2"], recorded, { ...CREDENTIAL_ENV });
  const [args] = recorded.operationRequests("GetQueriesAlertsV2");
  assert.equal(args?.query?.filter, "severity_name:'High'+status:'new'+created_timestamp:>'now-24h'");
  assert.equal(args?.query?.limit, 2);
  assert.equal(args?.query?.offset, 0);
});

test("an empty result states the filter that produced it and makes no hydrate request", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", fixture("alerts/query-empty.json"))]);
  const result = await run(["detection", "list", "--severity", "critical", "--since", "24h"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^detections: 0 detections matching critical severity in the last 24h$/m);
  assert.equal(recorded.operationRequests("PostEntitiesAlertsV2").length, 0);
  assert.match(result.stdout, /--since 7d/);
});

test("a response without a total says unknown rather than inventing a count", async () => {
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", fixture("alerts/query-no-total.json")),
    serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-detail.json")),
  ]);
  const result = await run(["detection", "list", "--limit", "1"], recorded, { ...CREDENTIAL_ENV });
  assert.match(result.stdout, /^count: 1 of unknown total$/m);
});

test("the hydrate step is chunked at the documented cap and the query order survives", async () => {
  const ids = Array.from({ length: 2500 }, (unused, index) => `ldt:synthetic-agent-${index}:${index}`);
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", response(200, { meta: { pagination: { total: 2500 } }, resources: ids })),
    serve("PostEntitiesAlertsV2", args => {
      const chunk = (args.body as { composite_ids: string[] }).composite_ids;
      assert.ok(chunk.length <= HYDRATE_CHUNK);
      return response(200, {
        resources: [...chunk].reverse().map(id => ({
          composite_id: id,
          severity_name: "Medium",
          tactic: "Discovery",
          device: { hostname: "WIN-WS-11" },
        })),
      });
    }),
  ]);
  const result = await run(["detection", "list", "--limit", "2500"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.equal(recorded.operationRequests("PostEntitiesAlertsV2").length, 3);
  const rows = result.stdout.split("\n").filter(line => /^ {2}"?ldt:/.test(line));
  assert.equal(rows.length, 2500);
  assert.ok(/^ {2}"?ldt:synthetic-agent-0:0"?,/.test(rows[0] ?? ""));
  assert.ok(/^ {2}"?ldt:synthetic-agent-2499:2499"?,/.test(rows[2499] ?? ""));
});

test("a cursor continues the same query and the wall withholds an unreachable cursor", async () => {
  const position = ALERTS_WALL - 10;
  const cursor = encodeCursor(
    position,
    { operation: "GetQueriesAlertsV2", clientId: CREDENTIAL_ENV.FALCON_CLIENT_ID, origin: "https://api.crowdstrike.com" },
    CREDENTIAL_ENV.FALCON_CLIENT_SECRET,
  );
  const ids = Array.from({ length: 10 }, (unused, index) => `ldt:synthetic-agent-${index}:${index}`);
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", response(200, { meta: { pagination: { total: 41892 } }, resources: ids })),
    serve("PostEntitiesAlertsV2", args =>
      response(200, {
        resources: (args.body as { composite_ids: string[] }).composite_ids.map(id => ({
          composite_id: id,
          severity_name: "Low",
          tactic: "Discovery",
          device: { hostname: "WIN-WS-07" },
        })),
      }),
    ),
  ]);
  const result = await run(["detection", "list", "--limit", "20", "--cursor", cursor], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  const [args] = recorded.operationRequests("GetQueriesAlertsV2");
  assert.equal(args?.query?.offset, position);
  // The requested page lands on the wall rather than overshooting it.
  assert.equal(args?.query?.limit, 10);
  assert.doesNotMatch(result.stdout, /continuation_cursor/);
  assert.match(result.stdout, /PostCombinedAlertsV1/);
});

test("a wall reached with no rows retained is PAGINATION_LIMIT at exit 1", async () => {
  const cursor = encodeCursor(
    ALERTS_WALL,
    { operation: "GetQueriesAlertsV2", clientId: CREDENTIAL_ENV.FALCON_CLIENT_ID, origin: "https://api.crowdstrike.com" },
    CREDENTIAL_ENV.FALCON_CLIENT_SECRET,
  );
  const recorded = new RecordedTransport([]);
  const result = await run(["detection", "list", "--cursor", cursor], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: PAGINATION_LIMIT$/m);
  assert.equal(recorded.operationRequests("GetQueriesAlertsV2").length, 0);
});

test("detection show truncates a long command line and offers --full", async () => {
  const recorded = new RecordedTransport([serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-detail.json"))]);
  const truncated = await run(["detection", "show", "ldt:synthetic-agent-01:1001"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(truncated.exitCode, 0);
  assert.match(truncated.stdout, /truncated, \d+ chars total/);
  assert.match(truncated.stdout, /--full/);
  assert.match(truncated.stdout, /severity: High \(70\)/);

  const full = await run(["detection", "show", "ldt:synthetic-agent-01:1001", "--full"], recorded, { ...CREDENTIAL_ENV });
  assert.doesNotMatch(full.stdout, /truncated/);
  assert.doesNotMatch(full.stdout, /--full/);
});

test("detection show reports a missing detection as NOT_FOUND", async () => {
  const recorded = new RecordedTransport([serve("PostEntitiesAlertsV2", response(200, { resources: [] }))]);
  const result = await run(["detection", "show", "ldt:absent:0"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: NOT_FOUND$/m);
});

test("the home view caps at five rows and names the read-only posture", async () => {
  const ids = Array.from({ length: 5 }, (unused, index) => `ldt:synthetic-agent-${index}:${index}`);
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", response(200, { meta: { pagination: { total: 384 } }, resources: ids })),
    serve("PostEntitiesAlertsV2", args =>
      response(200, {
        resources: (args.body as { composite_ids: string[] }).composite_ids.map(id => ({
          composite_id: id,
          severity_name: "High",
          tactic: "Execution",
          device: { hostname: "WIN-WS-42" },
        })),
      }),
    ),
  ]);
  const result = await run([], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^description: Read CrowdStrike Falcon detections from the shell \(read-only\)$/m);
  assert.match(result.stdout, /^tenant: us-1 \(own CID unavailable\)$/m);
  assert.match(result.stdout, /^count: 5 of 384 total$/m);
  assert.equal(result.stdout.split("\n").filter(line => /^ {2}"?ldt:/.test(line)).length, 5);
});

test("the home view without a credential is the setup instruction", async () => {
  const result = await run([], new RecordedTransport([]), { FALCON_AXI_CREDENTIALS_FILE: "/nonexistent/credentials" });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: AUTH_REQUIRED$/m);
  assert.match(result.stdout, /^bin: /m);
  assert.match(result.stdout, /FALCON_CLIENT_ID and FALCON_CLIENT_SECRET/);
});
