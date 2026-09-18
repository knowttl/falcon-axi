import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../../src/cli.js";
import { CREDENTIAL_ENV, RecordedTransport, response, serve } from "../support/recorded.js";

/**
 * Regression for the pagination advance fix (02aba94).
 * PostEntitiesAlertsV2 can return fewer records than the query step consumed when an alert ages
 * out between the query and hydrate calls. The continuation position must advance by the number of
 * query-step ids consumed, not by the hydrated row count, or detections at positions past the page
 * are silently dropped (total unknown) or re-shown (total known).
 */

test("total unknown: a short hydrate still advances the cursor by the ids consumed", async () => {
  const ids = Array.from({ length: 20 }, (unused, index) => `ldt:synthetic-agent-${index}:${index}`);
  const recorded = new RecordedTransport([
    // 20 ids returned for a limit-20 page, no total in meta.
    serve("GetQueriesAlertsV2", response(200, { resources: ids })),
    // Two ids aged out: only 18 records hydrate.
    serve("PostEntitiesAlertsV2", args =>
      response(200, {
        resources: (args.body as { composite_ids: string[] }).composite_ids.slice(0, 18).map(id => ({
          composite_id: id,
          severity_name: "Medium",
          tactic: "Discovery",
          device: { hostname: "WIN-WS-11" },
        })),
      }),
    ),
  ]);
  const result = await run(["detection", "list", "--limit", "20"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^count: 18 of unknown total$/m);
  // The bug stopped pagination here (18 >= 20 is false), dropping rows at positions 20+.
  assert.match(result.stdout, /^continuation_cursor: /m);
});

test("total known: a short hydrate advances the cursor past the whole page, not just the rows shown", async () => {
  const ids = Array.from({ length: 20 }, (unused, index) => `ldt:synthetic-agent-${index}:${index}`);
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", response(200, { meta: { pagination: { total: 100 } }, resources: ids })),
    serve("PostEntitiesAlertsV2", args =>
      response(200, {
        resources: (args.body as { composite_ids: string[] }).composite_ids.slice(0, 18).map(id => ({
          composite_id: id,
          severity_name: "Low",
          tactic: "Discovery",
          device: { hostname: "WIN-WS-07" },
        })),
      }),
    ),
  ]);
  // First page.
  const first = await run(["detection", "list", "--limit", "20"], recorded, { ...CREDENTIAL_ENV });
  const cursorLine = first.stdout.split("\n").find(line => line.startsWith("continuation_cursor: "));
  assert.ok(cursorLine, "a continuation cursor must be emitted");
  const cursor = cursorLine.slice("continuation_cursor: ".length).trim();

  // Continuing with that cursor must query at offset 20, not 18 (which would re-show rows 18 and 19).
  const next = new RecordedTransport([
    serve("GetQueriesAlertsV2", response(200, { meta: { pagination: { total: 100 } }, resources: [] })),
  ]);
  const second = await run(["detection", "list", "--limit", "20", "--cursor", cursor], next, { ...CREDENTIAL_ENV });
  assert.equal(second.exitCode, 0);
  const [args] = next.operationRequests("GetQueriesAlertsV2");
  assert.equal(args?.query?.offset, 20);
});
