import assert from "node:assert/strict";
import test from "node:test";
import { MUTATION_ROUTE_PATTERNS, OPERATIONS, operation, registeredScopes, type OperationId } from "../../src/transport/operations.js";
import { CliError } from "../../src/core.js";

/** The mechanical form of Invariant R (docs/design/v1.md §3.3, §14.5). */
const EXPECTED = {
  GetQueriesAlertsV2: { method: "GET", path: "/alerts/queries/alerts/v2", scopes: ["Alerts:read"], docScope: "Alerts: READ" },
  PostEntitiesAlertsV2: { method: "POST", path: "/alerts/entities/alerts/v2", scopes: ["Alerts:read"], docScope: "Alerts: READ" },
  QueryDevicesByFilter: { method: "GET", path: "/devices/queries/devices/v1", scopes: ["Hosts:read"], docScope: "Hosts: READ" },
  PostDeviceDetailsV2: { method: "POST", path: "/devices/entities/devices/v2", scopes: ["Hosts:read"], docScope: "Hosts: READ" },
  combinedQueryVulnerabilities: {
    method: "GET",
    path: "/spotlight/combined/vulnerabilities/v1",
    scopes: ["Vulnerabilities:read"],
    docScope: "Vulnerabilities: READ",
  },
} as const;

test("the registry contains exactly the five registered read operations", () => {
  assert.deepEqual(Object.keys(OPERATIONS).sort(), Object.keys(EXPECTED).sort());
});

test("every descriptor equals its canonical value and carries read evidence", () => {
  for (const [id, expected] of Object.entries(EXPECTED)) {
    const descriptor = OPERATIONS[id as OperationId];
    assert.equal(descriptor.id, id);
    assert.equal(descriptor.method, expected.method);
    assert.equal(descriptor.path, expected.path);
    assert.deepEqual([...descriptor.scopes], [...expected.scopes]);
    assert.equal(descriptor.effect, "read");
    assert.equal(descriptor.evidence.docScope, expected.docScope);
    assert.match(descriptor.evidence.docScope, /:\s*READ$/i);
    assert.ok(descriptor.evidence.docUrl.startsWith("https://"));
    assert.ok(descriptor.evidence.falconMcp.includes("api_scopes.py"));
  }
});

test("no registered path matches a known mutation route", () => {
  for (const descriptor of Object.values(OPERATIONS)) {
    for (const pattern of MUTATION_ROUTE_PATTERNS) assert.equal(pattern.test(descriptor.path), false, `${descriptor.id} matches ${pattern}`);
  }
});

test("every registered scope is a read scope", () => {
  for (const scope of registeredScopes(Object.keys(EXPECTED) as OperationId[])) assert.match(scope, /:read$/);
});

test("the registry and every nested value resist mutation", () => {
  const record = OPERATIONS as unknown as Record<string, unknown>;
  assert.throws(() => {
    "use strict";
    record.GetQueriesAlertsV2 = { id: "GetQueriesAlertsV2" };
  });
  const descriptor = OPERATIONS.GetQueriesAlertsV2 as unknown as Record<string, unknown>;
  assert.throws(() => {
    "use strict";
    descriptor.path = "/entities/devices/action";
  });
  assert.throws(() => {
    "use strict";
    (descriptor.evidence as Record<string, unknown>).docScope = "Hosts: WRITE";
  });
  assert.throws(() => {
    "use strict";
    (OPERATIONS.GetQueriesAlertsV2.scopes as string[]).push("Hosts:write");
  });
  assert.equal(OPERATIONS.GetQueriesAlertsV2.path, "/alerts/queries/alerts/v2");
  assert.equal(OPERATIONS.GetQueriesAlertsV2.evidence.docScope, "Alerts: READ");
  assert.deepEqual([...OPERATIONS.GetQueriesAlertsV2.scopes], ["Alerts:read"]);
});

test("an unregistered operation id fails with READ_ONLY_VIOLATION before anything is sent", () => {
  const attempt = (): unknown => operation("PatchEntitiesAlertsV3" as OperationId);
  assert.throws(attempt, (error: unknown) => error instanceof CliError && error.code === "READ_ONLY_VIOLATION");
  assert.throws(() => operation("toString" as OperationId), (error: unknown) => error instanceof CliError);
});
