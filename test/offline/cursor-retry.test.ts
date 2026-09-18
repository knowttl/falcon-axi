import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { decodeCursor, encodeCursor, type CursorContext } from "../../src/cursor.js";
import { MAX_ATTEMPTS, retryPlan } from "../../src/transport/retry.js";

const SECRET = "synthetic-client-secret";
const CONTEXT: CursorContext = {
  operation: "GetQueriesAlertsV2",
  clientId: "synthetic-client-id",
  query: "severity_name:'High'",
  origin: "https://api.crowdstrike.com",
  memberCid: "synthetic-member-cid",
};

function rejects(token: string, context: CursorContext, secret = SECRET): void {
  assert.throws(
    () => decodeCursor(token, context, secret),
    (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR" && error.exitCode === 2,
  );
}

test("a cursor round-trips its position", () => {
  const token = encodeCursor(40, CONTEXT, SECRET);
  assert.equal(decodeCursor(token, CONTEXT, SECRET), 40);
});

test("a cursor carries no credential or tenant value", () => {
  const decoded = Buffer.from(encodeCursor(40, CONTEXT, SECRET), "base64url").toString("utf8");
  assert.ok(!decoded.includes(SECRET));
  assert.ok(!decoded.includes(CONTEXT.clientId));
  assert.ok(!decoded.includes("synthetic-member-cid"));
  assert.ok(decoded.includes("GetQueriesAlertsV2"));
});

test("any changed context element rejects the cursor before a request", () => {
  const token = encodeCursor(40, CONTEXT, SECRET);
  rejects(token, { ...CONTEXT, query: "severity_name:'Critical'" });
  rejects(token, { ...CONTEXT, sort: "created_timestamp|desc" });
  rejects(token, { ...CONTEXT, origin: "https://api.eu-1.crowdstrike.com" });
  rejects(token, { ...CONTEXT, memberCid: undefined });
  rejects(token, { ...CONTEXT, clientId: "another-client" });
  rejects(token, { ...CONTEXT, operation: "combinedQueryVulnerabilities" });
  rejects(token, CONTEXT, "rotated-secret");
});

test("a tampered position or malformed token is rejected", () => {
  const payload = JSON.parse(Buffer.from(encodeCursor(40, CONTEXT, SECRET), "base64url").toString("utf8")) as { position: number };
  payload.position = 0;
  rejects(Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"), CONTEXT);
  rejects("not-a-cursor", CONTEXT);
});

test("a 429 waits until a future X-RateLimit-RetryAfter", () => {
  const now = 1_000_000;
  const plan = retryPlan(429, { "x-ratelimit-retryafter": String((now + 5_000) / 1000) }, 1, now, 0);
  assert.deepEqual(plan, { waitMs: 5_000, reason: "retry_after" });
});

test("a past or malformed retry-after falls back to jittered backoff", () => {
  const now = 1_000_000;
  assert.deepEqual(retryPlan(429, { "x-ratelimit-retryafter": "1" }, 1, now, 0), { waitMs: 500, reason: "backoff" });
  assert.deepEqual(retryPlan(429, { "x-ratelimit-retryafter": "soon" }, 2, now, 0), { waitMs: 1_000, reason: "backoff" });
  assert.deepEqual(retryPlan(429, {}, 1, now, 1), { waitMs: 1_000, reason: "backoff" });
});

test("a 503 ignores the retry-after header and a 400 is never retried", () => {
  const now = 1_000_000;
  assert.deepEqual(retryPlan(503, { "x-ratelimit-retryafter": String((now + 60_000) / 1000) }, 1, now, 0), { waitMs: 500, reason: "backoff" });
  assert.equal(retryPlan(400, {}, 1, now, 0), undefined);
  assert.equal(retryPlan(403, {}, 1, now, 0), undefined);
});

test("retries stop after the last attempt", () => {
  assert.equal(retryPlan(429, {}, MAX_ATTEMPTS, 1_000_000, 0), undefined);
});
