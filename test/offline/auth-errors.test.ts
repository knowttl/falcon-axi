import assert from "node:assert/strict";
import test from "node:test";
import { run } from "../../src/cli.js";
import { CREDENTIAL_ENV, fixture, RecordedTransport, response, serve } from "../support/recorded.js";

const SECRET = CREDENTIAL_ENV.FALCON_CLIENT_SECRET;
const TOKEN_SUCCESS = fixture("oauth2/token-success.json");
const QUERY_PAGE = fixture("alerts/query-page.json");
const HYDRATE_PAGE = fixture("alerts/hydrate-page.json");

test("auth status reports the channel and region without printing any value", async () => {
  const recorded = new RecordedTransport([]);
  const result = await run(["auth", "status"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^credential_resolved: true$/m);
  assert.match(result.stdout, /^credential_channel: environment$/m);
  assert.match(result.stdout, /^tenant: us-1 \(own CID unavailable\)$/m);
  assert.match(result.stdout, /^scopes: read-only client recommended; falcon-axi requests no write scope$/m);
  assert.match(result.stdout, /^rate_limit: 5999 of 6000 requests remaining$/m);
  assert.ok(!result.stdout.includes(SECRET));
  assert.ok(!result.stdout.includes("synthetic-access-token"));
});

test("auth status without a credential reports the setup paths and exits 0", async () => {
  const result = await run(["auth", "status"], new RecordedTransport([]), { FALCON_AXI_CREDENTIALS_FILE: "/nonexistent/credentials" });
  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^credential_resolved: false$/m);
  assert.match(result.stdout, /FALCON_CLIENT_ID/);
});

test("a member CID is selected at token mint and only its masked suffix is printed", async () => {
  const recorded = new RecordedTransport([], [TOKEN_SUCCESS]);
  const result = await run(["auth", "status", "--member-cid", "synthetic-child-cid-a3b4"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  const [mint] = recorded.requests;
  assert.equal(mint?.kind, "oauth");
  assert.equal(mint?.kind === "oauth" ? mint.args.memberCid : undefined, "synthetic-child-cid-a3b4");
  assert.match(result.stdout, /member CID …a3b4/);
  assert.ok(!result.stdout.includes("synthetic-child-cid-a3b4"));
});

test("--no-member-cid clears an inherited environment selection", async () => {
  const recorded = new RecordedTransport([], [TOKEN_SUCCESS]);
  await run(["auth", "status", "--no-member-cid"], recorded, { ...CREDENTIAL_ENV, FALCON_MEMBER_CID: "synthetic-child-cid" });
  const [mint] = recorded.requests;
  assert.equal(mint?.kind === "oauth" ? mint.args.memberCid : "unset", undefined);
});

test("a 403 at token mint with a member CID is TENANT_DENIED", async () => {
  const recorded = new RecordedTransport([], [fixture("oauth2/token-403-member-cid.json")]);
  const result = await run(["auth", "status", "--member-cid", "synthetic-child-cid"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: TENANT_DENIED$/m);
  assert.match(result.stdout, /--no-member-cid/);
});

test("a 401 at token mint is AUTH_FAILED and a 403 without a member CID is too", async () => {
  const unauthorized = await run(["auth", "status"], new RecordedTransport([], [fixture("oauth2/token-401.json")]), { ...CREDENTIAL_ENV });
  assert.equal(unauthorized.exitCode, 1);
  assert.match(unauthorized.stdout, /^code: AUTH_FAILED$/m);

  const forbidden = await run(
    ["auth", "status"],
    new RecordedTransport([], [{ ...fixture("oauth2/token-403-member-cid.json") }]),
    { ...CREDENTIAL_ENV },
  );
  assert.match(forbidden.stdout, /^code: AUTH_FAILED$/m);
  assert.match(forbidden.stdout, /no scopes granted/);
});

test("region autodiscovery re-targets exactly once on X-Cs-Region", async () => {
  const recorded = new RecordedTransport([], [fixture("oauth2/token-region-us-2.json"), TOKEN_SUCCESS]);
  const result = await run(["auth", "status"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 0);
  const mints = recorded.requests.filter(entry => entry.kind === "oauth");
  assert.equal(mints.length, 2);
  assert.match(result.stdout, /^tenant: us-2 \(re-targeted from us-1\) \(own CID unavailable\)$/m);
});

test("an unknown observed region is REGION_MISMATCH and preserves the observed value", async () => {
  const observed = { ...TOKEN_SUCCESS, headers: { "x-cs-region": "us-gov-2" } };
  const result = await run(["auth", "status"], new RecordedTransport([], [observed]), { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: REGION_MISMATCH$/m);
  assert.match(result.stdout, /us-gov-2/);
  assert.match(result.stdout, /--allow-unknown-origin/);
});

test("a 403 on an operation names the read scopes to grant", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/403-scope.json"))]);
  const result = await run(["detection", "list"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: SCOPE_DENIED$/m);
  assert.match(result.stdout, /required_scopes\[1\]: Alerts:read|required_scopes\[1\]: "Alerts:read"/);
  assert.match(result.stdout, /Falcon console/);
});

test("a 400 filter rejection teaches the FQL rules and exits 2", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/400-fql.json"))]);
  const result = await run(["detection", "list", "--filter", "severity_name:High"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /^code: FQL_INVALID$/m);
  assert.match(result.stdout, /\+ for AND/);
});

test("an upstream failure prints the trace id and never the raw Falcon body", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", fixture("errors/500-internal.json"))]);
  const result = await run(["detection", "list", "--limit", "2"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: UPSTREAM_ERROR$/m);
  assert.match(result.stdout, /synthetic-trace-500/);
  assert.ok(!result.stdout.includes("internal server error"));
  assert.ok(!result.stdout.includes("500 "));
  assert.ok(!result.stdout.includes("/alerts/entities"));
});

test("a 429 after retries is RATE_LIMITED", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", fixture("errors/429-rate-limited.json"))]);
  const result = await run(["detection", "list"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 1);
  assert.match(result.stdout, /^code: RATE_LIMITED$/m);
});

test("no credential, token, or CID value reaches stdout on a successful read", async () => {
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)]);
  const result = await run(["detection", "list", "--limit", "2", "--member-cid", "synthetic-child-cid"], recorded, {
    ...CREDENTIAL_ENV,
  });
  assert.equal(result.exitCode, 0);
  for (const secret of [SECRET, CREDENTIAL_ENV.FALCON_CLIENT_ID, "synthetic-access-token", "synthetic-child-cid"]) {
    assert.ok(!result.stdout.includes(secret), `stdout leaked ${secret}`);
  }
});

test("redaction covers every sensitive key that reaches the renderer", async () => {
  const { render } = await import("../../src/render.js");
  const rendered = render({
    access_token: "synthetic-access-token",
    client_id: "synthetic-client-id",
    client_secret: SECRET,
    member_cid: "synthetic-child-cid",
    token: "synthetic-token",
    Authorization: "Bearer synthetic-access-token",
    nested: { client_secret: SECRET },
  });
  for (const secret of ["synthetic-access-token", "synthetic-client-id", SECRET, "synthetic-child-cid", "synthetic-token"]) {
    assert.ok(!rendered.includes(secret), `render leaked ${secret}`);
  }
  assert.equal(rendered.match(/\[redacted\]/g)?.length, 7);
});

test("a rate-limit headroom note appears when the window is nearly spent", async () => {
  const lowHeadroom = { ...TOKEN_SUCCESS, headers: { "x-cs-region": "us-1", "x-ratelimit-limit": "6000", "x-ratelimit-remaining": "100" } };
  const recorded = new RecordedTransport([serve("GetQueriesAlertsV2", QUERY_PAGE), serve("PostEntitiesAlertsV2", HYDRATE_PAGE)], [lowHeadroom]);
  const result = await run(["detection", "list", "--limit", "2"], recorded, { ...CREDENTIAL_ENV });
  assert.match(result.stdout, /^rate_limit: 100 of 6000 requests remaining in this rate limit window$/m);
  assert.equal(response(200, {}).status, 200);
});
