import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { request as requestHttp } from "node:http";
import type { ClientRequest } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import {
  run,
  reset,
  wire,
  dynamicResponse,
  tokenResponse,
  hostedConnection,
  managedAudit,
  nextHostedTerminal,
  nextHostedChild,
} from "./s01.test.js";

afterEach(reset);

interface HostedResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: { code: string };
}
async function post(
  args: string[],
  headers = hostedConnection().headers,
  input?: { stdin: string },
): Promise<{ status: number; result: HostedResult; requestId: string }> {
  const connection = hostedConnection();
  const response = await fetch(`${connection.url}/v1/tools/falcon-axi/run`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ args, ...input }),
  });
  return {
    status: response.status,
    result: (await response.json()) as HostedResult,
    requestId: response.headers.get("x-artium-request-id")!,
  };
}
async function saveCredential(
  value: Record<string, unknown>,
): Promise<Response> {
  const { url, headers } = hostedConnection();
  const current = (await (
    await fetch(`${url}/v1/admin/tools/falcon-axi/credential`, { headers })
  ).json()) as { revision: number };
  const tool = (await (
    await fetch(`${url}/v1/admin/tools/falcon-axi`, { headers })
  ).json()) as { revision: number };
  return fetch(`${url}/v1/admin/tools/falcon-axi/credential`, {
    method: "PATCH",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({
      expectedRevision: current.revision,
      expectedToolRevision: tool.revision,
      value,
    }),
  });
}
async function settled(): Promise<void> {
  assert.deepEqual(
    (await readdir(join(hostedConnection().state!, "calls"))).filter((name) =>
      name.startsWith("artium-call-"),
    ),
    [],
  );
}

test("S13 C24 public credential entry rejects refs and unknown fields and has no missing-secret fallback", async () => {
  await run(["detection", "list"]);
  const identity = { clientId: "synthetic-entry-client", region: "us-1" };
  const saved = await saveCredential({
    ...identity,
    clientSecret: "synthetic-entry-secret",
  });
  assert.equal(saved.status, 200, await saved.text());
  reset();
  const ref = await saveCredential({
    ...identity,
    clientSecret: { env: "SYNTHETIC_SECRET" },
  });
  assert.equal(ref.status, 400, await ref.text());
  const unknown = await saveCredential({
    ...identity,
    clientSecret: "synthetic-entry-secret",
    surprise: true,
  });
  assert.equal(unknown.status, 400, await unknown.text());
  assert.equal(wire.length, 0);
  const retained = await saveCredential(identity);
  assert.equal(retained.status, 200, await retained.text());
  const retainedHealth = await post(["auth", "status"]);
  assert.equal(
    retainedHealth.result.exitCode,
    0,
    JSON.stringify(retainedHealth),
  );
  assert.equal(
    new URLSearchParams(wire[0]!.body).get("client_secret"),
    "synthetic-entry-secret",
  );
  reset();
  const missing = await saveCredential({
    clientId: "synthetic-new-client",
    region: "us-1",
  });
  assert.equal(missing.status, 200, await missing.text());
  const health = await post(["auth", "status"]);
  assert.equal(health.result.exitCode, 1, JSON.stringify(health));
  assert.match(health.result.stdout, /AUTH_REQUIRED/);
  assert.equal(wire.length, 0);
  await settled();
});

test("S13 concurrent users receive private profiles and independent tokens despite conflicting server environment", async (context) => {
  await run(["detection", "list"]);
  reset();
  const connection = hostedConnection();
  assert.ok(connection.otherHeaders);
  let firstSeen!: () => void, releaseFirst!: () => void;
  const firstArrived = new Promise<void>((resolve) => {
    firstSeen = resolve;
  });
  const holdFirst = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const pending: Promise<unknown>[] = [];
  context.after(async () => {
    releaseFirst();
    reset();
    await Promise.allSettled(pending);
  });
  let profiles: string[] = [];
  dynamicResponse("GetQueriesAlertsV2", async (query) => {
    const first = query.get("filter") === "hostname:'first'";
    if (first) {
      firstSeen();
      await holdFirst;
    } else {
      const root = join(connection.state!, "calls");
      const calls = (await readdir(root)).filter((name) =>
        name.startsWith("artium-call-"),
      );
      assert.equal(calls.length, 2);
      profiles = await Promise.all(
        calls.map(async (name) => {
          const path = join(root, name, "config/falcon-axi/config.json");
          assert.equal((await stat(path)).mode & 0o077, 0);
          return readFile(path, "utf8");
        }),
      );
      releaseFirst();
    }
    return {
      status: 200,
      body: {
        resources: [first ? "synthetic-first" : "synthetic-second"],
        meta: { pagination: { total: 1 } },
      },
    };
  });
  dynamicResponse("PostEntitiesAlertsV2", (_query, body) => ({
    status: 200,
    body: {
      resources: (body.composite_ids as string[]).map((id) => ({
        composite_id: id,
        severity_name: "Low",
        tactic: "Discovery",
        device: { hostname: id },
      })),
    },
  }));
  tokenResponse(200, {
    access_token: "synthetic-token-first",
    expires_in: 1800,
  });
  const first = post(["detection", "list", "--filter", "hostname:'first'"]);
  pending.push(first);
  await firstArrived;
  tokenResponse(200, {
    access_token: "synthetic-token-second",
    expires_in: 1800,
  });
  const secondRequest = post(
    ["detection", "list", "--filter", "hostname:'second'"],
    connection.otherHeaders,
  );
  pending.push(secondRequest);
  const second = await secondRequest;
  assert.equal((await first).result.exitCode, 0);
  assert.equal(second.result.exitCode, 0, JSON.stringify(second));
  for (const text of profiles) {
    const profile = JSON.parse(text) as {
      profiles: { artium: { clientSecret: unknown } };
    };
    assert.deepEqual(profile.profiles.artium.clientSecret, {
      env: "ARTIUM_SECRET_0",
    });
    assert.doesNotMatch(text, /synthetic-s01-secret|synthetic-wrong-server/);
  }
  const tokens = wire.filter((item) => item.url === "/oauth2/token");
  assert.equal(tokens.length, 2);
  for (const token of tokens) {
    assert.equal(
      new URLSearchParams(token.body).get("client_id"),
      "synthetic-s01-client",
    );
    assert.equal(
      new URLSearchParams(token.body).get("client_secret"),
      "synthetic-s01-secret",
    );
  }
  for (const name of ["first", "second"])
    assert.equal(
      wire.find(
        (item) =>
          item.url.includes("entities/alerts") &&
          item.body.includes(`synthetic-${name}`),
      )!.authorization,
      `Bearer synthetic-token-${name}`,
    );
  await settled();
});

test("S13 H09 bounded API stdin does not become a Falcon query or credential", async () => {
  await run(["detection", "list"]);
  reset();
  const result = await post(["detection", "list", "--limit", "1"], undefined, {
    stdin: "synthetic-stdin-content",
  });
  assert.equal(result.result.exitCode, 0, JSON.stringify(result));
  assert.match(result.result.stdout, /ldt:synthetic-agent-02:1002/);
  assert.ok(
    wire.every((item) => !item.body.includes("synthetic-stdin-content")),
  );
  await settled();
});

test("S13 H09 named uploads are refused before vendor delivery", async () => {
  await run(["detection", "list"]);
  reset();
  const { url, headers } = hostedConnection();
  const response = await fetch(`${url}/v1/tools/falcon-axi/run`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({
      args: ["detection", "list"],
      files: [
        {
          name: "synthetic.txt",
          contentBase64: Buffer.from("synthetic ignored input").toString(
            "base64",
          ),
        },
      ],
    }),
  });
  assert.equal(response.status, 400);
  assert.equal(
    ((await response.json()) as { error: { code: string } }).error.code,
    "UNSUPPORTED_INPUT",
  );
  assert.equal(wire.length, 0);
  await settled();
});

test(
  "S13 H13 silent vendor request reaches the native 30-second bound and settles",
  { timeout: 45000 },
  async () => {
    await run(["detection", "list"]);
    reset();
    dynamicResponse("GetQueriesAlertsV2", () => new Promise<never>(() => {}));
    const child = nextHostedChild();
    const started = performance.now();
    const result = await post(["detection", "list"]);
    assert.equal(result.result.exitCode, 1, JSON.stringify(result));
    assert.match(result.result.stdout, /WAIT_TIMEOUT/);
    assert.ok(
      performance.now() - started >= 29000 &&
        performance.now() - started < 40000,
    );
    assert.equal(
      wire.filter((item) => item.url.includes("queries/alerts")).length,
      1,
    );
    const [terminal] = await managedAudit(result.requestId);
    assert.equal(terminal?.error_code, "WAIT_TIMEOUT");
    const pid = await child;
    assert.throws(() => process.kill(-pid, 0), { code: "ESRCH" });
    await settled();
  },
);

test(
  "S13 H13 2001 IDs and three 20-second hydration chunks exceed the unchanged 65000 ms host budget",
  { timeout: 90000 },
  async () => {
    await run(["detection", "list"]);
    reset();
    const ids = Array.from(
      { length: 2001 },
      (_unused, index) => `ldt:synthetic-agent-${index}:${index}`,
    );
    dynamicResponse("GetQueriesAlertsV2", async () => {
      await delay(20000);
      return {
        status: 200,
        body: { resources: ids, meta: { pagination: { total: ids.length } } },
      };
    });
    dynamicResponse("PostEntitiesAlertsV2", async (_query, body) => {
      await delay(20000);
      return {
        status: 200,
        body: {
          resources: (body.composite_ids as string[]).map((id) => ({
            composite_id: id,
            severity_name: "Low",
            tactic: "Discovery",
            device: { hostname: id },
          })),
        },
      };
    });
    const child = nextHostedChild();
    const started = performance.now();
    const result = await post([
      "detection",
      "list",
      "--all",
      "--max-rows",
      "2001",
    ]);
    assert.equal(result.result.error?.code, "TIMEOUT", JSON.stringify(result));
    assert.ok(
      performance.now() - started >= 64000 &&
        performance.now() - started < 70000,
    );
    assert.deepEqual(
      wire
        .filter((item) => item.url.includes("entities/alerts"))
        .map(
          (item) =>
            (JSON.parse(item.body) as { composite_ids: string[] }).composite_ids
              .length,
        ),
      [1000, 1000, 1],
    );
    const [terminal] = await managedAudit(result.requestId);
    assert.equal(terminal?.outcome, "TIMEOUT");
    const pid = await child;
    assert.throws(() => process.kill(-pid, 0), { code: "ESRCH" });
    await settled();
  },
);

test(
  "S13 H13 disconnected read settles its process group profile and terminal audit",
  { timeout: 15000 },
  async () => {
    await run(["detection", "list"]);
    reset();
    const { url, headers } = hostedConnection();
    let request!: ClientRequest;
    dynamicResponse("GetQueriesAlertsV2", () => {
      request.destroy(new Error("synthetic disconnect"));
      return new Promise<never>(() => {});
    });
    const child = nextHostedChild();
    const terminal = nextHostedTerminal("any", "CANCELLED");
    await new Promise<void>((resolve, reject) => {
      request = requestHttp(
        `${url}/v1/tools/falcon-axi/run`,
        {
          method: "POST",
          headers: { ...headers, "content-type": "application/json" },
        },
        () => reject(new Error("Expected a disconnected client")),
      );
      request.once("error", (error) =>
        error.message === "synthetic disconnect" ? resolve() : reject(error),
      );
      request.end(JSON.stringify({ args: ["detection", "list"] }));
    });
    await terminal;
    const pid = await child;
    assert.throws(() => process.kill(-pid, 0), { code: "ESRCH" });
    await settled();
  },
);
