import assert from "node:assert/strict";
import { test } from "node:test";
import {
  run,
  reset,
  wire,
  recordedResponse,
  hostedConnection,
  dynamicResponse,
  tokenResponse,
  nextHostedTerminal,
} from "./s01.test.js";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { request as requestHttp } from "node:http";
import type { ClientRequest } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

interface HostedResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
async function execute(
  host: string,
  headers: Record<string, string>,
): Promise<{ status: number; result: HostedResult }> {
  const response = await fetch(
    `${hostedConnection().url}/v1/tools/falcon-axi/run`,
    {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({
        args: [
          "rtr",
          "run",
          host,
          "--command",
          "ps",
          "--execute",
          "--confirm",
          `${host}:ps`,
        ],
      }),
    },
  );
  return {
    status: response.status,
    result: (await response.json()) as HostedResult,
  };
}

test("S11 hosted installed preview remains local", async () => {
  reset();
  const result = await run(["rtr", "run", "a".repeat(32), "--command", "ps"], {
    S11_HOST_RTR: "1",
  });
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.match(result.stdout, /preview:/);
  assert.equal(wire.length, 0);
});

test("S11 hosted authorized execution deletes its session", async () => {
  reset();
  const host = "a".repeat(32);
  recordedResponse(
    "RTR_InitSession",
    201,
    { resources: [{ session_id: "synthetic-session" }] },
    true,
  );
  recordedResponse(
    "RTR_ExecuteCommand",
    201,
    { resources: [{ cloud_request_id: "synthetic-request" }] },
    true,
  );
  recordedResponse(
    "RTR_CheckCommandStatus",
    200,
    {
      resources: [
        { complete: true, stdout: "synthetic output", sequence_id: 0 },
      ],
    },
    true,
  );
  recordedResponse(
    "RTR_CheckCommandStatus",
    200,
    { resources: [{ complete: true, stdout: "" }] },
    true,
  );
  recordedResponse("RTR_DeleteSession", 204, undefined, true);
  const result = await run(
    [
      "rtr",
      "run",
      host,
      "--command",
      "ps",
      "--execute",
      "--confirm",
      `${host}:ps`,
    ],
    { S11_HOST_RTR: "1" },
  );
  assert.equal(result.code, 0, JSON.stringify(result));
  assert.match(result.stdout, /cleanup: deleted/);
  assert.equal(wire.at(-1)!.method, "DELETE");
});

for (const access of ["default-off", "malquery-only"])
  test(`S11 hosted independent capability refuses ${access} before OAuth`, async () => {
    reset();
    const host = "a".repeat(32);
    const result = await run(
      [
        "rtr",
        "run",
        host,
        "--command",
        "ps",
        "--execute",
        "--confirm",
        `${host}:ps`,
      ],
      access === "malquery-only" ? { S11_HOST_RTR: "malquery-only" } : {},
    );
    assert.equal(result.code, 1, JSON.stringify(result));
    assert.match(result.stdout, /READ_ONLY_VIOLATION/);
    assert.equal(wire.length, 0);
  });

test("S11 hosted device lock crosses users and region/tenant/profile aliases before OAuth", async () => {
  reset();
  await run(["rtr", "run", "a".repeat(32), "--command", "ps"], {
    S11_HOST_RTR: "1",
  });
  tokenResponse(
    201,
    { access_token: "synthetic-s01-token" },
    { "x-cs-region": "us-2" },
  );
  const connection = hostedConnection();
  assert.ok(connection.otherHeaders);
  let contender: Awaited<ReturnType<typeof execute>> | undefined;
  let contenderSends = 0;
  dynamicResponse("RTR_InitSession", async (_query, body) => {
    if (body.device_id === "A".repeat(32))
      return {
        status: 201,
        body: { resources: [{ session_id: "synthetic-rival-session" }] },
      };
    const current = await fetch(
      `${connection.url}/v1/admin/tools/falcon-axi/credential`,
      { headers: connection.headers },
    );
    const credential = (await current.json()) as { revision: number };
    const toolReply = await fetch(
      `${connection.url}/v1/admin/tools/falcon-axi`,
      { headers: connection.headers },
    );
    const tool = (await toolReply.json()) as { revision: number };
    const updated = await fetch(
      `${connection.url}/v1/admin/tools/falcon-axi/credential`,
      {
        method: "PUT",
        headers: { ...connection.headers, "content-type": "application/json" },
        body: JSON.stringify({
          expectedRevision: credential.revision,
          expectedToolRevision: tool.revision,
          value: {
            clientId: "synthetic-other-client",
            clientSecret: "synthetic-other-secret",
            region: "us-2",
            memberCid: "synthetic-other-member",
            rtr: { enabled: true, commands: ["ps"] },
            writes: { allowWrites: true, operations: ["rtr run"] },
          },
        }),
      },
    );
    assert.equal(updated.status, 200, await updated.text());
    const before = wire.length;
    contender = await execute("A".repeat(32), connection.otherHeaders!);
    contenderSends = wire.length - before;
    return {
      status: 201,
      body: { resources: [{ session_id: "synthetic-session" }] },
    };
  });
  dynamicResponse("RTR_ExecuteCommand", () => ({
    status: 201,
    body: { resources: [{ cloud_request_id: "synthetic-request" }] },
  }));
  dynamicResponse("RTR_CheckCommandStatus", () => ({
    status: 200,
    body: { resources: [{ complete: true, stdout: "" }] },
  }));
  dynamicResponse("RTR_DeleteSession", () => ({
    status: 204,
    body: undefined,
  }));
  const holder = await execute("a".repeat(32), connection.headers);
  assert.equal(holder.status, 200, JSON.stringify(holder));
  assert.equal(holder.result.exitCode, 0, JSON.stringify(holder));
  assert.match(holder.result.stdout, /cleanup: deleted/);
  assert.equal(contenderSends, 0, "contender sent OAuth or init");
  assert.notEqual(contender!.status, 200, JSON.stringify(contender));
  const lock = join(
    connection.state!,
    "calls",
    "falcon-rtr-locks",
    `rtr-${"a".repeat(32)}.lock`,
  );
  assert.equal((await lstat(lock)).size, 0);
  assert.deepEqual(
    wire
      .filter((entry) => entry.url === "/oauth2/token")
      .slice(0, 2)
      .map((entry) => entry.host),
    ["api.crowdstrike.com", "api.us-2.crowdstrike.com"],
  );
});

test("S11 hosted different devices remain independent and retained locks release", async () => {
  reset();
  await run(["rtr", "run", "a".repeat(32), "--command", "ps"], {
    S11_HOST_RTR: "1",
  });
  const connection = hostedConnection();
  let independent: Awaited<ReturnType<typeof execute>> | undefined;
  dynamicResponse("RTR_InitSession", async (_query, body) => {
    if (body.device_id === "a".repeat(32))
      independent = await execute("b".repeat(32), connection.otherHeaders!);
    return {
      status: 201,
      body: {
        resources: [{ session_id: `session-${String(body.device_id)}` }],
      },
    };
  });
  dynamicResponse("RTR_ExecuteCommand", (_query, body) => ({
    status: 201,
    body: {
      resources: [{ cloud_request_id: `request-${String(body.session_id)}` }],
    },
  }));
  dynamicResponse("RTR_CheckCommandStatus", () => ({
    status: 200,
    body: { resources: [{ complete: true, stdout: "" }] },
  }));
  dynamicResponse("RTR_DeleteSession", () => ({
    status: 204,
    body: undefined,
  }));
  const first = await execute("a".repeat(32), connection.headers);
  assert.equal(first.result.exitCode, 0, JSON.stringify(first));
  assert.equal(independent!.result.exitCode, 0, JSON.stringify(independent));
  const path = join(
    connection.state!,
    "calls",
    "falcon-rtr-locks",
    `rtr-${"a".repeat(32)}.lock`,
  );
  const inode = (await lstat(path)).ino;
  const second = await execute("a".repeat(32), connection.headers);
  assert.equal(second.result.exitCode, 0, JSON.stringify(second));
  assert.equal((await lstat(path)).ino, inode);
});

test(
  "S11 hosted disconnect retains ten-second cleanup inside twelve-second grace and settles custody",
  { timeout: 18000 },
  async () => {
    reset();
    await run(["rtr", "run", "a".repeat(32), "--command", "ps"], {
      S11_HOST_RTR: "1",
    });
    const connection = hostedConnection();
    let request: ClientRequest;
    const terminal = nextHostedTerminal();
    let disconnected = 0;
    dynamicResponse("RTR_InitSession", () => ({
      status: 201,
      body: { resources: [{ session_id: "synthetic-disconnect-session" }] },
    }));
    dynamicResponse("RTR_ExecuteCommand", () => ({
      status: 201,
      body: { resources: [{ cloud_request_id: "synthetic-request" }] },
    }));
    dynamicResponse("RTR_CheckCommandStatus", () => {
      disconnected = performance.now();
      request.destroy(new Error("synthetic disconnect"));
      return new Promise<never>(() => {});
    });
    dynamicResponse("RTR_DeleteSession", () => new Promise<never>(() => {}));
    const disconnectedClient = new Promise<void>((resolve, reject) => {
      request = requestHttp(
        `${connection.url}/v1/tools/falcon-axi/run`,
        {
          method: "POST",
          headers: {
            ...connection.headers,
            "content-type": "application/json",
          },
        },
        () => reject(new Error("Expected disconnected client")),
      );
      request.once("error", (error) => {
        if (error.message === "synthetic disconnect") resolve();
        else reject(error);
      });
      request.end(
        JSON.stringify({
          args: [
            "rtr",
            "run",
            "a".repeat(32),
            "--command",
            "ps",
            "--execute",
            "--confirm",
            `${"a".repeat(32)}:ps`,
          ],
        }),
      );
    });
    await disconnectedClient;
    const settled = await terminal;
    const elapsed = performance.now() - disconnected;
    assert.ok(
      elapsed >= 9900 && elapsed < 12000,
      JSON.stringify({ elapsed, settled }),
    );
    assert.equal(settled.event, "run-terminal");
    assert.equal(wire.filter((entry) => entry.method === "DELETE").length, 1);
    assert.deepEqual(
      (await readdir(join(connection.state!, "calls"))).filter((name) =>
        name.startsWith("artium-call-"),
      ),
      [],
    );
    const root = join(connection.state!, "writes.log.runs");
    const records = (
      await Promise.all(
        (await readdir(root)).map(async (name) => {
          try {
            return await readFile(join(root, name, "writes.log"), "utf8");
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
            throw error;
          }
        }),
      )
    ).join("\n");
    assert.match(records, /"session":"synthetic-disconnect-session"/);
    assert.match(records, /"phase":"outcome"[^\n]*"cleanup":"failed"/);
    reset();
    dynamicResponse("RTR_InitSession", () => ({
      status: 201,
      body: { resources: [{ session_id: "synthetic-released-session" }] },
    }));
    dynamicResponse("RTR_ExecuteCommand", () => ({
      status: 201,
      body: { resources: [{ cloud_request_id: "synthetic-request" }] },
    }));
    dynamicResponse("RTR_CheckCommandStatus", () => ({
      status: 200,
      body: { resources: [{ complete: true, stdout: "" }] },
    }));
    dynamicResponse("RTR_DeleteSession", () => ({
      status: 204,
      body: undefined,
    }));
    const next = await execute("a".repeat(32), connection.headers);
    assert.equal(next.result.exitCode, 0, JSON.stringify(next));
  },
);

test(
  "S11 hosted mutation detector alias-partition",
  { timeout: 20000 },
  async () => {
    const child = spawn(
      process.execPath,
      [
        "--test",
        "--test-reporter=tap",
        "--test-name-pattern=S11 hosted device lock",
        fileURLToPath(import.meta.url),
      ],
      {
        env: {
          ...process.env,
          NODE_TEST_CONTEXT: undefined,
          NODE_OPTIONS: `--import=${fileURLToPath(new URL("./rtr-seeds.js", import.meta.url))}`,
          S11_MUTATION: "alias-partition",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    assert.equal(code, 1, stdout + stderr);
    assert.match(stdout + stderr, /seed-applied:alias-partition/);
    assert.match(stdout, /contender sent OAuth or init/);
  },
);
