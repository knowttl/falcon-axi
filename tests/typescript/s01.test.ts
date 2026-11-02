import assert from "node:assert/strict";
import { test, before, after } from "node:test";
import { createServer } from "node:https";
import { createServer as tcpServer, connect } from "node:net";
import { createServer as proxyServer } from "node:http";
import { execFileSync, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import {
  mkdtemp,
  readFile,
  writeFile,
  mkdir,
  rm,
  copyFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { render, Raw, truncate, registerMemberCid } from "../../src/render.js";
import { parseResponse } from "../../src/core.js";
import { operation, operationIds } from "../../src/transport/operations.js";
import { requestRead, requestToken } from "../../src/transport/https.js";
import { decode } from "@toon-format/toon";
import { spawnSync } from "node:child_process";
import { VERSION } from "../../src/version.js";

export let directory: string;
export let executable: string;
let ca: string;
export let config: string;
let port: number;
let socketPath: string | undefined;
const sockets = new Set<Duplex>();
export const wire: {
  method: string;
  url: string;
  host: string;
  body: string;
  time: number;
  epoch: number;
  authorization: string;
}[] = [];
let tokenAttempt = 0;
let respondToken: (request: IncomingMessage, response: ServerResponse) => void;
let queryVariant = "normal";
let goldenMode = false;
type Reply = {
  status: number;
  disconnect?: boolean;
  headers?: Record<string, string>;
  body: unknown;
  fault?: "drop" | "truncate" | "stream";
};
export interface Scenario {
  name: string;
  argv: string[];
  exit_code: number;
  env?: string;
  envExtra?: NodeJS.ProcessEnv;
  responders?: {
    op: string;
    fixture?: string;
    response?: Reply;
    generate?: Record<string, unknown>;
  }[];
  oauth?: { fixture?: string; response?: Reply }[];
  cursor?: { position: number };
}
let generated = new Map<string, Record<string, unknown>>();
let customReplies = new Map<
  string,
  (
    query: URLSearchParams,
    body: Record<string, unknown>,
  ) => Reply | Promise<Reply>
>();
export function dynamicResponse(
  operation: string,
  reply: (
    query: URLSearchParams,
    body: Record<string, unknown>,
  ) => Reply | Promise<Reply>,
): void {
  customReplies.set(operation, reply);
}
export async function prepareScenario(scenario: Scenario): Promise<void> {
  reset();
  goldenMode = true;
  for (const responder of scenario.responders ?? []) {
    if (responder.generate) generated.set(responder.op, responder.generate);
    else if (responder.response)
      recorded.push({ operation: responder.op, response: responder.response });
    else {
      const fixture = JSON.parse(
        await readFile(resolve("tests/fixtures", responder.fixture!), "utf8"),
      ) as { response: Reply };
      recorded.push({ operation: responder.op, response: fixture.response });
    }
  }
  const tokens = await Promise.all(
    (scenario.oauth ?? [{ fixture: "oauth2/token-success.json" }]).map(
      async (entry) =>
        entry.response ??
        (
          JSON.parse(
            await readFile(resolve("tests/fixtures", entry.fixture!), "utf8"),
          ) as { response: Reply }
        ).response,
    ),
  );
  respondToken = (_request, response) => {
    const reply = tokens.length > 1 ? tokens.shift()! : tokens[0]!;
    json(response, reply.body, reply.status, reply.headers);
  };
}
const D1 = "ldt:synthetic-agent-01:1001";
const D2 = "ldt:synthetic-agent-02:1002";
const D3 = "ldt:synthetic-agent-03:1003";
let alerts: Record<string, unknown>[];
let host: ChildProcess | undefined;
let hosted:
  | {
      url: string;
      headers: Record<string, string>;
      environment: NodeJS.ProcessEnv;
      otherHeaders?: Record<string, string>;
      state?: string;
    }
  | undefined;
export function hostedConnection(): NonNullable<typeof hosted> {
  assert.ok(hosted);
  return hosted;
}
function setHostedDelivery(nextPort: string | number): Promise<void> {
  return new Promise((resolve, reject) => {
    const ready = (message: unknown): void => {
      if (
        message &&
        typeof message === "object" &&
        "deliveryReady" in message &&
        message.deliveryReady === true
      ) {
        host!.removeListener("message", ready);
        resolve();
      }
    };
    host!.on("message", ready);
    host!.send({ port: nextPort }, (error) => {
      if (error) {
        host!.removeListener("message", ready);
        reject(error);
      }
    });
  });
}
export function nextHostedTerminal(
  action: "read" | "write" | "any" = "write",
  outcome?: string,
): Promise<Record<string, unknown>> {
  assert.ok(host);
  return new Promise((resolve) => {
    const listener = (message: unknown): void => {
      if (
        message &&
        typeof message === "object" &&
        "terminal" in message &&
        message.terminal &&
        typeof message.terminal === "object" &&
        "action" in message.terminal &&
        (action === "any" || message.terminal.action === action) &&
        (outcome === undefined ||
          ("outcome" in message.terminal &&
            message.terminal.outcome === outcome))
      ) {
        host!.removeListener("message", listener);
        resolve(message.terminal as Record<string, unknown>);
      }
    };
    host!.on("message", listener);
  });
}
export function nextHostedChild(): Promise<number> {
  assert.ok(host);
  return new Promise((resolve) => {
    const listener = (message: unknown): void => {
      if (
        message &&
        typeof message === "object" &&
        "falconChild" in message &&
        typeof message.falconChild === "number"
      ) {
        host!.removeListener("message", listener);
        resolve(message.falconChild);
      }
    };
    host!.on("message", listener);
  });
}
const server = createServer();
export async function managedAudit(
  requestId?: string,
): Promise<Record<string, unknown>[]> {
  if (!hosted) throw new Error("Managed audit requires Artium");
  const response = await fetch(
    `${hosted.url}/v1/admin/audit?tool=falcon-axi&event=run-terminal&limit=100${requestId ? `&requestId=${encodeURIComponent(requestId)}` : ""}`,
    { headers: hosted.headers },
  );
  assert.equal(response.status, 200);
  const body = (await response.json()) as {
    records: Record<string, unknown>[];
  };
  return body.records;
}
function matchesRoute(id: string, method: string, path: string): boolean {
  const descriptor = operation(id);
  const pattern = descriptor.path
    .replace("{vertex_type}", "processes")
    .split(/\{[^}]+\}/)
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("[^/]+");
  return descriptor.method === method && new RegExp(`^${pattern}$`).test(path);
}
const delivery = fileURLToPath(new URL("./delivery.js", import.meta.url));
function json(
  response: ServerResponse,
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): void {
  response.writeHead(status, {
    "content-type": "application/json",
    ...headers,
  });
  response.end(Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
let recorded: {
  operation: string;
  response: { status: number; headers?: Record<string, string>; body: unknown };
  once?: boolean;
}[] = [];
export function tokenResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  respondToken = (_request, response) => json(response, body, status, headers);
}
export function recordedResponse(
  operation: string,
  status: number,
  body: unknown,
  once = false,
): void {
  recorded.push({ operation, response: { status, body }, once });
}
export async function recordings(fixtures: string[]): Promise<void> {
  recorded = await Promise.all(
    fixtures.map(async (fixture) => {
      const data = JSON.parse(
        await readFile(resolve("tests/fixtures", fixture), "utf8"),
      ) as {
        provenance: { operation: string };
        response: {
          status: number;
          headers?: Record<string, string>;
          body: unknown;
        };
      };
      return { operation: data.provenance.operation, response: data.response };
    }),
  );
}
export function reset(): void {
  goldenMode = false;
  generated = new Map();
  customReplies = new Map();
  recorded = [];
  wire.length = 0;
  tokenAttempt = 0;
  queryVariant = "normal";
  respondToken = (_request, response) =>
    json(response, { access_token: "synthetic-s01-token", expires_in: 1800 });
}
interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  elapsed: number;
}
export async function run(
  args: string[] = [],
  extra: NodeJS.ProcessEnv = {},
  cancelOnToken = false,
  closeInput = false,
  shellInvocation?: string,
  rawManagedArgs = false,
  childStarted?: (child: ChildProcess) => void,
): Promise<RunResult> {
  let start = performance.now();
  let command = executable;
  let invocation = args.length ? args : ["detection", "list", "--limit", "2"];
  if (goldenMode && !hosted) {
    command = process.execPath;
    invocation = [
      fileURLToPath(new URL("./golden-launcher.js", import.meta.url)),
      executable,
      ...args,
    ];
  }
  if (shellInvocation) {
    command = "/bin/sh";
    invocation = ["-c", shellInvocation];
  }
  let hostedEnvironment: NodeJS.ProcessEnv = {};
  if (hosted) {
    await setHostedDelivery(port);
    const regionIndex = rawManagedArgs ? -1 : invocation.indexOf("--region");
    const memberIndex = rawManagedArgs
      ? -1
      : invocation.indexOf("--member-cid");
    const current = await fetch(
      `${hosted.url}/v1/admin/tools/falcon-axi/credential`,
      { headers: hosted.headers },
    );
    const data = (await current.json()) as { revision: number };
    const tool = (await (
      await fetch(`${hosted.url}/v1/admin/tools/falcon-axi`, {
        headers: hosted.headers,
      })
    ).json()) as { revision: number };
    // Credential replacement performs its own real health read in this fixture.
    // Faults and wire assertions below describe only the requested invocation.
    const tokenResponse = respondToken;
    const requestedVariant = queryVariant;
    respondToken = (_request, response) =>
      json(response, { access_token: "synthetic-s01-token", expires_in: 1800 });
    queryVariant = "normal";
    const credential = await fetch(
      `${hosted.url}/v1/admin/tools/falcon-axi/credential`,
      {
        method: "PUT",
        headers: { ...hosted.headers, "content-type": "application/json" },
        body: JSON.stringify({
          expectedRevision: data.revision,
          expectedToolRevision: tool.revision,
          value: {
            clientId: "synthetic-s01-client",
            clientSecret: "synthetic-s01-secret",
            ...((invocation[0] === "search" && invocation[1] !== "status") ||
            (invocation[0] === "identity" && invocation[1] === "activity") ||
            (invocation[0] === "host" && invocation[1] === "usb") ||
            (invocation[0] === "malquery" && invocation[1] === "search")
              ? {
                  writes: {
                    allowWrites: !/^(1|true)$/i.test(
                      extra.FALCON_AXI_READ_ONLY ?? "false",
                    ),
                    operations: extra.S08_HOST_OPERATIONS?.split(",") ?? [
                      "rtr run",
                      "malquery search",
                    ],
                  },
                }
              : {}),
            region: regionIndex >= 0 ? invocation[regionIndex + 1] : "us-1",
            ...(["1", "malquery-only"].includes(extra.S11_HOST_RTR ?? "")
              ? {
                  rtr: { enabled: true },
                  writes: {
                    allowWrites: true,
                    operations: [
                      extra.S11_HOST_RTR === "malquery-only"
                        ? "malquery search"
                        : "rtr run",
                    ],
                  },
                }
              : {}),
            ...(memberIndex >= 0
              ? { memberCid: invocation[memberIndex + 1] }
              : {}),
          },
        }),
      },
    );
    assert.equal(credential.status, 200, await credential.text());
    wire.length = 0;
    tokenAttempt = 0;
    respondToken = tokenResponse;
    queryVariant = requestedVariant;
    if (extra.S01_DELIVERY_PORT)
      await setHostedDelivery(extra.S01_DELIVERY_PORT);
    invocation = invocation.filter(
      (_arg, index) =>
        ![
          regionIndex,
          regionIndex < 0 ? -1 : regionIndex + 1,
          memberIndex,
          memberIndex < 0 ? -1 : memberIndex + 1,
        ].includes(index),
    );
    command = process.execPath;
    invocation = [
      join(process.env.S01_ARTIUM_ROOT!, "dist/cli/artium-axi.mjs"),
      "falcon-axi",
      ...invocation,
    ];
    hostedEnvironment = hosted.environment;
  }
  if (shellInvocation) {
    command = "/bin/sh";
    invocation = ["-c", shellInvocation];
  }
  start = performance.now();
  const child = spawn(command, invocation, {
    cwd: directory,
    env: {
      HOME: directory,
      NODE_OPTIONS: `--import=${delivery}`,
      NODE_EXTRA_CA_CERTS: ca,
      FALCON_AXI_CONFIG: config,
      FALCON_AXI_PROFILE: "artium",
      ARTIUM_SECRET_0: "synthetic-s01-secret",
      // A selected file profile must ignore competing server identity.
      FALCON_AXI_CLIENT_ID: "synthetic-wrong-server-id",
      FALCON_AXI_CLIENT_SECRET: "synthetic-wrong-server-secret",
      S01_DELIVERY_PORT: String(port),
      ...(socketPath ? { S01_DELIVERY_SOCKET: socketPath } : {}),
      ...extra,
      ...hostedEnvironment,
      PATH: `${join(directory, "managed-bin")}:${dirname(executable)}:${hostedEnvironment.PATH ?? process.env.PATH ?? ""}`,
    },
  });
  if (closeInput) child.stdin.end();
  childStarted?.(child);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  let cancel: (() => void) | undefined;
  if (cancelOnToken) {
    cancel = () => child.kill("SIGTERM");
    server.once("token-sent", cancel);
  }
  let signal: NodeJS.Signals | null = null;
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, termination) => {
      signal = termination;
      resolve(code);
    });
  });
  if (cancel) server.removeListener("token-sent", cancel);
  for (const canary of [
    "synthetic-s01-secret",
    "synthetic-s01-client",
    "synthetic-s01-token",
    "synthetic-wrong-server",
  ])
    assert.ok(
      !(stdout + stderr).includes(canary),
      "credential canary escaped output",
    );
  return { code, signal, stdout, stderr, elapsed: performance.now() - start };
}
function assertRead(result: RunResult): void {
  assert.equal(result.code, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /^count: 2 of 3 total\n/);
  assert.match(
    result.stdout,
    /detections\[2\]\{id,severity,tactic,hostname\}:\n  "ldt:synthetic-agent-02:1002",Critical,Execution,WIN-WS-42\n  "ldt:synthetic-agent-01:1001",High,Defense Evasion,WIN-DC-01\n/,
  );
  assert.ok(result.stdout.endsWith("\n"));
  assert.equal(result.stderr, "");
  assert.equal(wire.at(-2)?.url, "/alerts/queries/alerts/v2?limit=2&offset=0");
  assert.equal(wire.at(-1)?.method, "POST");
  assert.deepEqual(JSON.parse(wire.at(-1)!.body), { composite_ids: [D2, D1] });
  for (const token of wire.filter((entry) => entry.url === "/oauth2/token")) {
    assert.equal(token.method, "POST");
    const form = new URLSearchParams(token.body);
    assert.equal(form.get("client_id"), "synthetic-s01-client");
    assert.equal(form.get("client_secret"), "synthetic-s01-secret");
  }
}

before(async () => {
  directory = await mkdtemp(
    join(
      process.env.S12_INSTALL_CHECK && process.platform !== "win32"
        ? "/var/tmp"
        : tmpdir(),
      "falcon-s01-installed ",
    ),
  );
  ca = join(directory, "ca.pem");
  const key = join(directory, "key.pem");
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      ca,
      "-days",
      "1",
      "-subj",
      "/CN=Synthetic Falcon S01",
      "-addext",
      "subjectAltName=DNS:api.crowdstrike.com,DNS:api.us-2.crowdstrike.com,DNS:api.eu-1.crowdstrike.com,DNS:synthetic-cloud.example,DNS:synthetic.invalid",
    ],
    { stdio: "ignore" },
  );
  server.setSecureContext({
    key: await readFile(key),
    cert: await readFile(ca),
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("request", (request, response) => {
    let body = "";
    request.on("data", (chunk: Buffer) => {
      body += chunk.toString();
    });
    request.on("end", async () => {
      wire.push({
        method: request.method!,
        url: request.url!,
        host: request.headers.host!,
        body,
        time: performance.now(),
        epoch: Date.now(),
        authorization: request.headers.authorization ?? "",
      });
      if (request.url === "/oauth2/token") {
        tokenAttempt++;
        respondToken(request, response);
        server.emit("token-sent");
        return;
      }
      const path = request.url!.split("?")[0]!;
      const custom = [...customReplies].find(([id]) =>
        matchesRoute(id, request.method!, path),
      )?.[1];
      if (custom) {
        const reply = await custom(
          new URL(request.url!, "https://api.crowdstrike.com").searchParams,
          body ? (JSON.parse(body) as Record<string, unknown>) : {},
        );
        if (reply.disconnect || reply.fault === "drop") response.destroy();
        else if (reply.fault === "stream") {
          response.writeHead(200, { "content-type": "application/json" });
          response.write('{"events":[');
          const timer = setInterval(() => response.write(" "), 10);
          response.once("close", () => clearInterval(timer));
        } else if (reply.fault === "truncate") {
          response.writeHead(200, {
            "content-type": "application/json",
            "content-length": "1000",
            connection: "close",
          });
          response.end('{"id":');
        } else json(response, reply.body, reply.status, reply.headers);
        return;
      }
      const generator = [...generated].find(
        ([id]) => operation(id).path === path,
      )?.[1];
      if (generator) {
        const query = new URL(request.url!, "https://api.crowdstrike.com")
          .searchParams;
        const payload = body
          ? (JSON.parse(body) as Record<string, unknown>)
          : {};
        let resources: unknown[];
        if (generator.kind === "host-ids") {
          const offset = Number(query.get("offset"));
          resources = Array.from(
            {
              length: Math.max(
                0,
                Math.min(
                  Number(generator.total) - offset,
                  Number(query.get("limit")),
                ),
              ),
            },
            (_, index) => `synthetic-device-${offset + index}`,
          );
        } else if (generator.kind === "ids")
          resources = Array.from(
            { length: Number(generator.count) },
            (_, index) => `ldt:synthetic-agent-${index}:${index}`,
          );
        else if (generator.kind === "host-hydrate")
          resources = [...(payload.ids as string[])]
            .reverse()
            .map((device_id) => ({
              device_id,
              hostname: "synthetic-host",
              platform_name: "Windows",
              last_seen: "unknown",
            }));
        else {
          const ids = payload.composite_ids as string[];
          const taken =
            generator.take === undefined
              ? [...ids]
              : ids.slice(0, Number(generator.take));
          resources = (generator.reverse ? taken.reverse() : taken).map(
            (composite_id) => ({
              composite_id,
              severity_name: generator.severity_name,
              tactic: generator.tactic,
              device: { hostname: generator.hostname },
            }),
          );
        }
        json(response, {
          ...(generator.total !== undefined
            ? { meta: { pagination: { total: generator.total } } }
            : {}),
          resources,
        });
        return;
      }
      const matched = recorded.find((entry) =>
        matchesRoute(entry.operation, request.method!, path),
      );
      if (matched) {
        if (matched.once) recorded.splice(recorded.indexOf(matched), 1);
        let payload = matched.response.body;
        const query = new URL(request.url!, "https://api.crowdstrike.com")
          .searchParams;
        const requested: unknown = body
          ? ((JSON.parse(body) as Record<string, unknown>).ids ??
            (JSON.parse(body) as Record<string, unknown>).composite_ids)
          : query.getAll("ids");
        if (
          matched.operation === "combined_summary_get" &&
          payload &&
          typeof payload === "object" &&
          "resources" in payload &&
          Array.isArray(payload.resources)
        )
          payload = {
            ...payload,
            resources: payload.resources.filter(
              (row: { id: string }) =>
                Array.isArray(requested) && requested.includes(row.id),
            ),
          };
        json(response, payload, matched.response.status, {
          "content-type": "",
          ...matched.response.headers,
        });
        return;
      }
      if (request.url?.startsWith("/alerts/queries/alerts/v2?")) {
        if (queryVariant === "denied") {
          json(response, { errors: [{ message: "synthetic refusal" }] }, 403);
          return;
        }
        if (queryVariant === "malformed") {
          json(response, { resources: "invalid" });
          return;
        }
        const offset = new URL(
          request.url,
          "https://api.crowdstrike.com",
        ).searchParams.get("offset");
        json(response, {
          meta: { pagination: { total: queryVariant === "empty" ? 0 : 3 } },
          errors: [],
          resources:
            queryVariant === "member"
              ? alerts.map((alert) => alert.composite_id)
              : queryVariant === "empty"
                ? []
                : offset === "0"
                  ? [D2, D1]
                  : [D3],
        });
        return;
      }
      if (
        request.url === "/alerts/entities/alerts/v2" &&
        request.method === "POST"
      ) {
        const ids = (JSON.parse(body) as { composite_ids: string[] })
          .composite_ids;
        json(response, {
          resources: alerts
            .filter((alert) => ids.includes(alert.composite_id as string))
            .reverse(),
          errors: [],
        });
        return;
      }
      json(response, { errors: [] }, 418);
    });
  });
  if (process.env.S11_SOCKET_DELIVERY === "1") {
    socketPath = join(directory, "falcon.sock");
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  } else
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
  const address = server.address();
  assert.ok(address);
  port = typeof address === "object" ? address.port : 0;
  const seed = await readFile(
    resolve("tests/fixtures/alerts/hydrate-page.json"),
  );
  assert.equal(
    createHash("sha256").update(seed).digest("hex"),
    "4be21331b0cde649c8c3913594cef92df922588b38a3a9d607f75b6edb8436b3",
  );
  const parsed = JSON.parse(seed.toString()) as {
    response: { body: { resources: Record<string, unknown>[] } };
  };
  alerts = [
    ...parsed.response.body.resources,
    {
      composite_id: D3,
      severity_name: "Low",
      tactic: "Discovery",
      device: { hostname: "WIN-WS-43" },
    },
  ];
  config = join(directory, "config.json");
  await writeFile(
    config,
    JSON.stringify({
      version: 1,
      defaultProfile: "artium",
      profiles: {
        artium: {
          clientId: "synthetic-s01-client",
          clientSecret: { env: "ARTIUM_SECRET_0" },
          region: "us-1",
        },
      },
    }),
    { mode: 0o600 },
  );
  const pack = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--json", "--ignore-scripts", "--pack-destination", directory],
      { encoding: "utf8" },
    ),
  ) as { filename: string; files: { path: string }[] }[];
  assert.equal(pack.length, 1);
  for (const file of pack[0]!.files)
    assert.ok(
      [
        "package.json",
        "LICENSE",
        "README.md",
        "artium-invocations.json",
      ].includes(file.path) ||
        (file.path.startsWith("skills/falcon-axi/") &&
          file.path.endsWith(".md")) ||
        file.path.startsWith(".typescript-build/src/") ||
        [
          ".typescript-build/native/checksums.json",
          "native/prebuilds/linux-x64.node",
          "native/prebuilds/win32-x64.node",
        ].includes(file.path),
      `unpackaged authority: ${file.path}`,
    );
  const prefix = join(directory, "clean install");
  await mkdir(prefix);
  execFileSync(
    "npm",
    [
      "install",
      "--offline",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--prefix",
      prefix,
      join(directory, pack[0]!.filename),
    ],
    { stdio: "pipe" },
  );
  executable = join(prefix, "node_modules", ".bin", "falcon-axi");
  if (process.env.S01_EVIDENCE_DIR) {
    const evidence = process.env.S01_EVIDENCE_DIR;
    const path = process.env.S01_ACTIVE_PATH ?? "native";
    const artifact = await readFile(join(directory, pack[0]!.filename));
    const hash = (data: Buffer): string =>
      createHash("sha256").update(data).digest("hex");
    await copyFile(
      join(directory, pack[0]!.filename),
      join(evidence, `${path}-package.tgz`),
    );
    await writeFile(
      join(evidence, `${path}-inputs.json`),
      JSON.stringify(
        {
          sourceSha: execFileSync("git", ["rev-parse", "HEAD"], {
            encoding: "utf8",
          }).trim(),
          sourceDirty: Boolean(
            execFileSync("git", ["status", "--porcelain"], {
              encoding: "utf8",
            }).trim(),
          ),
          artifactSha256: hash(artifact),
          integrity: `sha512-${createHash("sha512").update(artifact).digest("base64")}`,
          schemaSha256: hash(
            await readFile(
              join(
                prefix,
                "node_modules/@knowttl/falcon-axi/.typescript-build/src/axi-credential.schema.json",
              ),
            ),
          ),
          runtime: process.version,
          runtimeSha256: hash(await readFile(process.execPath)),
          fixtureSha256: hash(seed),
          fixture: "tests/fixtures/alerts/hydrate-page.json",
          ...(process.env.S01_ARTIUM_ROOT
            ? {
                artiumSha: execFileSync(
                  "git",
                  ["-C", process.env.S01_ARTIUM_ROOT, "rev-parse", "HEAD"],
                  { encoding: "utf8" },
                ).trim(),
                artiumDirty: Boolean(
                  execFileSync(
                    "git",
                    [
                      "-C",
                      process.env.S01_ARTIUM_ROOT,
                      "status",
                      "--porcelain",
                    ],
                    { encoding: "utf8" },
                  ).trim(),
                ),
              }
            : {}),
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );
  }
  if (process.env.S01_ACTIVE_PATH === "artium") {
    const fixture = process.env.S01_ARTIUM_ROOT!;
    await mkdir(join(directory, "managed-bin"));
    await writeFile(
      join(directory, "managed-bin/artium-axi"),
      `#!/bin/sh\nexec '${process.execPath}' '${join(fixture, "dist/cli/artium-axi.mjs")}' "$@"\n`,
      { mode: 0o700 },
    );
    host = spawn(
      process.execPath,
      [join(fixture, "dist/test/falcon-s01-host.js")],
      {
        cwd: fixture,
        stdio: ["ignore", "pipe", "pipe", "ipc"],
        env: {
          ...process.env,
          S01_HOST_STATE: join(directory, "host"),
          S01_INSTALLED_EXECUTABLE: executable,
          S01_INSTALLED_SCHEMA: join(
            prefix,
            "node_modules/@knowttl/falcon-axi/.typescript-build/src/axi-credential.schema.json",
          ),
          S01_DELIVERY_PRELOAD: delivery,
          S01_DELIVERY_PORT: String(port),
          S01_CA: ca,
          ...(socketPath
            ? {
                S01_DELIVERY_SOCKET: socketPath,
                S11_DENY_LAUNCHER: process.env.S11_DENY_LAUNCHER,
              }
            : {}),
        },
      },
    );
    let diagnostics = "";
    host.stderr!.on("data", (chunk: Buffer) => {
      diagnostics += chunk.toString();
      if (process.env.S11_MUTATION) process.stderr.write(chunk);
    });
    hosted = await new Promise<NonNullable<typeof hosted>>(
      (resolve, reject) => {
        const ready = (message: unknown): void => {
          if (
            message &&
            typeof message === "object" &&
            "url" in message &&
            typeof message.url === "string"
          ) {
            host!.removeListener("message", ready);
            resolve(message as NonNullable<typeof hosted>);
          }
        };
        host!.on("message", ready);
        host!.once("error", reject);
        host!.once("exit", (code) =>
          reject(
            new Error(`Local Artium setup failed (${code}): ${diagnostics}`),
          ),
        );
      },
    );
  }
  reset();
});
after(async () => {
  if (host?.connected) {
    host.send("close");
    await new Promise<void>((resolve) => host!.once("exit", () => resolve()));
  }
  for (const socket of sockets) socket.destroy();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await rm(directory, { recursive: true, force: true });
});

test("H06 installed package preserves query order, columns, total and returned continuation", async () => {
  reset();
  const first = await run();
  assertRead(first);
  const cursor = /^continuation_cursor: (.+)$/m.exec(first.stdout)?.[1];
  assert.ok(cursor);
  const second = await run([
    "detection",
    "list",
    "--limit",
    "2",
    "--cursor",
    cursor,
  ]);
  assert.equal(second.code, 0);
  assert.equal(
    second.stdout,
    `count: 1 of 3 total\ndetections[1]{id,severity,tactic,hostname}:\n  "${D3}",Low,Discovery,WIN-WS-43\nhelp[1]: "Run \`${hosted ? "artium-axi falcon-axi" : "falcon-axi"} detection show <id>\` for the full detection"\n`,
  );
});
if (process.env.S01_ACTIVE_PATH !== "artium") {
  for (const selection of [
    ["--member-cid", ""],
    ["--member-cid="],
    ["--member-cid", "   "],
    ["--member-cid", "synthetic-member", "--no-member-cid"],
  ])
    test(`tenant selector ${JSON.stringify(selection)} fails before credentials`, async () => {
      reset();
      const result = await run(["detection", "list", ...selection], {
        FALCON_AXI_CONFIG: join(directory, "missing.json"),
      });
      assert.equal(result.code, 2);
      assert.match(result.stdout, /VALIDATION_ERROR/);
      assert.equal(result.stderr, "");
      assert.equal(wire.length, 0);
    });

  for (const source of ["flag", "environment", "profile"])
    test(`composite IDs survive ${source} member selection without exposing secrets`, async () => {
      reset();
      queryVariant = "member";
      const member = "synthetic-member";
      const ids = [
        `${member}:ind:agent:alert`,
        `${member}:automated-lead:alert`,
      ];
      const original = alerts;
      alerts = ids.map((composite_id) => ({
        composite_id,
        severity_name: "High",
        tactic: "synthetic-s01-secret synthetic-s01-client synthetic-s01-token",
        hostname: member,
      }));
      const extra: NodeJS.ProcessEnv = {};
      const args = ["detection", "list", "--limit", "2"];
      if (source === "flag") args.push("--member-cid", member);
      if (source === "environment") {
        extra.FALCON_AXI_PROFILE = undefined;
        extra.FALCON_AXI_CLIENT_ID = "synthetic-s01-client";
        extra.FALCON_AXI_CLIENT_SECRET = "synthetic-s01-secret";
        extra.FALCON_AXI_MEMBER_CID = member;
      }
      if (source === "profile") {
        const profile = JSON.parse(await readFile(config, "utf8"));
        profile.profiles.artium.memberCid = member;
        extra.FALCON_AXI_CONFIG = join(directory, "member-config.json");
        await writeFile(extra.FALCON_AXI_CONFIG, JSON.stringify(profile), {
          mode: 0o600,
        });
      }
      try {
        const result = await run(args, extra);
        assert.equal(result.code, 0, result.stdout);
        const data = decode(result.stdout) as {
          detections: { id: string; hostname: string; tactic: string }[];
        };
        assert.deepEqual(
          data.detections.map((row) => row.id),
          ids,
        );
        for (const row of data.detections) {
          assert.equal(row.hostname, "[redacted]");
          assert.equal(row.tactic, "[redacted] [redacted] [redacted]");
        }
        assert.equal(result.stderr, "");
        assert.equal(
          new URLSearchParams(wire[0]!.body).get("member_cid"),
          member,
        );
      } finally {
        alerts = original;
      }
    });
}

test("OAuth refuses an explicitly empty member selection before sending", () => {
  reset();
  assert.throws(
    () =>
      requestToken(
        "https://api.crowdstrike.com",
        {
          clientId: "synthetic-client",
          clientSecret: "synthetic-secret",
          memberCid: "",
        },
        false,
        new AbortController().signal,
      ),
    { code: "VALIDATION_ERROR" },
  );
  assert.equal(wire.length, 0);
});

test("CID redaction preserves composite IDs across structured, raw and help output", () => {
  const cid = "synthetic-render-member";
  const id = `${cid}:ind:agent:alert`;
  registerMemberCid(cid);
  const output = render(
    {
      detections: [{ id, cid, hostname: cid }],
      note: new Raw(`${id} ${cid}`),
    },
    [`Run detection show ${id}; tenant ${cid}; https://example.test/${cid}`],
  );
  const data = decode(output) as {
    detections: { id: string; cid: string; hostname: string }[];
    note: string;
    help: string[];
  };
  assert.deepEqual(data.detections, [
    { id, cid: "[redacted]", hostname: "[redacted]" },
  ]);
  assert.equal(data.note, `${id} [redacted]`);
  assert.deepEqual(data.help, [
    `Run detection show ${id}; tenant [redacted]; https://example.test/[redacted]`,
  ]);
});

for (const field of [
  "cid",
  "member_cid",
  "device.cid",
  "tenant.member_cid",
  "CID",
])
  test(`continuation conceals the ${field} filter while sending it unchanged`, async () => {
    reset();
    const filter = `${field}:'synthetic-unregistered-tenant'`;
    const result = await run([
      "detection",
      "list",
      "--limit",
      "2",
      "--filter",
      filter,
    ]);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /--filter '<original-filter>'/);
    assert.match(
      result.stdout,
      /Replace <original-filter> with your original --filter/,
    );
    assert.ok(!result.stdout.includes("synthetic-unregistered-tenant"));
    assert.equal(
      new URL(wire[1]!.url, "https://api.crowdstrike.com").searchParams.get(
        "filter",
      ),
      filter,
    );
    assert.equal(result.stderr, "");
  });

for (const variant of ["empty", "malformed", "denied"])
  test(`H07 installed ${variant} response is distinct`, async () => {
    reset();
    queryVariant = variant;
    const result = await run();
    if (variant === "empty")
      assert.equal(
        result.stdout,
        `detections: 0 detections in this tenant\nhelp[1]: "Run \`${hosted ? "artium-axi falcon-axi" : "falcon-axi"} detection list\` without filters to see what is firing"\n`,
      );
    else
      assert.match(
        result.stdout,
        new RegExp(
          `code: ${variant === "malformed" ? "UPSTREAM_ERROR" : "SCOPE_DENIED"}`,
        ),
      );
    assert.equal(result.code, variant === "empty" ? 0 : 1);
    if (variant === "malformed")
      assert.deepEqual(decode(result.stdout), {
        error: "Falcon returned a malformed resources array",
        code: "UPSTREAM_ERROR",
        status: 200,
        contentType: "application/json",
        shape: [
          { path: "$", type: "object" },
          { path: '$["resources"]', type: "string" },
        ],
        shapeTruncated: false,
      });
    assert.equal(wire.length, 2);
  });
for (const status of [429, 500, 502, 503, 504])
  for (const failures of [1, 2, 3])
    test(`OAuth ${status} after ${failures} failures obeys three-attempt ceiling`, async () => {
      reset();
      respondToken = (_request, response) =>
        tokenAttempt <= failures
          ? json(response, { errors: [] }, status)
          : json(response, { access_token: "synthetic-s01-token" });
      const result = await run();
      assert.equal(tokenAttempt, Math.min(failures + 1, 3));
      if (failures < 3) assertRead(result);
      else {
        assert.equal(result.code, 1);
        assert.equal(wire.length, 3);
      }
      const tokens = wire.filter((entry) => entry.url === "/oauth2/token");
      for (let i = 1; i < tokens.length; i++) {
        const elapsed = tokens[i]!.time - tokens[i - 1]!.time;
        assert.ok(
          elapsed >= 500 * 2 ** (i - 1) - 20 &&
            elapsed <= 1000 * 2 ** (i - 1) + 250,
          `retry timing ${elapsed}`,
        );
      }
    });
for (const status of [400, 401, 403, 404])
  test(`OAuth ${status} is terminal without replay`, async () => {
    reset();
    respondToken = (_request, response) => json(response, {}, status);
    const result = await run();
    assert.equal(result.code, 1);
    assert.equal(wire.length, 1);
    assert.match(
      result.stdout,
      new RegExp(
        `code: ${[401, 403].includes(status) ? "AUTH_FAILED" : "UPSTREAM_ERROR"}`,
      ),
    );
  });
test("token 403 under a member is TENANT_DENIED", async () => {
  reset();
  respondToken = (_request, response) => json(response, {}, 403);
  const result = await run([
    "detection",
    "list",
    "--member-cid",
    "synthetic-member",
  ]);
  assert.match(result.stdout, /code: TENANT_DENIED/);
  assert.equal(wire.length, 1);
});
for (const status of [301, 302, 303, 307, 308])
  test(`OAuth ${status} never follows Location`, async () => {
    reset();
    respondToken = (_request, response) =>
      json(response, {}, status, {
        location: "https://hostile.invalid/secret-trap",
      });
    const result = await run();
    assert.match(result.stdout, /code: ORIGIN_NOT_ALLOWED/);
    assert.equal(wire.length, 1);
  });
test("verified-region re-mint has an independent retry ceiling and no third mint", async () => {
  reset();
  respondToken = (request, response) => {
    if (tokenAttempt === 1) json(response, {}, 503);
    else if (tokenAttempt === 2)
      json(response, {}, 308, {
        "x-cs-region": "us-2",
        location: "https://hostile.invalid",
      });
    else if (tokenAttempt === 3) json(response, {}, 502);
    else {
      assert.equal(request.headers.host, "api.us-2.crowdstrike.com");
      json(response, { access_token: "synthetic-s01-token" });
    }
  };
  assertRead(await run());
  assert.equal(tokenAttempt, 4);
});
test("epoch-only 429 hint bounds the next send", async () => {
  reset();
  let epoch = 0;
  respondToken = (_request, response) => {
    if (tokenAttempt === 1) {
      epoch = Date.now() + 2000;
      json(response, {}, 429, {
        "x-ratelimit-retryafter": String(epoch / 1000),
      });
    } else json(response, { access_token: "synthetic-s01-token" });
  };
  assertRead(await run());
  assert.ok(
    wire[1]!.epoch >= epoch && wire[1]!.epoch <= epoch + 250,
    `retry arrived ${wire[1]!.epoch - epoch} ms from the supplied epoch`,
  );
});
for (const hint of ["0", "invalid", "NaN", "Infinity", "-Infinity"])
  test(`invalid epoch hint ${hint} falls back to backoff`, async () => {
    reset();
    respondToken = (_request, response) =>
      tokenAttempt === 1
        ? json(response, {}, 429, { "x-ratelimit-retryafter": hint })
        : json(response, { access_token: "synthetic-s01-token" });
    assertRead(await run());
    assert.ok(
      wire[1]!.time - wire[0]!.time >= 500 &&
        wire[1]!.time - wire[0]!.time <= 1250,
    );
  });
test("an inherited token deadline bounds retry sleep before any scoped send", async () => {
  reset();
  respondToken = (_request, response) =>
    json(response, {}, 429, {
      "x-ratelimit-retryafter": String(Date.now() / 1000 + 10),
    });
  const result = await run([
    "search",
    "status",
    "synthetic-job",
    "--wait",
    "1",
  ]);
  assert.match(result.stdout, /code: WAIT_TIMEOUT/);
  assert.ok(result.elapsed < 1600);
  assert.equal(wire.length, 1);
});
test("cancellation during token acquisition settles without another send", async () => {
  reset();
  respondToken = (_request, response) => {
    response.writeHead(200);
    response.write('{"access_token":"');
  };
  const result = await run([], {}, true);
  if (!hosted) assert.match(result.stdout, /code: WAIT_TIMEOUT/);
  assert.equal(wire.length, 1);
  assert.ok(result.elapsed < 1500);
});
test("continuous response bytes cannot extend the 30-second acquisition deadline", async () => {
  reset();
  respondToken = (_request, response) => {
    response.writeHead(200);
    response.write('{"access_token":"');
    const timer = setInterval(() => response.write("x"), 100);
    response.once("close", () => clearInterval(timer));
  };
  const result = await run();
  assert.match(result.stdout, /code: WAIT_TIMEOUT/);
  assert.ok(result.elapsed >= 30_000 && result.elapsed < 31_000);
  assert.equal(wire.length, 1);
});
for (const region of [
  "https://api.crowdstrike.com:443",
  "https://api.crowdstrike.com/../",
  "https://api.crowdstrike.com/%2e%2e",
  "https://api.crowdstrike.com\\hostile.invalid",
  "https://api.crowdstrike.com?secret=trap",
  "https://api.crowdstrike.com#fragment",
  "https://user@api.crowdstrike.com",
  "https://api.crowdstrike.com.evil.invalid",
])
  test(`lexical origin refusal ${region}`, async () => {
    reset();
    const result = await run(["detection", "list", "--region", region]);
    assert.match(result.stdout, /code: ORIGIN_NOT_ALLOWED/);
    assert.equal(wire.length, 0);
    assert.ok(!result.stdout.includes("trap"));
  });
test("unknown flag fails before credentials or traffic", async () => {
  reset();
  const result = await run(["detection", "list", "-x"], {
    FALCON_AXI_CONFIG: "/missing",
  });
  assert.equal(result.code, 2);
  assert.match(result.stdout, /unknown flag -x/);
  assert.equal(wire.length, 0);
});
test("sealed registry rejects inherited keys, mutation and unimplemented exception operations", async () => {
  assert.equal(operationIds.length, 114);
  for (const id of ["__proto__", "constructor", "toString", "DeleteHosts"])
    assert.throws(() => operation(id), /outside the sealed/);
  assert.throws(
    () => Object.assign(operation("GetQueriesAlertsV2"), { method: "DELETE" }),
    TypeError,
  );
  await assert.rejects(
    async () =>
      requestRead(
        "RTR_InitSession",
        "https://api.crowdstrike.com",
        "synthetic",
        {},
        undefined,
        false,
        new AbortController().signal,
      ),
    /not available/,
  );
});
test("TOON boundaries preserve raw lines, omission, help quoting, Unicode lengths and exact integers", () => {
  assert.equal(
    render(
      {
        omitted: null,
        count: new Raw("2 of 3 total"),
        text: "a: b",
        integer: parseResponse("9007199254740993"),
      },
      ['a "quote",\nnext'],
    ),
    'count: 2 of 3 total\ntext: "a: b"\ninteger: "9007199254740993"\nhelp[1]: "a \\"quote\\",\\nnext"\n',
  );
  assert.equal(truncate("😀😀😀", 2), "😀😀… (truncated, 3 chars total)");
});
for (const [input, expected] of [
  ["9007199254740993", 'value: "9007199254740993"\n'],
  ["9007199254740993.1", 'value: "9007199254740993.1"\n'],
  ["1e100", 'value: "1e100"\n'],
  ["-9007199254740993", 'value: "-9007199254740993"\n'],
  // Rounds onto the safe-integer boundary, so the fraction would be lost.
  ["9007199254740991.1", 'value: "9007199254740991.1"\n'],
  ["-9007199254740991.1", 'value: "-9007199254740991.1"\n'],
  ["9.0071992547409911e15", 'value: "9.0071992547409911e15"\n'],
  ["-9.0071992547409911E15", 'value: "-9.0071992547409911E15"\n'],
  ["9007199254740992.0", 'value: "9007199254740992.0"\n'],
  ["-9007199254740992.0", 'value: "-9007199254740992.0"\n'],
  ["9.007199254740992e15", 'value: "9.007199254740992e15"\n'],
  ["-9.007199254740992e15", 'value: "-9.007199254740992e15"\n'],
  // Exact in Number, so it stays a plain number.
  ["9007199254740991", "value: 9007199254740991\n"],
  ["-9007199254740991", "value: -9007199254740991\n"],
  ["9007199254740991.0", "value: 9007199254740991\n"],
  ["-9007199254740991.0", "value: -9007199254740991\n"],
  ["9.007199254740991e15", "value: 9007199254740991\n"],
  ["-9.007199254740991e15", "value: -9007199254740991\n"],
  ["90071992547409910e-1", "value: 9007199254740991\n"],
  ["0.090071992547409910e+17", "value: 9007199254740991\n"],
  ["9007199254740990.9", "value: 9007199254740991\n"],
  ["0e999999999999999999999", "value: 0\n"],
  ["1e-999999999999999999999", "value: 0\n"],
  ["1.5", "value: 1.5\n"],
])
  test(`numeric response lexeme ${input} is preserved exactly`, () => {
    assert.equal(render({ value: parseResponse(input!) }), expected);
  });
test("slice selectors reject unknown, empty and missing requested paths", () => {
  const runner = fileURLToPath(
    new URL("../../scripts/typescript/check-slice.js", import.meta.url),
  );
  for (const args of [
    [],
    ["--slice", "S99", "--paths", "native", "--offline"],
    ["--slice", "S01", "--paths", "absent", "--offline"],
  ]) {
    assert.equal(
      spawnSync(process.execPath, [runner, ...args], { encoding: "utf8" })
        .status,
      2,
    );
  }
  assert.equal(
    spawnSync(
      process.execPath,
      [runner, "--slice", "S01", "--paths", "artium", "--offline"],
      { encoding: "utf8", env: { ...process.env, S01_ARTIUM_ROOT: undefined } },
    ).status,
    1,
  );
});
if (process.env.S01_ACTIVE_PATH !== "artium")
  test("version latency stays near the Node startup floor", () => {
    const env = { PATH: process.env.PATH, HOME: directory };
    const floors: number[] = [];
    const versions: number[] = [];
    for (let index = 0; index < 7; index++) {
      let start = performance.now();
      assert.equal(
        spawnSync(process.execPath, ["-e", "console.log(1)"], {
          env,
          encoding: "utf8",
        }).status,
        0,
      );
      floors.push(performance.now() - start);
      start = performance.now();
      assert.equal(
        spawnSync(executable, ["--version"], { env, encoding: "utf8" }).stdout,
        `${VERSION}\n`,
      );
      versions.push(performance.now() - start);
    }
    const median = (values: number[]): number =>
      values.sort((a, b) => a - b)[3]!;
    assert.ok(
      median(versions) <= median(floors) * 3,
      "version path loaded the command graph",
    );
  });
test("public fast-version aliases answer from the clean installed artifact", async () => {
  for (const flag of ["-v", "-V", "--version"])
    assert.equal((await run([flag])).stdout, `${VERSION}\n`);
});
test("TLS hostname rejection remains active at the synthetic connection boundary", async () => {
  reset();
  const result = await run([
    "detection",
    "list",
    "--region",
    "https://other.crowdstrike.com",
  ]);
  assert.match(result.stdout, /code: TLS_UNTRUSTED/);
  assert.equal(wire.length, 0);
});
test("TCP/TLS stall respects inherited budget and settles", async () => {
  reset();
  const baseline = await run(["auth", "status"]);
  assert.equal(baseline.code, 0, baseline.stdout);
  reset();
  const stalled = tcpServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => stalled.listen(0, "127.0.0.1", resolve));
  const address = stalled.address();
  assert.ok(address && typeof address === "object");
  try {
    const result = await run(
      ["search", "status", "synthetic-job", "--wait", "1"],
      { S01_DELIVERY_PORT: String(address.port) },
    );
    assert.match(result.stdout, /code: WAIT_TIMEOUT/);
    assert.ok(
      result.elapsed - baseline.elapsed < 1600,
      `invocation settled at ${result.elapsed} ms; startup baseline ${baseline.elapsed} ms`,
    );
    assert.equal(wire.length, 0);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => stalled.close(() => resolve()));
  }
});
test("outbound network denial is enforced by the process namespace", async () => {
  const error = await new Promise<Error & { code?: string }>((resolve) => {
    const socket = connect({ host: "192.0.2.1", port: 443 });
    socket.once("connect", () => {
      socket.destroy();
      throw new Error("External network unexpectedly reachable");
    });
    socket.once("error", resolve);
  });
  assert.equal(error.code, "ENETUNREACH");
});
for (const status of [500, 502, 503, 504])
  test(`OAuth ${status} ignores the rate-limit timestamp`, async () => {
    reset();
    respondToken = (_request, response) =>
      tokenAttempt === 1
        ? json(response, {}, status, {
            "x-ratelimit-retryafter": String(Date.now() / 1000 + 3600),
          })
        : json(response, { access_token: "synthetic-s01-token" });
    assertRead(await run());
    assert.ok(
      wire[1]!.time - wire[0]!.time >= 500 &&
        wire[1]!.time - wire[0]!.time <= 1250,
    );
  });
for (const hint of ["us-1", "unverified-cloud"])
  test(`OAuth refuses a redirect hint ${hint} without re-mint`, async () => {
    reset();
    respondToken = (_request, response) =>
      json(response, {}, 308, {
        "x-cs-region": hint,
        location: "https://hostile.invalid/",
      });
    const result = await run();
    assert.match(
      result.stdout,
      new RegExp(
        `code: ${hint === "us-1" ? "ORIGIN_NOT_ALLOWED" : "REGION_MISMATCH"}`,
      ),
    );
    assert.equal(wire.length, 1);
  });
test("a second region redirect cannot mint a third time", async () => {
  reset();
  respondToken = (_request, response) =>
    json(response, {}, 308, {
      "x-cs-region": tokenAttempt === 1 ? "us-2" : "us-1",
    });
  assert.match((await run()).stdout, /code: ORIGIN_NOT_ALLOWED/);
  assert.equal(wire.length, 2);
});
for (const afterRetry of [false, true])
  test(`a raised transport failure${afterRetry ? " after a retry" : ""} is not replayed`, async () => {
    reset();
    respondToken = (_request, response) =>
      afterRetry && tokenAttempt === 1
        ? json(response, {}, 503)
        : response.destroy();
    assert.match((await run()).stdout, /code: NETWORK_UNREACHABLE/);
    assert.equal(wire.length, afterRetry ? 2 : 1);
  });
test("a truncated token response is a raised failure without replay", async () => {
  reset();
  respondToken = (_request, response) => {
    response.writeHead(200, { "content-length": "100" });
    response.end('{"access_token":');
  };
  assert.match((await run()).stdout, /code: NETWORK_UNREACHABLE/);
  assert.equal(wire.length, 1);
});
for (const variant of ["backoff", "body"])
  test(`inherited OAuth deadline includes ${variant}`, async () => {
    reset();
    respondToken = (_request, response) => {
      if (variant === "backoff") json(response, {}, 503);
      else {
        response.writeHead(200);
        response.write('{"access_token":"');
      }
    };
    const result = await run([
      "search",
      "status",
      "synthetic-job",
      "--wait",
      "1",
    ]);
    assert.match(result.stdout, /code: WAIT_TIMEOUT/);
    assert.ok(result.elapsed < 1800);
    assert.ok(wire.length > 0 && wire.length <= 2);
    assert.ok(wire.every((entry) => entry.url === "/oauth2/token"));
  });
test("cancellation during retry backoff cannot send again", async () => {
  reset();
  respondToken = (_request, response) => json(response, {}, 503);
  const result = await run([], {}, true);
  if (!hosted) assert.match(result.stdout, /code: WAIT_TIMEOUT/);
  assert.equal(wire.length, 1);
});
if (process.env.S01_ACTIVE_PATH !== "artium")
  test("HTTP proxy uses CONNECT and carries the read only inside verified TLS", async () => {
    reset();
    let connects = 0;
    let tunneledBytes = 0;
    const proxy = proxyServer((_request, response) => {
      response.writeHead(500);
      response.end();
    });
    proxy.on("connect", (request, socket, head) => {
      assert.equal(request.url, "api.crowdstrike.com:443");
      assert.equal(head.length, 0);
      connects++;
      const upstream = connect(port, "127.0.0.1", () => {
        socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        socket.pipe(upstream);
        upstream.pipe(socket);
      });
      socket.on("data", (chunk: Buffer) => {
        tunneledBytes += chunk.length;
      });
      socket.on("error", () => upstream.destroy());
      upstream.on("error", () => socket.destroy());
      socket.once("close", () => upstream.destroy());
      upstream.once("close", () => socket.destroy());
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const address = proxy.address();
    assert.ok(address && typeof address === "object");
    try {
      assertRead(
        await run([], {
          FALCON_AXI_PROXY_URL: `http://127.0.0.1:${address.port}`,
        }),
      );
      assert.equal(connects, 3);
      assert.ok(tunneledBytes > 0);
    } finally {
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
  });

if (process.env.S01_ACTIVE_PATH !== "artium")
  test("DNS resolution settles within the inherited invocation budget", () => {
    const probe = fileURLToPath(
      new URL("./dns-deadline-probe.js", import.meta.url),
    );
    const result = spawnSync(
      "unshare",
      ["--mount", process.execPath, probe, executable],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
