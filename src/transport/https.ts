import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import type { Duplex } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { CliError, object, parseResponse } from "../core.js";
import { origin } from "../origin.js";
import { operation } from "./operations.js";
import { VERSION } from "../version.js";
import { createLookup } from "./resolver.js";

export interface Response {
  status: number;
  headers: Readonly<Record<string, string>>;
  body: unknown;
}
type Query = Readonly<Record<string, string | number | readonly string[]>>;
interface Prepared {
  origin: string;
  method: string;
  path: string;
  headers: Readonly<Record<string, string>>;
  body: string;
}
const permits = new WeakSet<Prepared>();
const timeout = (): CliError =>
  new CliError("WAIT_TIMEOUT", "the Falcon request exceeded its time budget", [
    "Retry shortly",
  ]);
function failure(error: unknown): CliError {
  if (error instanceof CliError) return error;
  const code =
    object(error) && typeof error.code === "string" ? error.code : "";
  return new CliError(
    [
      "CERT_HAS_EXPIRED",
      "DEPTH_ZERO_SELF_SIGNED_CERT",
      "SELF_SIGNED_CERT_IN_CHAIN",
      "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
      "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
      "ERR_TLS_CERT_ALTNAME_INVALID",
    ].includes(code)
      ? "TLS_UNTRUSTED"
      : "NETWORK_UNREACHABLE",
    "the Falcon connection could not be completed",
    ["Check network connectivity and the system trust store"],
  );
}

// The sole network sink. Only frozen requests registered in this module carry authority.
async function send(
  prepared: Prepared,
  inherited: AbortSignal,
): Promise<Response> {
  if (!permits.has(prepared) || !Object.isFrozen(prepared))
    throw new CliError("READ_ONLY_VIOLATION", "request authority was refused");
  const signal = AbortSignal.any([inherited, AbortSignal.timeout(30_000)]);
  signal.throwIfAborted();
  const resolver = createLookup(inherited, signal);
  let tunnel: Duplex | undefined;
  let proxyRequest: http.ClientRequest | undefined;
  let request: http.ClientRequest | undefined;
  let tunnelAgent: https.Agent | undefined;
  const abort = (): void => {
    proxyRequest?.destroy(timeout());
    request?.destroy(timeout());
    tunnel?.destroy();
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    const target = new URL(prepared.origin);
    const proxyValue = process.env.FALCON_AXI_PROXY_URL;
    if (proxyValue) {
      const proxy = new URL(proxyValue);
      if (
        !["http:", "https:"].includes(proxy.protocol) ||
        proxy.pathname !== "/" ||
        proxy.search ||
        proxy.hash
      )
        throw new CliError("CONFIG_INVALID", "invalid proxy URL");
      tunnel = await new Promise<Duplex>((resolve, reject) => {
        proxyRequest = (proxy.protocol === "https:" ? https : http).request(
          proxy,
          {
            method: "CONNECT",
            lookup: resolver.lookup,
            path: `${target.hostname}:443`,
            agent: false,
            headers: {
              host: `${target.hostname}:443`,
              ...(proxy.username
                ? {
                    "proxy-authorization": `Basic ${Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64")}`,
                  }
                : {}),
            },
          },
        );
        proxyRequest.on("error", reject);
        proxyRequest.on("connect", (response, socket, head) => {
          if (response.statusCode !== 200 || head.length) {
            socket.destroy();
            reject(
              new CliError(
                "NETWORK_UNREACHABLE",
                "the proxy refused the Falcon tunnel",
              ),
            );
            return;
          }
          resolve(socket);
        });
        proxyRequest.end();
      });
    }
    if (signal.aborted) throw timeout();
    return await new Promise<Response>((resolve, reject) => {
      const socket = tunnel
        ? tls.connect({
            socket: tunnel,
            servername: target.hostname,
            rejectUnauthorized: true,
          })
        : undefined;
      socket?.on("error", reject);
      if (socket) {
        tunnelAgent = new https.Agent({ keepAlive: false });
        tunnelAgent.createConnection = () => socket;
      }
      request = https.request(
        {
          hostname: target.hostname,
          lookup: resolver.lookup,
          port: 443,
          method: prepared.method,
          path: prepared.path,
          headers: prepared.headers,
          agent: tunnelAgent ?? false,
        },
        (response) => {
          const chunks: Buffer[] = [];
          let bytes = 0;
          response.on("error", reject);
          response.on("aborted", () =>
            reject(
              new CliError(
                "NETWORK_UNREACHABLE",
                "the Falcon response was interrupted",
              ),
            ),
          );
          response.on("data", (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > 16 * 1024 * 1024) {
              request!.destroy(
                new CliError(
                  "UPSTREAM_ERROR",
                  "the Falcon response exceeded the acquisition limit",
                ),
              );
              return;
            }
            chunks.push(chunk);
          });
          response.on("end", () => {
            if (signal.aborted) {
              reject(timeout());
              return;
            }
            const headers: Record<string, string> = {};
            for (const [key, value] of Object.entries(response.headers))
              if (value !== undefined && key !== "location")
                headers[key] = Array.isArray(value) ? value.join(",") : value;
            let body: unknown = null;
            const text = Buffer.concat(chunks).toString("utf8");
            if (text) {
              try {
                body = parseResponse(text);
              } catch {
                /* Non-JSON errors retain status, never raw upstream text. */
              }
            }
            resolve({
              status: response.statusCode ?? 500,
              headers: Object.freeze(headers),
              body,
            });
          });
        },
      );
      request.on("error", reject);
      request.end(prepared.body);
    });
  } catch (error) {
    if (signal.aborted) throw timeout();
    throw failure(error);
  } finally {
    signal.removeEventListener("abort", abort);
    request?.destroy();
    proxyRequest?.destroy();
    tunnelAgent?.destroy();
    tunnel?.destroy();
    await resolver.close();
  }
}

async function acquire(
  prepared: Prepared,
  signal: AbortSignal,
): Promise<Response> {
  Object.freeze(prepared.headers);
  Object.freeze(prepared);
  permits.add(prepared);
  try {
    for (let attempt = 1; ; attempt++) {
      if (signal.aborted) throw timeout();
      const response = await send(prepared, signal);
      if (attempt >= 3 || ![429, 500, 502, 503, 504].includes(response.status))
        return response;
      const hint = Number(response.headers["x-ratelimit-retryafter"]);
      const retryAt = Math.ceil(hint * 1000);
      const wait =
        response.status === 429 && Number.isFinite(hint) && retryAt > Date.now()
          ? retryAt - Date.now()
          : Math.round(500 * 2 ** (attempt - 1) * (1 + Math.random()));
      try {
        await delay(wait, undefined, { signal });
        // Timers can wake before the wall-clock epoch supplied by Falcon.
        while (
          response.status === 429 &&
          Number.isFinite(retryAt) &&
          Date.now() < retryAt
        )
          await delay(Math.max(1, retryAt - Date.now()), undefined, { signal });
      } catch {
        throw timeout();
      }
    }
  } finally {
    permits.delete(prepared);
  }
}

export function requestToken(
  base: string,
  credential: { clientId: string; clientSecret: string; memberCid?: string },
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<Response> {
  if (credential.memberCid !== undefined && !credential.memberCid.trim())
    throw new CliError("VALIDATION_ERROR", "member CID must not be empty");
  const destination = origin(base, allowUnknown);
  const form = new URLSearchParams({
    client_id: credential.clientId,
    client_secret: credential.clientSecret,
  });
  if (credential.memberCid !== undefined)
    form.set("member_cid", credential.memberCid);
  const body = form.toString();
  return acquire(
    {
      origin: destination,
      method: "POST",
      path: "/oauth2/token",
      body,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(body)),
        "user-agent": `falcon-axi/${VERSION}`,
      },
    },
    signal,
  );
}
// Lifecycle operations retain their separate, undelivered authority gates.
const enabledReadOperations = new Set([
  "GetQueriesAlertsV2",
  "PostEntitiesAlertsV2",
  "PostAggregatesAlertsV2",
  "QueryDevicesByFilter",
  "PostDeviceDetailsV2",
  "QueryDeviceLoginHistoryV2",
  "QueryGetNetworkAddressHistoryV1",
  "highVolumeQueryChanges",
  "getChanges",
  "combined_summary_get",
  "combined_edges_get",
  "RTR_ListAllSessions",
  "RTR_ListSessions",
  "RTRAuditSessions",
  "indicator_search_v1",
  "indicator_get_v1",
  "DevicesRanOn",
  "ProcessesRanOn",
  "entities_processes",
  "query_iot_hostsV2",
  "get_iot_hosts",
  "GetSensorUsageWeekly",
  "queryCombinedHostGroups",
  "queryCombinedGroupMembers",
  "combined_hosts",
  "combined_applications",
  "get_hosts",
  "query_logins",
  "get_logins",
  "QuerySensorsByFilter",
  "GetSensorDetails",
  "query_accounts",
  "get_accounts",
  "GetCombinedVulnerabilitiesSARIF",
  "ReadContainerCombined",
  "ReadCombinedVulnerabilities",
  "GetSecurityChecksV3",
  "GetCombinedImages",
  "QueryVulnerabilities",
  "getVulnerabilities",
  "cloud_security_assets_queries",
  "cloud_security_assets_entities_get",
  "cspm_evaluations_iom_queries",
  "cspm_evaluations_iom_entities",
  "combined_cloud_risks",
  "combinedQueryVulnerabilities",
  "GetVulnerabilities",
]);

export function requestRead(
  id: string,
  base: string,
  token: string,
  query: Query,
  body: unknown,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<Response> {
  const descriptor = operation(id);
  if (!enabledReadOperations.has(descriptor.id) || descriptor.effect !== "read")
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "this operation is not available in the current slice",
    );
  const destination = origin(base, allowUnknown);
  if (descriptor.method === "GET" && body !== undefined)
    throw new CliError("READ_ONLY_VIOLATION", "read body is not allowed");
  if (
    [
      "PostDeviceDetailsV2",
      "QueryDeviceLoginHistoryV2",
      "QueryGetNetworkAddressHistoryV1",
      "RTR_ListSessions",
      "GetSensorDetails",
      "GetVulnerabilities",
    ].includes(id)
  ) {
    const maximum =
      id === "PostDeviceDetailsV2"
        ? 5000
        : id === "GetSensorDetails"
          ? 200
          : id === "RTR_ListSessions" || id === "GetVulnerabilities"
            ? 100
            : 1;
    if (
      !object(body) ||
      Object.keys(body).join() !== "ids" ||
      !Array.isArray(body.ids) ||
      !body.ids.length ||
      body.ids.length > maximum ||
      body.ids.some((value) => typeof value !== "string" || !value)
    )
      throw new CliError("READ_ONLY_VIOLATION", "invalid hydration authority");
  }
  if (
    id === "PostAggregatesAlertsV2" &&
    (!Array.isArray(body) ||
      body.length !== 1 ||
      !object(body[0]) ||
      body[0].name !== "severity" ||
      body[0].type !== "terms" ||
      body[0].field !== "severity_name" ||
      body[0].size !== 100 ||
      body[0].missing !== "unknown" ||
      Object.keys(body[0]).some(
        (key) =>
          !["name", "type", "field", "size", "missing", "filter"].includes(key),
      ))
  )
    throw new CliError("READ_ONLY_VIOLATION", "invalid aggregate authority");
  if (
    id === "GetQueriesAlertsV2" &&
    (body !== undefined ||
      Object.keys(query).some(
        (key) => !["filter", "limit", "offset"].includes(key),
      ))
  )
    throw new CliError("READ_ONLY_VIOLATION", "invalid query authority");
  if (
    id === "PostEntitiesAlertsV2" &&
    (Object.keys(query).length ||
      !object(body) ||
      Object.keys(body).join() !== "composite_ids" ||
      !Array.isArray(body.composite_ids) ||
      !body.composite_ids.length ||
      body.composite_ids.length > 1000 ||
      body.composite_ids.some((value) => typeof value !== "string" || !value))
  )
    throw new CliError("READ_ONLY_VIOLATION", "invalid hydration authority");
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query))
    for (const item of Array.isArray(value) ? value : [value])
      params.append(key, String(item));
  const serialized = body === undefined ? "" : JSON.stringify(body);
  return acquire(
    {
      origin: destination,
      method: descriptor.method,
      path:
        descriptor.path.replace("{vertex_type}", "processes") +
        (params.size ? `?${params}` : ""),
      body: serialized,
      headers: {
        authorization: `Bearer ${token}`,
        "user-agent": `falcon-axi/${VERSION}`,
        ...(serialized
          ? {
              "content-type": "application/json",
              "content-length": String(Buffer.byteLength(serialized)),
            }
          : {}),
      },
    },
    signal,
  );
}
