import { assertTrustedOrigin } from "../origin.js";
import { userAgent } from "../version.js";
import { mintPermit, sendPermittedRequest, type PreparedRequest } from "./network-sink.js";
import { operation, type OperationId } from "./operations.js";
import { MAX_ATTEMPTS, retryPlan } from "./retry.js";
import type { FalconResponse, OAuthTokenArgs, RequestArgs, Transport } from "./types.js";

const OAUTH_PATH = "/oauth2/token";

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function send(request: PreparedRequest): Promise<FalconResponse> {
  const permit = mintPermit();
  for (let attempt = 1; ; attempt++) {
    const response = await sendPermittedRequest(request, permit);
    const plan = attempt < MAX_ATTEMPTS ? retryPlan(response.status, response.headers, attempt, Date.now()) : undefined;
    if (!plan) return response;
    await sleep(plan.waitMs);
  }
}

function queryString(query: Readonly<Record<string, string | number>> | undefined): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) params.set(key, String(value));
  const text = params.toString();
  return text ? `?${text}` : "";
}

/**
 * Issues one registered read operation (docs/design/v1.md §3.3).
 * The caller supplies an operation id, never a method, path, or URL; the descriptor is resolved
 * from the frozen registry, and the destination is re-validated on every operation (§6.3).
 */
async function request(id: OperationId, args: RequestArgs): Promise<FalconResponse> {
  const descriptor = operation(id);
  const origin = assertTrustedOrigin(args.baseUrl, args.allowUnknownOrigin);
  const headers: Record<string, string> = {
    accept: "application/json",
    authorization: `Bearer ${args.token}`,
    "user-agent": userAgent(),
  };
  const body = args.body === undefined ? undefined : JSON.stringify(args.body);
  if (body !== undefined) headers["content-type"] = "application/json";
  return send({
    url: `${origin}${descriptor.path}${queryString(args.query)}`,
    method: descriptor.method,
    headers,
    body,
  });
}

/**
 * The separately sealed authentication path (§3.3, §5.1).
 * Its method and path are fixed, it cannot issue a scoped operation, and it does not pass through
 * `request`, because authentication is not one of the registered read operations.
 */
async function requestOAuthToken(args: OAuthTokenArgs): Promise<FalconResponse> {
  const origin = assertTrustedOrigin(args.baseUrl, args.allowUnknownOrigin);
  const form = new URLSearchParams({ client_id: args.clientId, client_secret: args.clientSecret });
  if (args.memberCid) form.set("member_cid", args.memberCid);
  return send({
    url: `${origin}${OAUTH_PATH}`,
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      "user-agent": userAgent(),
    },
    body: form.toString(),
  });
}

/** The only transport the shipped binary contains (§14.2). */
export const httpTransport: Transport = Object.freeze({ request, requestOAuthToken });

export type { FalconResponse, OAuthTokenArgs, RequestArgs, Transport } from "./types.js";
export type { OperationId } from "./operations.js";
