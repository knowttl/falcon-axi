import { CliError } from "./core.js";
import type { Credential } from "./credentials.js";
import { translateFalconError } from "./falcon-error.js";
import { REGIONS, regionOf } from "./origin.js";
import type { FalconResponse, Transport } from "./transport/types.js";

export type RateLimit = Readonly<{ limit?: number; remaining?: number }>;

export type Session = Readonly<{
  token: string;
  baseUrl: string;
  region?: string;
  retargetedFrom?: string;
  memberCid?: string;
  allowUnknownOrigin: boolean;
  rateLimit: RateLimit;
}>;

export type AuthOptions = Readonly<{
  credential: Credential;
  baseUrl: string;
  memberCid?: string;
  allowUnknownOrigin?: boolean;
}>;

export function rateLimitOf(response: FalconResponse): RateLimit {
  const read = (name: string): number | undefined => {
    const value = Number(response.headers[name]);
    return Number.isFinite(value) ? value : undefined;
  };
  return { limit: read("x-ratelimit-limit"), remaining: read("x-ratelimit-remaining") };
}

function tokenOf(response: FalconResponse): string {
  const token = (response.body as { access_token?: unknown } | undefined)?.access_token;
  if (typeof token !== "string" || !token) {
    throw new CliError("UPSTREAM_ERROR", "the Falcon token response carried no access token", [
      "Retry shortly",
      "Run `falcon-axi auth status` to re-check the credential",
    ]);
  }
  return token;
}

function tokenFailure(response: FalconResponse, memberCid: string | undefined): CliError {
  if (response.status === 401) {
    return new CliError("AUTH_FAILED", "the Falcon credential was rejected", [
      "The client ID or secret is wrong, or the API client was revoked",
    ]);
  }
  if (response.status === 403) {
    if (memberCid) {
      return new CliError("TENANT_DENIED", "the selected member CID was refused for this credential", [
        "Verify this is a valid child CID in the Falcon console and not the parent CID itself",
        "Or retry with `--no-member-cid` to authenticate as the credential's own CID",
      ]);
    }
    return new CliError("AUTH_FAILED", "the Falcon credential was refused", [
      "The API client has no scopes granted, or is disabled",
      "Grant `Alerts:read` (read only) in the Falcon console under Support and resources > API clients and keys",
    ]);
  }
  return translateFalconError(response, "GetQueriesAlertsV2", "the Falcon token endpoint");
}

/**
 * Mints a bearer token for this invocation (docs/design/v1.md §5.1, §5.4).
 * The token is never persisted, and region autodiscovery re-targets at most once on the
 * `X-Cs-Region` header Falcon returns with the token (§6.4).
 */
export async function authenticate(transport: Transport, options: AuthOptions): Promise<Session> {
  const allowUnknownOrigin = Boolean(options.allowUnknownOrigin);
  const mint = (baseUrl: string): Promise<FalconResponse> =>
    transport.requestOAuthToken({
      baseUrl,
      clientId: options.credential.clientId,
      clientSecret: options.credential.clientSecret,
      memberCid: options.memberCid,
      allowUnknownOrigin,
    });

  let baseUrl = options.baseUrl;
  let response = await mint(baseUrl);
  if (response.status !== 200 && response.status !== 201) throw tokenFailure(response, options.memberCid);

  let retargetedFrom: string | undefined;
  const observed = response.headers["x-cs-region"];
  const current = regionOf(baseUrl);
  if (observed && current && observed !== current) {
    const target = REGIONS[observed];
    if (!target) {
      throw new CliError("REGION_MISMATCH", `this credential belongs to Falcon region ${observed}`, [
        `falcon-axi has no verified base URL for ${observed}`,
        "Supply a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
      ], { observed_region: observed });
    }
    retargetedFrom = current;
    baseUrl = target;
    response = await mint(baseUrl);
    if (response.status !== 200 && response.status !== 201) throw tokenFailure(response, options.memberCid);
  }

  return {
    token: tokenOf(response),
    baseUrl,
    region: regionOf(baseUrl),
    retargetedFrom,
    memberCid: options.memberCid,
    allowUnknownOrigin,
    rateLimit: rateLimitOf(response),
  };
}
