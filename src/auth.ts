import { CliError, object } from "./core.js";
import { malformed } from "./response.js";
import type { Credential } from "./credentials.js";
import { REGIONS } from "./origin.js";
import { registerSecret } from "./render.js";
import { requestToken } from "./transport/https.js";
import type { Response } from "./transport/https.js";

export function responseFailure(
  response: Response,
  subject: string,
  token = false,
  member = false,
): never {
  if (response.status === 401)
    throw new CliError("AUTH_FAILED", "the Falcon credential was rejected", [
      "The client ID or secret is wrong, or the API client was revoked",
    ]);
  if (response.status === 403) {
    if (token && member)
      throw new CliError(
        "TENANT_DENIED",
        "the selected member CID was refused for this credential",
        [
          "Verify this is a valid child CID in the Falcon console and not the parent CID itself",
          "Or retry with `--no-member-cid` to authenticate as the credential's own CID",
        ],
      );
    if (token)
      throw new CliError("AUTH_FAILED", "the Falcon credential was refused", [
        "The API client has no scopes granted, or is disabled",
        "Grant `Alerts:read` (read only) in the Falcon console under Support and resources > API clients and keys",
      ]);
    throw new CliError(
      "SCOPE_DENIED",
      `this API client is not permitted to read ${subject}`,
      [
        "Grant Alerts:read (read only) to the API client in the Falcon console under Support and resources > API clients and keys",
        "A 403 can also mean the API client is disabled",
      ],
      { required_scopes: ["Alerts:read"] },
    );
  }
  if (response.status === 429)
    throw new CliError("RATE_LIMITED", "Falcon rate limited this API client", [
      "Wait for the rate limit window to reset and retry",
      "Narrow the FQL filter or lower `--limit` to issue fewer requests",
    ]);
  if ([502, 503, 504].includes(response.status))
    throw new CliError(
      "UPSTREAM_UNAVAILABLE",
      "Falcon is temporarily unavailable",
      [
        "Retry shortly",
        "Quote the trace_id when opening a CrowdStrike support case",
      ],
    );
  throw new CliError(
    "UPSTREAM_ERROR",
    `Falcon could not answer the request for ${subject}`,
    [
      "Retry shortly",
      "Quote the trace_id when opening a CrowdStrike support case",
    ],
  );
}
export async function authenticate(
  credential: Credential,
  base: string,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<{ token: string; base: string }> {
  let response = await requestToken(base, credential, allowUnknown, signal);
  const current = Object.keys(REGIONS).find((key) => REGIONS[key] === base);
  const observed = response.headers["x-cs-region"];
  const redirect = (): never => {
    throw new CliError(
      "ORIGIN_NOT_ALLOWED",
      "the Falcon endpoint answered with a redirect and no credential was replayed",
      ["Supply a verified Falcon base URL with `--region <url>`"],
      { invalid_component: "redirect" },
    );
  };
  if (
    (response.status >= 300 && response.status < 400) ||
    ([200, 201].includes(response.status) &&
      observed &&
      current &&
      observed !== current)
  ) {
    if (!observed) redirect();
    if (!Object.hasOwn(REGIONS, observed!))
      throw new CliError(
        "REGION_MISMATCH",
        "this credential belongs to an unverified Falcon region",
        [
          "Supply a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
        ],
      );
    const target = REGIONS[observed!]!;
    if (target === base) redirect();
    base = target;
    response = await requestToken(base, credential, allowUnknown, signal);
    if (response.status >= 300 && response.status < 400) redirect();
  }
  if (![200, 201].includes(response.status))
    responseFailure(
      response,
      "the Falcon token endpoint",
      true,
      Boolean(credential.memberCid),
    );
  if (
    !object(response.body) ||
    typeof response.body.access_token !== "string" ||
    !response.body.access_token
  )
    malformed(response, "the Falcon token response carried no access token", [
      "Retry shortly",
    ]);
  const token = response.body.access_token;
  registerSecret(token);
  return { token, base };
}
