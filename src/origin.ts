import { CliError } from "./core.js";

/** The verified Falcon clouds (docs/design/v1.md §6.1). Not necessarily the complete set (§17.3). */
export const REGIONS: Readonly<Record<string, string>> = Object.freeze({
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
});

export const DEFAULT_REGION = "us-1";

const TRUSTED_HOSTS = new Set(Object.values(REGIONS).map(url => new URL(url).host));
const TRUSTED_PARENTS = ["crowdstrike.com", "gcw.crowdstrike.com"];

export type InvalidComponent = "scheme" | "userinfo" | "port" | "path" | "query" | "fragment" | "host" | "redirect";

/**
 * Refuses an untrusted destination before any credential or token is sent (§6.3).
 * The rejected URL and every component value stay out of the message, because an arbitrary query
 * key can carry a secret that key-based redaction would not recognize (§5.5).
 */
function refuse(component: InvalidComponent): CliError {
  return new CliError(
    "ORIGIN_NOT_ALLOWED",
    "the resolved Falcon base URL is not a trusted destination",
    [
      `Use a documented region with \`--region\` (${Object.keys(REGIONS).join(" ")})`,
      "Allowed hosts are the documented Falcon clouds and subdomains of crowdstrike.com or gcw.crowdstrike.com",
      "Pass `--allow-unknown-origin` in the same invocation to reach a deliberately selected unknown Falcon cloud",
    ],
    { invalid_component: component },
  );
}

function hostAllowed(host: string): boolean {
  if (TRUSTED_HOSTS.has(host)) return true;
  return TRUSTED_PARENTS.some(parent => host === parent || host.endsWith(`.${parent}`));
}

/**
 * Validates a base URL and returns its canonical origin.
 * `allowUnknownOrigin` relaxes only the host allowlist; every other rule still applies (§6.3).
 */
export function assertTrustedOrigin(baseUrl: string, allowUnknownOrigin = false): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw refuse("scheme");
  }
  if (url.protocol !== "https:") throw refuse("scheme");
  if (url.username || url.password) throw refuse("userinfo");
  if (url.port) throw refuse("port");
  if (url.pathname !== "/") throw refuse("path");
  if (url.search) throw refuse("query");
  if (url.hash) throw refuse("fragment");
  if (!allowUnknownOrigin && !hostAllowed(url.host)) throw refuse("host");
  return url.origin;
}

/** The short name of a base URL, when it is one of the verified clouds. */
export function regionOf(baseUrl: string): string | undefined {
  return Object.entries(REGIONS).find(([, url]) => url === baseUrl)?.[0];
}

/**
 * Region precedence: `--region`, then FALCON_BASE_URL, then the default cloud (§6.2).
 * Profile configuration is not implemented in stage 1; see README.
 */
export function resolveBaseUrl(options: Readonly<{ region?: string; envBaseUrl?: string }>): string {
  const { region, envBaseUrl } = options;
  if (region !== undefined) {
    const known = REGIONS[region];
    if (known) return known;
    if (region.includes("://")) return region;
    throw new CliError("VALIDATION_ERROR", `unknown region ${region}`, [
      `valid regions: ${Object.keys(REGIONS).join(", ")}`,
      "Or pass a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
    ]);
  }
  if (envBaseUrl) return envBaseUrl;
  return REGIONS[DEFAULT_REGION] as string;
}
