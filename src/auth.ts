import { CliError, object } from "./core.js";
import { malformed } from "./response.js";
import type { Credential } from "./credentials.js";
import { REGIONS } from "./origin.js";
import { registerSecret } from "./render.js";
import { requestToken } from "./transport/https.js";
import type { Response } from "./transport/https.js";
import { operation } from "./transport/operations.js";

export function responseFailure(
  response: Response,
  subject: string,
  token = false,
  member = false,
  operationId = "GetQueriesAlertsV2",
): never {
  const scopes = operation(operationId).scopes;
  const envelope = object(response.body) ? response.body : {};
  const meta = object(envelope.meta) ? envelope.meta : {};
  const details =
    typeof meta.trace_id === "string" ? { trace_id: meta.trace_id } : {};
  if (response.status === 400) {
    const remedy: Readonly<Record<string, readonly [string, string]>> = {
      query_accounts: ["account list", "username:'synthetic-user'"],
      get_accounts: ["account list", "username:'synthetic-user'"],
      GetSensorUsageWeekly: ["sensor-usage list", "period:'30'"],
      combined_hosts: ["asset list", "entity_type:'managed'"],
      get_hosts: ["asset list", "entity_type:'managed'"],
      combined_applications: ["application list", "name:'Chrome'"],
      query_logins: ["login list", "login_status:'Failed'"],
      get_logins: ["login list", "login_status:'Failed'"],
      queryCombinedHostGroups: ["host-group list", "group_type:'dynamic'"],
      queryCombinedGroupMembers: [
        "host-group members",
        "platform_name:'Windows'",
      ],
      query_iot_hostsV2: ["iot list", "device_type:'Printer'"],
      get_iot_hosts: ["iot list", "device_type:'Printer'"],
      QuerySensorsByFilter: [
        "identity sensor list",
        "hostname:'SYNTH-DC-01'+status:'healthy'",
      ],
      GetSensorDetails: [
        "identity sensor list",
        "hostname:'SYNTH-DC-01'+status:'healthy'",
      ],
      cloud_security_assets_queries: [
        "cloud-asset list",
        "cloud_provider:'aws'",
      ],
      cloud_security_assets_entities_get: [
        "cloud-asset list",
        "cloud_provider:'aws'",
      ],
      cspm_evaluations_iom_queries: [
        "iom list",
        "severity:'critical'+status:'non-compliant'",
      ],
      cspm_evaluations_iom_entities: [
        "iom list",
        "severity:'critical'+status:'non-compliant'",
      ],
      combined_cloud_risks: [
        "cloud-risk list",
        "severity:'Critical'+status:'Open'",
      ],
      QueryVulnerabilities: ["cve list", "severity:'CRITICAL'"],
      GetVulnerabilities: ["cve list", "severity:'CRITICAL'"],
      getVulnerabilities: ["vuln list", "status:'open'"],
      combinedQueryVulnerabilities: ["vuln list", "status:'open'"],
      ReadContainerCombined: ["container list", "namespace:'production'"],
      GetCombinedImages: ["image list", "repository:'example/service'"],
      ReadCombinedVulnerabilities: ["image vulnerabilities", "cvss_score:>7"],
      GetCombinedVulnerabilitiesSARIF: [
        "serverless list",
        "cloud_provider:'aws'",
      ],
      highVolumeQueryChanges: [
        "file-change list",
        "host.name:'SYNTHETIC-HOST'",
      ],
      getChanges: ["file-change list", "host.name:'SYNTHETIC-HOST'"],
      RTR_ListAllSessions: ["rtr session list", "hostname:'SYNTHETIC-*'"],
      RTR_ListSessions: ["rtr session list", "hostname:'SYNTHETIC-*'"],
      RTRAuditSessions: ["rtr audit list", "created_at:>'now-7d'"],
      indicator_search_v1: ["ioc list", "type:'domain'"],
      indicator_get_v1: ["ioc list", "type:'domain'"],
    };
    const [command, example] =
      remedy[operationId] ??
      (scopes.includes("Hosts:read")
        ? ["host list", "hostname:'WIN-*'"]
        : ["detection list", "severity_name:'High'+status:'new'"]);
    const errors = Array.isArray(envelope.errors) ? envelope.errors : [];
    if (
      errors.some(
        (error) =>
          object(error) &&
          typeof error.message === "string" &&
          /\b(fql|filter|query)\b/i.test(error.message),
      )
    )
      throw new CliError(
        "FQL_INVALID",
        `the filter for ${subject} was rejected`,
        [
          "FQL uses + for AND, `,` for OR, and values must be quoted",
          `Example: \`--filter "${example}"\``,
          `Run \`falcon-axi ${command} --help\` for the filterable fields`,
        ],
      );
    throw new CliError(
      "UPSTREAM_ERROR",
      `Falcon rejected the request for ${subject}`,
      ["Check the flags for this command with `--help`"],
      details,
    );
  }
  if (response.status === 401)
    throw new CliError("AUTH_FAILED", "the Falcon credential was rejected", [
      "The client ID or secret is wrong, or the API client was revoked",
      ...(!token
        ? ["Run `falcon-axi auth status` after updating the credential"]
        : []),
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
    const licences: Readonly<Record<string, string>> = {
      "Assets:read": "Falcon Discover or Exposure Management",
      "Sandbox (Falcon Intelligence):read": "Falcon Intelligence (Sandbox)",
      "Device Control Policies:read": "Falcon Device Control",
      "Falcon FileVantage:read": "Falcon FileVantage",
      "Threatgraph:read":
        "a Falcon subscription with ThreatGraph API access enabled",
      "Real time response:read":
        "a Falcon subscription with Real Time Response enabled",
      "Real time response audit:read":
        "a Falcon subscription with Real Time Response audit enabled",
    };
    throw new CliError(
      "SCOPE_DENIED",
      `this API client is not permitted to read ${subject}`,
      [
        `Grant ${scopes.join(" and ")} (read only) to the API client in the Falcon console under Support and resources > API clients and keys`,
        ...scopes
          .filter((scope) => licences[scope])
          .map(
            (scope) =>
              `${scope} needs ${licences[scope]}; if the scope is absent from the picker, the tenant lacks that subscription`,
          ),
        ...(operationId === "entities_processes"
          ? [
              "Process details may be unavailable under this tenant's subscription or API client permissions",
            ]
          : []),
        "A 403 can also mean the API client is disabled",
      ],
      { required_scopes: [...scopes] },
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
      details,
    );
  throw new CliError(
    "UPSTREAM_ERROR",
    `Falcon could not answer the request for ${subject}`,
    [
      "Retry shortly",
      "Quote the trace_id when opening a CrowdStrike support case",
    ],
    details,
  );
}
export interface Session {
  token: string;
  base: string;
  rateLimit?: number;
  remaining?: number;
}
export function observeRate(session: Session, response: Response): void {
  for (const [header, field] of [
    ["x-ratelimit-limit", "rateLimit"],
    ["x-ratelimit-remaining", "remaining"],
  ] as const) {
    const value = response.headers[header];
    if (
      value !== undefined &&
      /^\d+$/.test(value) &&
      Number.isSafeInteger(Number(value))
    )
      session[field] = Number(value);
  }
}
export async function authenticate(
  credential: Credential,
  base: string,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<Session> {
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
        `this credential belongs to Falcon region ${observed}`,
        [
          `falcon-axi has no verified base URL for ${observed}`,
          "Supply a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
        ],
        { observed_region: observed },
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
  const session: Session = { token, base };
  observeRate(session, response);
  return session;
}
