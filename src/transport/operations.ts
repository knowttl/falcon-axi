import { CliError } from "../core.js";

/**
 * The complete scoped-operation surface of falcon-axi v1 (docs/design/v1.md §2.1, §3.3).
 * The union is closed: adding a member requires both §2.2 citations in the same change.
 */
export type OperationId =
  | "GetQueriesAlertsV2"
  | "PostEntitiesAlertsV2"
  | "QueryDevicesByFilter"
  | "PostDeviceDetailsV2"
  | "combinedQueryVulnerabilities";

export type FalconOperation = Readonly<{
  id: OperationId;
  method: "GET" | "POST";
  path: string;
  scopes: readonly string[];
  effect: "read";
  evidence: Readonly<{ docUrl: string; docScope: string; falconMcp: string }>;
}>;

const ALERTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/alerts/";
const HOSTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/hosts/";
const SPOTLIGHT_DOC = "https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/";

const CANONICAL: readonly FalconOperation[] = [
  {
    id: "GetQueriesAlertsV2",
    method: "GET",
    path: "/alerts/queries/alerts/v2",
    scopes: ["Alerts:read"],
    effect: "read",
    evidence: {
      docUrl: ALERTS_DOC,
      docScope: "Alerts: READ",
      falconMcp: "falcon_mcp/common/api_scopes.py maps GetQueriesAlertsV2 to Alerts:read for search_detections",
    },
  },
  {
    id: "PostEntitiesAlertsV2",
    method: "POST",
    path: "/alerts/entities/alerts/v2",
    scopes: ["Alerts:read"],
    effect: "read",
    evidence: {
      docUrl: ALERTS_DOC,
      docScope: "Alerts: READ",
      falconMcp: "falcon_mcp/common/api_scopes.py maps PostEntitiesAlertsV2 to Alerts:read as the hydrate step of search_detections",
    },
  },
  {
    id: "QueryDevicesByFilter",
    method: "GET",
    path: "/devices/queries/devices/v1",
    scopes: ["Hosts:read"],
    effect: "read",
    evidence: {
      docUrl: HOSTS_DOC,
      docScope: "Hosts: READ",
      falconMcp: "falcon_mcp/common/api_scopes.py maps QueryDevicesByFilter to Hosts:read for search_hosts",
    },
  },
  {
    id: "PostDeviceDetailsV2",
    method: "POST",
    path: "/devices/entities/devices/v2",
    scopes: ["Hosts:read"],
    effect: "read",
    evidence: {
      docUrl: HOSTS_DOC,
      docScope: "Hosts: READ",
      falconMcp: "falcon_mcp/common/api_scopes.py maps PostDeviceDetailsV2 to Hosts:read for search_hosts and get_host_details",
    },
  },
  {
    id: "combinedQueryVulnerabilities",
    method: "GET",
    path: "/spotlight/combined/vulnerabilities/v1",
    scopes: ["Vulnerabilities:read"],
    effect: "read",
    evidence: {
      docUrl: SPOTLIGHT_DOC,
      docScope: "Vulnerabilities: READ",
      falconMcp: "falcon_mcp/common/api_scopes.py maps combinedQueryVulnerabilities to Vulnerabilities:read for search_vulnerabilities",
    },
  },
];

/** Routes whose shape marks a Falcon mutation; no registered operation may match one (§3.3 property 5). */
export const MUTATION_ROUTE_PATTERNS: readonly RegExp[] = [
  /\/entities\/[^/]+\/action/i,
  /\/queries\/[^/]+\/action/i,
  /\/real-time-response\//i,
];

function seal(input: FalconOperation): FalconOperation {
  if (input.effect !== "read") throw new Error(`operation ${input.id} is not a read`);
  if (input.method !== "GET" && input.method !== "POST") throw new Error(`operation ${input.id} has an unsupported method`);
  if (!input.path.startsWith("/")) throw new Error(`operation ${input.id} has a malformed path`);
  if (!input.scopes.length) throw new Error(`operation ${input.id} declares no scope`);
  if (!input.evidence.docUrl || !input.evidence.docScope || !input.evidence.falconMcp) throw new Error(`operation ${input.id} is missing evidence`);
  if (!/:\s*READ$/i.test(input.evidence.docScope)) throw new Error(`operation ${input.id} does not cite a read scope`);
  if (MUTATION_ROUTE_PATTERNS.some(pattern => pattern.test(input.path))) throw new Error(`operation ${input.id} matches a known mutation route`);
  return Object.freeze({
    id: input.id,
    method: input.method,
    path: input.path,
    scopes: Object.freeze([...input.scopes]),
    effect: "read",
    evidence: Object.freeze({ ...input.evidence }),
  });
}

/** The frozen registry. Every descriptor, its `scopes` array, its `evidence`, and this record are immutable. */
export const OPERATIONS: Readonly<Record<OperationId, FalconOperation>> = Object.freeze(
  Object.fromEntries(CANONICAL.map(entry => [entry.id, seal(entry)])) as Record<OperationId, FalconOperation>,
);

/**
 * Resolves the canonical descriptor for an operation id.
 * Deny by default: an id that is not an own key of the registry, or a descriptor whose own id
 * disagrees with its key, fails with READ_ONLY_VIOLATION before any request is prepared.
 */
export function operation(id: OperationId): FalconOperation {
  const resolved = Object.prototype.hasOwnProperty.call(OPERATIONS, id) ? OPERATIONS[id] : undefined;
  if (!resolved || resolved.id !== id || resolved.effect !== "read") {
    throw new CliError("READ_ONLY_VIOLATION", `operation ${String(id)} is not a registered falcon-axi read operation`, [
      "falcon-axi issues only the read operations in its closed registry; report this as a bug",
    ]);
  }
  return resolved;
}

/** The read scopes the registered operations require, for operator provisioning (§5.7). */
export function registeredScopes(ids: readonly OperationId[]): readonly string[] {
  return [...new Set(ids.flatMap(id => operation(id).scopes))].sort();
}
