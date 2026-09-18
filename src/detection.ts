import type { Session } from "./auth.js";
import { CliError } from "./core.js";
import type { Credential } from "./credentials.js";
import { encodeCursor, decodeCursor, type CursorContext } from "./cursor.js";
import { translateFalconError } from "./falcon-error.js";
import { describeDetectionQuery, detectionFilter, type DetectionQuery } from "./fql.js";
import { raw, truncate } from "./render.js";
import type { FalconResponse, Transport } from "./transport/types.js";

/** Documented Alerts limits (docs/design/v1.md §7.3, §2.3). */
export const DEFAULT_LIMIT = 20;
export const QUERY_CEILING = 10_000;
export const HYDRATE_CHUNK = 1_000;
/** v1's defensive Alerts result stop; unverified and open in §17.12. */
export const ALERTS_WALL = 10_000;

export type CommandOutput = Readonly<{ value: Record<string, unknown>; help: readonly string[] }>;

export type ListOptions = Readonly<{
  query: DetectionQuery;
  limit: number;
  cursor?: string;
  credential: Credential;
  /** The invocation replayed for a next-page suggestion, without any sensitive value (§7.2). */
  suggestion: string;
  rows?: number;
}>;

type Alert = Readonly<Record<string, unknown>>;

function resources(response: FalconResponse): unknown[] {
  const list = (response.body as { resources?: unknown } | undefined)?.resources;
  return Array.isArray(list) ? list : [];
}

function total(response: FalconResponse): number | undefined {
  const meta = (response.body as { meta?: { pagination?: { total?: unknown } } } | undefined)?.meta;
  const value = meta?.pagination?.total;
  return typeof value === "number" ? value : undefined;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function hostnameOf(alert: Alert): string | undefined {
  const device = alert.device as Record<string, unknown> | undefined;
  return text(device?.hostname) ?? text(alert.hostname);
}

function deviceIdOf(alert: Alert): string | undefined {
  const device = alert.device as Record<string, unknown> | undefined;
  return text(device?.device_id) ?? text(alert.device_id) ?? text(alert.agent_id);
}

function idOf(alert: Alert): string {
  return text(alert.composite_id) ?? text(alert.id) ?? "";
}

function severityOf(alert: Alert): string {
  const name = text(alert.severity_name) ?? "unknown";
  return typeof alert.severity === "number" ? `${name} (${alert.severity})` : name;
}

async function queryAlertIds(
  transport: Transport,
  session: Session,
  args: Readonly<{ filter?: string; limit: number; offset: number }>,
): Promise<{ ids: string[]; total?: number }> {
  const query: Record<string, string | number> = { limit: args.limit, offset: args.offset };
  if (args.filter) query.filter = args.filter;
  const response = await transport.request("GetQueriesAlertsV2", {
    baseUrl: session.baseUrl,
    token: session.token,
    allowUnknownOrigin: session.allowUnknownOrigin,
    query,
  });
  if (response.status !== 200) throw translateFalconError(response, "GetQueriesAlertsV2", "detections");
  return { ids: resources(response).filter((id): id is string => typeof id === "string"), total: total(response) };
}

/**
 * Hydrates composite ids into alert records (§2.3).
 * The hydrate cap is smaller than the query cap, so the step is chunked, and the query-step order
 * is reapplied because an entity endpoint may return resources in arbitrary order.
 */
async function hydrateAlerts(transport: Transport, session: Session, ids: readonly string[]): Promise<Alert[]> {
  const byId = new Map<string, Alert>();
  for (let index = 0; index < ids.length; index += HYDRATE_CHUNK) {
    const chunk = ids.slice(index, index + HYDRATE_CHUNK);
    const response = await transport.request("PostEntitiesAlertsV2", {
      baseUrl: session.baseUrl,
      token: session.token,
      allowUnknownOrigin: session.allowUnknownOrigin,
      body: { composite_ids: chunk },
    });
    if (response.status !== 200) throw translateFalconError(response, "PostEntitiesAlertsV2", "detections");
    for (const entry of resources(response)) {
      const alert = entry as Alert;
      const id = idOf(alert);
      if (id) byId.set(id, alert);
    }
  }
  return ids.map(id => byId.get(id)).filter((alert): alert is Alert => alert !== undefined);
}

function cursorContext(session: Session, credential: Credential, filter: string | undefined): CursorContext {
  return {
    operation: "GetQueriesAlertsV2",
    clientId: credential.clientId,
    query: filter,
    origin: session.baseUrl,
    memberCid: session.memberCid,
  };
}

function rateLimitNote(session: Session): string | undefined {
  const { limit, remaining } = session.rateLimit;
  if (limit === undefined || remaining === undefined || limit <= 0) return undefined;
  return remaining < limit * 0.1 ? `${remaining} of ${limit} requests remaining in this rate limit window` : undefined;
}

/** `detection list`: query ids, hydrate them, and render the four-field schema (§10.2). */
export async function listDetections(transport: Transport, session: Session, options: ListOptions): Promise<CommandOutput> {
  const filter = detectionFilter(options.query);
  const context = cursorContext(session, options.credential, filter);
  const offset = options.cursor === undefined ? 0 : decodeCursor(options.cursor, context, options.credential.clientSecret);
  const headroom = ALERTS_WALL - offset;
  if (headroom <= 0) {
    throw new CliError("PAGINATION_LIMIT", `this read reached the ${ALERTS_WALL} result boundary falcon-axi enforces for Alerts`, [
      `Narrow the filter so the result set fits under ${ALERTS_WALL}, for example by shortening \`--since\` or adding \`--severity\``,
      "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` pagination, which falcon-axi v1 does not register",
    ]);
  }
  const limit = Math.min(options.limit, headroom);
  const query = await queryAlertIds(transport, session, { filter, limit, offset });
  const describe = describeDetectionQuery(options.query);

  if (!query.ids.length) {
    const emptyHelp = options.query.since
      ? [`Run \`${options.suggestion} --since 7d\` to widen the window`]
      : ["Run `falcon-axi detection list` without filters to see what is firing"];
    return {
      value: { detections: raw(describe ? `0 detections matching ${describe}` : "0 detections in this tenant") },
      help: emptyHelp,
    };
  }

  const alerts = await hydrateAlerts(transport, session, query.ids);
  const rows = alerts.map(alert => ({
    id: idOf(alert),
    severity: text(alert.severity_name) ?? "unknown",
    tactic: text(alert.tactic) ?? "unknown",
    hostname: hostnameOf(alert) ?? "unknown",
  }));
  const shown = options.rows === undefined ? rows : rows.slice(0, options.rows);
  const next = offset + query.ids.length;
  const moreRemain = query.total === undefined ? query.ids.length >= limit : next < query.total;
  const reachable = moreRemain && next < ALERTS_WALL;

  const help: string[] = ["Run `falcon-axi detection show <id>` for the full detection"];
  const value: Record<string, unknown> = {
    count: raw(`${shown.length} of ${query.total ?? "unknown"} total`),
  };
  if (reachable) {
    value.continuation_cursor = encodeCursor(next, context, options.credential.clientSecret);
    help.push(`Run \`${options.suggestion} --cursor ${String(value.continuation_cursor)}\` for the next page`);
    if (session.memberCid) help.push("Supply the same tenant selection used for this invocation when continuing");
  } else if (moreRemain) {
    help.push(
      `Narrow the filter so the result set fits under ${ALERTS_WALL}, for example by shortening \`--since\` or adding \`--severity\``,
      "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` pagination, which falcon-axi v1 does not register, so those rows are not reachable through this CLI",
    );
  }
  value.detections = shown;
  const note = rateLimitNote(session);
  if (note) value.rate_limit = raw(note);
  return { value, help };
}

/** `detection show <id>`: hydrate one composite id into the detail view (§10.4). */
export async function showDetection(
  transport: Transport,
  session: Session,
  id: string,
  full: boolean,
): Promise<CommandOutput> {
  const [alert] = await hydrateAlerts(transport, session, [id]);
  if (!alert) {
    throw new CliError("NOT_FOUND", "no detection matched that identifier", [
      "Run `falcon-axi detection list` to see current detection identifiers",
      "A composite id looks like `ldt:<agent id>:<detection id>`",
    ]);
  }
  const cmdline = text(alert.cmdline);
  const rendered = cmdline === undefined ? undefined : full ? { text: cmdline, truncated: false } : truncate(cmdline);
  const help: string[] = [];
  if (rendered?.truncated) help.push(`Run \`falcon-axi detection show ${id} --full\` to see the complete command line`);
  const device = deviceIdOf(alert);
  return {
    value: {
      detection: {
        id: idOf(alert),
        severity: severityOf(alert),
        tactic: text(alert.tactic) ?? "unknown",
        technique: text(alert.technique) ?? "unknown",
        hostname: hostnameOf(alert) ?? "unknown",
        ...(device ? { device_id: device } : {}),
        status: text(alert.status) ?? "unknown",
        first_seen: text(alert.created_timestamp) ?? "unknown",
        ...(rendered ? { cmdline: rendered.text } : {}),
      },
    },
    help,
  };
}
