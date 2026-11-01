import { createHmac, timingSafeEqual } from "node:crypto";
import { CliError, object } from "./core.js";
import { malformed } from "./response.js";
import type { Credential } from "./credentials.js";
import { responseFailure } from "./auth.js";
import { Raw } from "./render.js";
import { requestRead } from "./transport/https.js";

export async function listDetections(
  credential: Credential,
  session: { token: string; base: string },
  limit: number,
  filter: string | undefined,
  cursor: string | undefined,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<{ value: Record<string, unknown>; help: string[] }> {
  const fingerprint = (position: number): string =>
    createHmac("sha256", credential.clientSecret)
      .update(
        JSON.stringify({
          client_id: credential.clientId,
          member_cid: credential.memberCid ?? null,
          model: "offset",
          operation: "GetQueriesAlertsV2",
          origin: session.base,
          position,
          query: filter ?? null,
          sort: null,
        }),
      )
      .digest("hex");
  let offset = 0;
  if (cursor) {
    try {
      const payload: unknown = JSON.parse(
        Buffer.from(cursor, "base64url").toString("utf8"),
      );
      if (
        !object(payload) ||
        payload.operation !== "GetQueriesAlertsV2" ||
        payload.model !== "offset" ||
        !Number.isSafeInteger(payload.position) ||
        (payload.position as number) < 0 ||
        typeof payload.fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/.test(payload.fingerprint) ||
        !timingSafeEqual(
          Buffer.from(payload.fingerprint),
          Buffer.from(fingerprint(payload.position as number)),
        )
      )
        throw new Error("cursor");
      offset = payload.position as number;
    } catch {
      throw new CliError(
        "VALIDATION_ERROR",
        "this cursor does not continue the current query",
        [
          "A cursor is bound to its operation, filter, sort, region, tenant selection, and credential",
          "Re-run the command without `--cursor` to start a fresh read",
        ],
      );
    }
  }
  if (offset >= 10_000)
    throw new CliError(
      "PAGINATION_LIMIT",
      "this read reached the 10000 result boundary falcon-axi enforces for Alerts",
    );
  const query = await requestRead(
    "GetQueriesAlertsV2",
    session.base,
    session.token,
    {
      limit: Math.min(limit, 10_000 - offset),
      offset,
      ...(filter ? { filter } : {}),
    },
    undefined,
    allowUnknown,
    signal,
  );
  if (query.status !== 200) responseFailure(query, "detections");
  if (!object(query.body) || !Array.isArray(query.body.resources))
    malformed(query, "Falcon returned a malformed resources array");
  const ids = query.body.resources.filter(
    (value): value is string => typeof value === "string",
  );
  const meta = object(query.body.meta) ? query.body.meta : {};
  const pagination = object(meta.pagination) ? meta.pagination : {};
  const total =
    typeof pagination.total === "number" &&
    Number.isSafeInteger(pagination.total)
      ? pagination.total
      : undefined;
  if (!ids.length)
    return {
      value: {
        detections: new Raw(
          offset ? "no more detections" : "0 detections in this tenant",
        ),
      },
      help: offset
        ? []
        : [
            "Run `falcon-axi detection list` without filters to see what is firing",
          ],
    };
  const byId = new Map<string, Record<string, unknown>>();
  for (let start = 0; start < ids.length; start += 1000) {
    const response = await requestRead(
      "PostEntitiesAlertsV2",
      session.base,
      session.token,
      {},
      { composite_ids: ids.slice(start, start + 1000) },
      allowUnknown,
      signal,
    );
    if (response.status !== 200) responseFailure(response, "detections");
    if (!object(response.body) || !Array.isArray(response.body.resources))
      malformed(response, "Falcon returned a malformed resources array");
    for (const alert of response.body.resources)
      if (object(alert)) {
        const id = alert.composite_id ?? alert.id;
        if (typeof id === "string") byId.set(id, alert);
      }
  }
  const rows = ids.flatMap((id) => {
    const alert = byId.get(id);
    if (!alert) return [];
    const text = (value: unknown): string | undefined =>
      typeof value === "string" && value ? value : undefined;
    const device = object(alert.device) ? alert.device : {};
    return [
      {
        id,
        severity: text(alert.severity_name) ?? "unknown",
        tactic: text(alert.tactic) ?? "unknown",
        hostname:
          text(device.hostname) ??
          text(alert.hostname) ??
          text(alert.source_endpoint_host_name) ??
          "unknown",
      },
    ];
  });
  const value: Record<string, unknown> = {
    count: new Raw(`${rows.length} of ${total ?? "unknown"} total`),
  };
  // Detail views land in S03. Do not advertise them in this partial candidate.
  const help: string[] = [];
  const position = offset + ids.length;
  if (
    (total === undefined ? ids.length === limit : position < total) &&
    position < 10_000
  ) {
    const continuation = Buffer.from(
      JSON.stringify({
        operation: "GetQueriesAlertsV2",
        model: "offset",
        position,
        fingerprint: fingerprint(position),
      }),
    ).toString("base64url");
    value.continuation_cursor = continuation;
    const quote = (text: string): string =>
      /^[\w@%+=:,./-]+$/.test(text)
        ? text
        : `'${text.replaceAll("'", `'"'"'`)}'`;
    const cidFilter = filter && /\b(?:cid|member_cid)\s*:/i.test(filter);
    help.push(
      `Run \`falcon-axi detection list --limit ${limit}${filter ? ` --filter ${quote(cidFilter ? "<original-filter>" : filter)}` : ""} --cursor ${continuation}\` for the next page`,
    );
    if (cidFilter)
      help.push(
        "Replace <original-filter> with your original --filter value when continuing; CID filters are not echoed",
      );
  }
  value.detections = rows;
  return { value, help };
}
