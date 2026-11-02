import { CliError, object } from "./core.js";
import type { Credential } from "./credentials.js";
import type { Invocation } from "./parser.js";
import { Cursor, pythonJson } from "./cursor.js";
import { Raw, redact, truncate } from "./render.js";
import { requestRead } from "./transport/https.js";
import { responseFailure } from "./auth.js";
import type { Session } from "./auth.js";
import { malformed } from "./response.js";
import { text, quote, project } from "./domain.js";

type RecordValue = Record<string, unknown>;
type Query = Record<string, string | number | readonly string[]>;
interface Output {
  value: RecordValue;
  help: string[];
}
const invalid = (message: string, details: RecordValue = {}): never => {
  throw new CliError("UPSTREAM_ERROR", message, [], details);
};
const hostname = (record: RecordValue): string | undefined =>
  text(object(record.device) ? record.device.hostname : undefined) ??
  text(record.hostname) ??
  text(record.source_endpoint_host_name);
const account = (record: RecordValue): string | undefined =>
  text(record.source_account_name) ?? text(record.source_account_upn);
const deviceId = (record: RecordValue): string | undefined =>
  text(object(record.device) ? record.device.device_id : undefined) ??
  text(record.device_id) ??
  text(record.agent_id);
const alertId = (record: RecordValue): string =>
  text(record.composite_id) ?? text(record.id) ?? "";

export async function investigate(
  invocation: Invocation,
  credential: Credential,
  session: Session,
  filter: string | undefined,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<Output> {
  const { command, flags, limit } = invocation;
  const name = command.name;
  const full = flags.has("--full");
  let id = invocation.id ?? "";
  const suggestion = `falcon-axi ${name === "home" ? "detection list" : name}${id ? ` ${quote(id)}` : ""}${flags.has("--all") ? " --all" : ""}${["filter", "sort", "hostname", "platform", "host", "severity", "status", "impact", "product", "since", "limit", "max-rows", "fields", "name", "email", "domain", "type", "category"].flatMap((key) => (flags.has(`--${key}`) ? [` --${key} ${quote(key === "filter" && /\b(?:cid|member_cid)\s*:/i.test(flags.get(`--${key}`)!) ? "<original-filter>" : flags.get(`--${key}`)!)}`] : [])).join("")}`;
  const hostsQuery = name === "host list";
  const description = [
    ...(flags.has("--hostname") && hostsQuery
      ? [`hostname ${flags.get("--hostname")}`]
      : []),
    ...(flags.has("--platform")
      ? [flags.get("--platform")!.toLowerCase()]
      : []),
    ...(flags.has("--severity")
      ? [`${flags.get("--severity")!.toLowerCase()} severity`]
      : []),
    ...(flags.has("--status")
      ? [`status ${flags.get("--status")!.toLowerCase()}`]
      : []),
    ...(flags.has("--product")
      ? [`product ${flags.get("--product")!.toLowerCase()}`]
      : []),
    ...(flags.has("--since")
      ? [
          `${hostsQuery ? "seen " : ""}in the last ${flags.get("--since")!.toLowerCase()}`,
        ]
      : []),
    ...(flags.has("--filter") ? ["the supplied filter"] : []),
  ].join(" ");
  let shortened = false;
  const preview = (value: unknown): unknown => {
    const safe = redact(value);
    if (typeof safe !== "string" || full) return safe;
    const result = truncate(safe);
    shortened ||= result !== safe;
    return result;
  };
  const read = async (
    operation: string,
    query: Query = {},
    body?: unknown,
  ): Promise<{
    rows: unknown[];
    total: number | undefined;
    pagination: RecordValue;
    body: unknown;
  }> => {
    const response = await requestRead(
      operation,
      session.base,
      session.token,
      query,
      body,
      allowUnknown,
      signal,
    );
    const envelope = object(response.body) ? response.body : {};
    if (
      operation === "QueryDeviceLoginHistoryV2" &&
      response.status === 400 &&
      Array.isArray(envelope.errors) &&
      envelope.errors.some(
        (error) =>
          object(error) &&
          typeof error.message === "string" &&
          /invalid device id/i.test(error.message),
      )
    )
      throw new CliError("NOT_FOUND", "no host matched that identifier", [
        "Run `falcon-axi host list` to see current device identifiers",
        "A device id is the agent id Falcon calls the AID",
      ]);
    const subject =
      name === "detection summary"
        ? name
        : name.startsWith("detection ") || name === "home"
          ? "detections"
          : name === "host logins"
            ? "host login history"
            : name.startsWith("host ")
              ? "hosts"
              : name === "process tree"
                ? "process trees"
                : name === "process show"
                  ? "process details"
                  : name.startsWith("file-change ")
                    ? "file changes"
                    : name.startsWith("ioc ")
                      ? "IOCs"
                      : name.startsWith("rtr session ")
                        ? "sessions"
                        : "audit_sessions";
    if (response.status === 404) {
      if (operation === "entities_processes")
        throw new CliError("NOT_FOUND", "no process matched that identifier", [
          "Run `falcon-axi ioc processes <type:value> --host <device_id>` to find process identifiers",
        ]);
      if (name.startsWith("ioc "))
        throw new CliError(
          "NOT_FOUND",
          "no IOC record matched that identifier",
          ["Run `falcon-axi ioc list`"],
        );
      const command =
        operation === "QueryGetNetworkAddressHistoryV1"
          ? "host list"
          : name.startsWith("file-change ")
            ? "file-change list"
            : name.startsWith("rtr session ")
              ? "rtr session list"
              : name.startsWith("rtr audit ")
                ? "rtr audit list"
                : "detection list";
      throw new CliError("NOT_FOUND", `no ${subject} matched that identifier`, [
        `Run \`falcon-axi ${command}\` to see current identifiers`,
      ]);
    }
    if (response.status !== 200)
      responseFailure(response, subject, false, false, operation);
    const rows: unknown = Array.isArray(response.body)
      ? response.body
      : envelope.resources;
    if (
      !Array.isArray(rows) ||
      (Array.isArray(envelope.errors) && envelope.errors.length)
    )
      malformed(response, "Falcon returned a malformed resources array");
    if (
      ["combined_summary_get", "combined_edges_get"].includes(operation) &&
      !object(response.body)
    )
      malformed(response, "Falcon returned an invalid process graph response");
    const meta = object(envelope.meta) ? envelope.meta : {};
    const pagination = object(meta.pagination) ? meta.pagination : {};
    const total =
      typeof pagination.total === "number" &&
      Number.isSafeInteger(pagination.total) &&
      pagination.total >= 0
        ? pagination.total
        : undefined;
    return { rows: rows as unknown[], total, pagination, body: response.body };
  };
  const hydrate = async (
    operation: string,
    ids: string[],
    chunk: number,
    key: string,
    bodyKey?: string,
  ): Promise<RecordValue[]> => {
    const records = new Map<string, RecordValue>();
    for (let start = 0; start < ids.length; start += chunk) {
      const batch = ids.slice(start, start + chunk);
      const result = await read(
        operation,
        bodyKey ? {} : { ids: batch },
        bodyKey ? { [bodyKey]: batch } : undefined,
      );
      for (const record of result.rows) {
        if (operation === "getChanges" && (!object(record) || !text(record.id)))
          invalid("Falcon returned a file change without an identifier");
        if (object(record)) {
          const identifier =
            key === "composite_id" ? alertId(record) : text(record[key]);
          if (identifier) records.set(identifier, record);
        }
      }
    }
    if (
      operation === "getChanges" &&
      records.size &&
      ids.some((identifier) => !records.has(identifier))
    )
      invalid("Falcon omitted requested file change identifiers");
    return ids.flatMap((identifier) =>
      records.has(identifier) ? [records.get(identifier)!] : [],
    );
  };
  const cursor = (
    operation: string,
    query = filter,
    model: "offset" | "token" = "offset",
    sort: string | null = null,
  ): Cursor =>
    new Cursor(credential, session.base, operation, query, model, sort);

  if (name === "detection list" || name === "host list" || name === "home") {
    const hosts = name === "host list";
    const operation = hosts ? "QueryDevicesByFilter" : "GetQueriesAlertsV2";
    const context = cursor(operation);
    let offset = flags.has("--cursor")
      ? (context.decode(flags.get("--cursor")!) as number)
      : 0;
    const wall = hosts ? 9999 : 10000;
    const wallHelp = hosts
      ? [
          "Narrow the filter so the result set fits under 10000, for example with `--platform` or `--since`",
          "This endpoint refuses a read whose limit plus offset reaches 10000, so the rows past that point are not reachable through this CLI",
        ]
      : [
          "Narrow the filter so the result set fits under 10000, for example by shortening `--since` or adding `--severity`",
          "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` pagination, which falcon-axi v1 does not register",
        ];
    if (offset >= wall)
      throw new CliError(
        "PAGINATION_LIMIT",
        hosts
          ? "this read reached the 10000 limit plus offset boundary Falcon enforces for hosts"
          : "this read reached the 10000 result boundary falcon-axi enforces for Alerts",
        wallHelp,
      );
    const records: RecordValue[] = [];
    let count: number | undefined;
    let remaining = flags.has("--all")
      ? Number(flags.get("--max-rows") ?? "1000")
      : name === "home"
        ? 5
        : limit;
    let more = false;
    let consumed = 0;
    do {
      const size = Math.min(
        flags.has("--all") ? command.ceiling! : remaining,
        remaining,
        wall - offset,
      );
      const result = await read(operation, {
        limit: size,
        offset,
        ...(filter ? { filter } : {}),
      });
      const ids = result.rows.filter(
        (value): value is string => typeof value === "string",
      );
      count = result.total;
      records.push(
        ...(await hydrate(
          hosts ? "PostDeviceDetailsV2" : "PostEntitiesAlertsV2",
          ids,
          hosts ? 5000 : 1000,
          hosts ? "device_id" : "composite_id",
          hosts ? "ids" : "composite_ids",
        )),
      );
      consumed += ids.length;
      offset += ids.length;
      remaining -= ids.length;
      more =
        ids.length > 0 &&
        (count === undefined ? ids.length >= size : offset < count);
    } while (flags.has("--all") && more && remaining > 0 && offset < wall);
    const key = hosts ? "hosts" : "detections";
    if (more && offset >= wall && !records.length)
      throw new CliError(
        "PAGINATION_LIMIT",
        "this read reached the endpoint pagination boundary",
        wallHelp,
      );
    if (!consumed)
      return {
        value: {
          [key]: new Raw(
            flags.has("--cursor")
              ? `no more ${key}`
              : description
                ? `0 ${key} matching ${description}`
                : `0 ${key} in this tenant`,
          ),
        },
        help: flags.has("--cursor")
          ? []
          : flags.has("--since")
            ? [
                `Run \`${suggestion} --since ${hosts ? "30d" : "7d"}\` to widen the window`,
              ]
            : [
                `Run \`falcon-axi ${hosts ? "host" : "detection"} list\` without filters to see ${hosts ? "the fleet" : "what is firing"}`,
              ],
      };
    const identity = records.some(
      (record) => account(record) || record.product === "idp",
    );
    const extras =
      flags
        .get("--fields")
        ?.split(",")
        .map((value) => value.trim())
        .filter(Boolean) ?? [];
    const rows = records.map((record) => {
      const row: RecordValue = hosts
        ? {
            device_id: record.device_id,
            hostname: text(record.hostname) ?? "unknown",
            platform: text(record.platform_name) ?? "unknown",
            last_seen: text(record.last_seen) ?? "unknown",
          }
        : {
            id: alertId(record),
            severity: text(record.severity_name) ?? "unknown",
            tactic: text(record.tactic) ?? "unknown",
            hostname:
              hostname(record) ??
              (account(record) || record.product === "idp" ? "n/a" : "unknown"),
          };
      if (!hosts && identity)
        Object.assign(row, {
          account: account(record) ?? "n/a",
          account_id: text(record.source_account_object_guid) ?? "n/a",
          device_id: deviceId(record) ?? "n/a",
          product: text(record.product) ?? "n/a",
        });
      for (const field of extras)
        if (!(field in row)) row[field] = text(record[field]) ?? "unknown";
      return row;
    });
    const value: RecordValue = {
      count: new Raw(`${rows.length} of ${count ?? "unknown"} total`),
    };
    const help = [
      hosts
        ? "Run `falcon-axi host show <device_id>` for full host details"
        : "Run `falcon-axi detection show <id>` for the full detection",
    ];
    if (hosts)
      help.push(
        "Run `falcon-axi vuln list --host <device_id>` for its open vulnerabilities",
      );
    if (flags.has("--all") && more) {
      value.partial = true;
      value.stop_reason = remaining <= 0 ? "max_rows" : "pagination_limit";
      if (remaining <= 0)
        help.push(
          offset < wall
            ? "Raise --max-rows, or follow continuation_cursor to resume from this position"
            : "The row budget was spent at the pagination boundary, so raising --max-rows reaches no further",
        );
    }
    if (more && offset < wall) {
      value.continuation_cursor = context.encode(offset);
      help.push(
        `Run \`${suggestion} --cursor ${String(value.continuation_cursor)}\` for the next page`,
      );
      if (filter && /\b(?:cid|member_cid)\s*:/i.test(filter))
        help.push(
          "Replace <original-filter> with your original --filter value when continuing; CID filters are not echoed",
        );
    } else if (more)
      help.push(
        wallHelp[0]!,
        hosts
          ? wallHelp[1]!
          : "The documented route past 10000 Alerts is PostCombinedAlertsV1 with `after` pagination, which falcon-axi v1 does not register, so those rows are not reachable through this CLI",
      );
    value[key] = rows;
    return { value, help };
  }
  if (name === "detection summary") {
    const result = await read("PostAggregatesAlertsV2", {}, [
      {
        name: "severity",
        type: "terms",
        field: "severity_name",
        size: 100,
        missing: "unknown",
        ...(filter ? { filter } : {}),
      },
    ]);
    const aggregate = result.rows.find(
      (row) => object(row) && row.name === "severity",
    );
    if (!result.rows.length)
      return {
        value: { detections: new Raw("0 detections in this tenant") },
        help: [],
      };
    if (
      !object(aggregate) ||
      !Array.isArray(aggregate.buckets) ||
      aggregate.buckets.some(
        (bucket) =>
          !object(bucket) ||
          typeof bucket.label !== "string" ||
          !Number.isSafeInteger(bucket.count) ||
          (bucket.count as number) < 0,
      )
    )
      invalid("Falcon returned an incomplete detection summary");
    const record = aggregate as RecordValue & { buckets: RecordValue[] };
    const other = record.sum_other_doc_count ?? 0;
    if (!Number.isSafeInteger(other) || (other as number) < 0)
      invalid("Falcon returned an incomplete detection summary");
    if (!record.buckets.length && !other)
      return {
        value: {
          detections: new Raw(
            description
              ? `0 detections matching ${description}`
              : "0 detections in this tenant",
          ),
        },
        help: [],
      };
    return {
      value: {
        severities: record.buckets.map((bucket) => ({
          severity: bucket.label,
          count: bucket.count,
        })),
        ...(other ? { other_count: other } : {}),
      },
      help: [],
    };
  }
  if (name === "detection show" || name === "detection process") {
    const record = (
      await hydrate(
        "PostEntitiesAlertsV2",
        [id],
        1000,
        "composite_id",
        "composite_ids",
      )
    )[0];
    if (!record)
      throw new CliError("NOT_FOUND", "no detection matched that identifier", [
        "Run `falcon-axi detection list` to see current detection identifiers",
        ...(name === "detection show"
          ? [
              "A composite id looks like `<cid>:ind:<id>`; copy it from the id column of `detection list`",
            ]
          : []),
      ]);
    const help: string[] = [];
    if (name === "detection process") {
      const fields = [
        "filename",
        "filepath",
        "cmdline",
        "sha256",
        "process_id",
      ];
      const value: RecordValue = {
        id: alertId(record),
        triggering_process_graph_id:
          text(record.triggering_process_graph_id) ?? "unknown",
      };
      const lineage = [
        ["triggering", record],
        ["parent", record.parent_details],
        ["grandparent", record.grandparent_details],
      ] as const;
      if (
        !fields.some((field) => text(record[field])) &&
        !text(record.triggering_process_graph_id) &&
        !lineage
          .slice(1)
          .some(([, entry]) => object(entry) && Object.keys(entry).length)
      )
        return {
          value: {
            ...value,
            processes: new Raw("no process recorded for this detection"),
          },
          help,
        };
      const rows: RecordValue[] = [];
      for (const [relation, entry] of lineage) {
        if (!object(entry) || !Object.keys(entry).length) {
          value[relation] = new Raw(`no ${relation} recorded`);
          continue;
        }
        const row: RecordValue = { relation, ...project(entry, fields) };
        row.cmdline = preview(row.cmdline);
        rows.push(row);
      }
      value.processes = rows;
      if (shortened)
        help.push(
          `Run \`falcon-axi detection process ${quote(id)} --full\` to see complete command lines`,
        );
      for (const pivot of new Set([
        record.triggering_process_graph_id,
        ...rows.map((row) => row.process_id),
      ]))
        if (
          typeof pivot === "string" &&
          /^pid:[a-fA-F0-9]{32}:\d+$/.test(pivot)
        )
          help.push(
            `Run \`falcon-axi process show ${pivot}\` for process details`,
          );
      for (const hash of new Set(rows.map((row) => row.sha256)))
        if (typeof hash === "string" && /^[a-fA-F0-9]{64}$/.test(hash))
          help.push(
            `Run \`falcon-axi sandbox list --sha256 ${hash}\` for existing sandbox reports`,
          );
      return { value, help };
    }
    const detail: RecordValue = {
      id: alertId(record),
      severity: `${text(record.severity_name) ?? "unknown"}${typeof record.severity === "number" ? ` (${record.severity})` : ""}`,
      tactic: text(record.tactic) ?? "unknown",
      technique: text(record.technique) ?? "unknown",
    };
    if (hostname(record) || !(account(record) || record.product === "idp"))
      detail.hostname = hostname(record) ?? "unknown";
    if (deviceId(record)) detail.device_id = deviceId(record);
    if (text(record.product)) detail.product = record.product;
    if (account(record)) detail.account = account(record);
    if (text(record.source_account_object_guid))
      detail.account_id = record.source_account_object_guid;
    Object.assign(detail, {
      status: text(record.status) ?? "unknown",
      first_seen: text(record.created_timestamp) ?? "unknown",
    });
    if (text(record.cmdline)) detail.cmdline = preview(record.cmdline);
    if (shortened)
      help.push(
        `Run \`falcon-axi detection show ${id} --full\` to see the complete command line`,
      );
    const subject = text(record.source_account_object_guid) ?? account(record);
    if (subject && /^[A-Za-z0-9._@$-]{1,256}$/.test(subject))
      help.push(
        `Run \`falcon-axi identity activity ${quote(subject)}\` to see what this account did`,
      );
    return { value: { detection: detail }, help };
  }
  if (name.startsWith("host ")) {
    const remedy = [
      "Run `falcon-axi host list --hostname '<pattern>' --limit 2` and select a device identifier",
    ];
    if (flags.has("--hostname")) {
      const result = await read("QueryDevicesByFilter", {
        filter: `hostname:'${flags.get("--hostname")}'`,
        limit: 2,
        offset: 0,
      });
      if (result.rows.length > 1 || (result.total ?? 0) > 1)
        throw new CliError(
          "VALIDATION_ERROR",
          "hostname matches more than one host; history was not read",
          remedy,
        );
      if (
        result.total === undefined ||
        result.total !== result.rows.length ||
        result.rows.some((row) => typeof row !== "string" || !row)
      )
        invalid(
          "the bounded hostname lookup could not prove a complete match; history was not read",
          { partial: true, stop_reason: "incomplete_lookup" },
        );
      if (!result.rows.length)
        throw new CliError(
          "NOT_FOUND",
          "no host matched that hostname; history was not read",
          remedy,
        );
      id = result.rows[0] as string;
    }
    const readHistory: typeof read = async (...args) => {
      try {
        return await read(...args);
      } catch (error) {
        if (flags.has("--hostname") && error instanceof CliError)
          Object.assign(error.details, {
            device_id: id,
            partial: true,
            stop_reason: "history_failed",
          });
        throw error;
      }
    };
    if (name === "host show") {
      const record = (
        await hydrate("PostDeviceDetailsV2", [id], 5000, "device_id", "ids")
      )[0];
      if (!record)
        throw new CliError("NOT_FOUND", "no host matched that identifier", [
          "Run `falcon-axi host list` to see current device identifiers",
          "A device id is the agent id Falcon calls the AID",
        ]);
      const detail: RecordValue = {
        device_id: record.device_id,
        hostname: text(record.hostname) ?? "unknown",
        platform: text(record.platform_name) ?? "unknown",
        ...project(record, [
          "os_version",
          "agent_version",
          "status",
          "first_seen",
          "last_seen",
        ]),
      };
      const domain = text(record.machine_domain) ?? text(record.site_name);
      if (domain) detail.domain = domain;
      return {
        value: { host: detail },
        help: [
          `Run \`falcon-axi vuln list --host ${quote(id)}\` for this host's open vulnerabilities`,
          `Run \`falcon-axi detection list --filter "device.hostname:'${String(detail.hostname)}'"\` for its detections`,
        ],
      };
    }
    if (name === "host network") {
      const result = await readHistory(
        "QueryGetNetworkAddressHistoryV1",
        {},
        { ids: [id] },
      );
      const history = result.rows.flatMap((row) =>
        object(row) && row.device_id === id && Array.isArray(row.history)
          ? row.history
          : [],
      );
      return {
        value: {
          device_id: id,
          network_history: history.length
            ? history
            : new Raw("0 network address history entries"),
        },
        help: [],
      };
    }
    const since = flags.get("--since");
    const result = await readHistory(
      "QueryDeviceLoginHistoryV2",
      { limit, ...(since ? { from: `now-${since.toLowerCase()}` } : {}) },
      { ids: [id] },
    );
    const logins = result.rows.flatMap((row) =>
      object(row) && Array.isArray(row.recent_logins)
        ? row.recent_logins.filter(object).map((login) => ({
            device_id: row.device_id,
            user_name: text(login.user_name) ?? "unknown",
            login_time: text(login.login_time) ?? "unknown",
          }))
        : [],
    );
    return {
      value: logins.length
        ? { count: new Raw(`${logins.length} logins on 1 host`), logins }
        : {
            logins: new Raw(`0 logins on 1 host in the last ${since ?? "7d"}`),
          },
      help: !logins.length
        ? [
            "Run `falcon-axi host logins <device_id> --since 30d` to widen the window",
            "Run `falcon-axi host show <device_id>` to check when the host was last seen",
          ]
        : [
            `Run \`falcon-axi host show ${id}\` for full host details`,
            "Run `falcon-axi host list --filter \"last_login_user:'<user_name>'\"` to find where a user last logged in",
            ...(result.rows.some(
              (row) =>
                object(row) &&
                Array.isArray(row.recent_logins) &&
                row.recent_logins.length >= limit,
            )
              ? [
                  `The host returned its limit of ${limit} logins: raise --limit (ceiling 100) or narrow --since`,
                ]
              : []),
          ],
    };
  }
  if (name === "process show") {
    const result = await read("entities_processes", { ids: [id] });
    if (!Array.isArray(result.body) || result.rows.some((row) => !object(row)))
      invalid("Falcon returned malformed process details");
    if (!result.rows.length)
      throw new CliError("NOT_FOUND", "no process matched that identifier", [
        "Run `falcon-axi ioc processes <type:value> --host <device_id>` to find process identifiers",
      ]);
    const record = result.rows.find(
      (row) => object(row) && row.process_id === id,
    );
    if (!object(record))
      invalid(
        "Falcon returned process details without the requested identifier",
      );
    const value = project(record as RecordValue, [
      "command_line",
      "device_id",
      "file_name",
      "process_id",
      "process_id_local",
      "start_timestamp",
      "start_timestamp_raw",
      "stop_timestamp",
      "stop_timestamp_raw",
    ]);
    value.command_line = preview(value.command_line);
    return {
      value: { process: value },
      help: shortened
        ? [
            `Run \`falcon-axi process show ${id} --full\` to see the complete command line`,
          ]
        : [],
    };
  }
  if (name === "process tree") {
    const context = cursor("combined_edges_get", id, "token", "child_process");
    const offset = flags.has("--cursor")
      ? (context.decode(flags.get("--cursor")!) as string)
      : undefined;
    const summary = async (identifier: string): Promise<RecordValue> => {
      const result = await read("combined_summary_get", { ids: [identifier] });
      if (!result.rows.length)
        throw new CliError(
          "NOT_FOUND",
          "no process matched that graph identifier",
        );
      const record = result.rows.find(
        (row) => object(row) && row.id === identifier,
      );
      return object(record)
        ? record
        : invalid("Falcon returned a different process graph identifier");
    };
    const rowOf = (record: RecordValue, relation: string): RecordValue => {
      const props = record.properties ?? {};
      if (!object(props))
        return invalid("Falcon returned invalid process properties");
      return {
        relation,
        id: record.id,
        filename: props.ImageFileName ?? "unknown",
        cmdline: preview(props.CommandLine ?? "unknown"),
        sha256: props.SHA256HashData ?? "unknown",
        start_time: props.ProcessStartTime_formatted ?? "unknown",
      };
    };
    const lineage: RecordValue[] = [];
    const seen = new Set([id]);
    let record = await summary(id);
    let ancestry = "no further parent recorded";
    for (let depth = 0; depth <= 5; depth++) {
      lineage.push(rowOf(record, depth ? `ancestor_${depth}` : "process"));
      const edges = record.edges ?? {};
      const parents = object(edges) ? (edges.parent_process ?? []) : undefined;
      if (!Array.isArray(parents) || parents.length > 1)
        invalid("Falcon returned ambiguous process parent edges");
      if (!(parents as unknown[]).length) break;
      const parent = (parents as unknown[])[0];
      if (!object(parent) || typeof parent.id !== "string" || !parent.id)
        invalid("Falcon returned a process parent without an identifier");
      const parentId = (parent as RecordValue).id as string;
      if (seen.has(parentId)) {
        ancestry = "cycle detected; ancestry stopped";
        break;
      }
      if (depth === 5) {
        ancestry = "depth limit reached; at most 5 ancestors shown";
        break;
      }
      seen.add(parentId);
      record = await summary(parentId);
    }
    const result = await read("combined_edges_get", {
      ids: id,
      edge_type: "child_process",
      limit: 100,
      ...(offset ? { offset } : {}),
    });
    const children = result.rows.map((record) => {
      if (!object(record) || typeof record.id !== "string" || !record.id)
        return invalid("Falcon returned a process child without an identifier");
      return rowOf(record, "child");
    });
    const value: RecordValue = {
      lineage,
      ancestry,
      children: children.length
        ? children
        : new Raw(
            flags.has("--cursor")
              ? "no more child processes"
              : "0 child processes",
          ),
      child_count: children.length,
    };
    const help: string[] = [];
    const next = text(result.pagination.next_page);
    if (children.length && next) {
      if (next === offset)
        invalid("Falcon returned a non-advancing child cursor");
      value.continuation_cursor = context.encode(next);
      help.push(
        `Run \`${suggestion}${full ? " --full" : ""} --cursor ${String(value.continuation_cursor)}\` for the next child page`,
      );
    }
    if (shortened)
      help.push(
        `Run \`${suggestion}${flags.has("--cursor") ? ` --cursor ${quote(flags.get("--cursor")!)}` : ""} --full\` for complete command lines`,
      );
    return { value, help };
  }
  if (name === "ioc hosts" || name === "ioc processes") {
    const processes = name === "ioc processes";
    const operation = processes ? "ProcessesRanOn" : "DevicesRanOn";
    const type = id.slice(0, id.indexOf(":"));
    const indicator = id.slice(id.indexOf(":") + 1);
    const host = flags.get("--host");
    const context = cursor(
      operation,
      pythonJson([type, indicator, host ?? null]),
    );
    const offset = flags.has("--cursor")
      ? (context.decode(flags.get("--cursor")!) as number)
      : 0;
    const result = await read(operation, {
      type,
      value: indicator,
      offset,
      limit,
      ...(host ? { device_id: host } : {}),
    });
    const ids = result.rows.filter(
      (value): value is string => typeof value === "string",
    );
    const key = processes ? "processes" : "hosts";
    const value: RecordValue = {
      count: new Raw(`${ids.length} of ${result.total ?? "unknown"} total`),
      [key]: ids.length
        ? ids.map((value) => ({
            [processes ? "process_id" : "device_id"]: value,
          }))
        : new Raw(`0 ${key} observed for this IOC`),
    };
    const help = [
      processes
        ? "Run `falcon-axi process show <process_id>` for process details"
        : "Run `falcon-axi host show <device_id>` for host details",
    ];
    if (!processes)
      help.push(
        `Run \`falcon-axi ioc processes ${quote(id)} --host <device_id>\` for process IDs`,
      );
    if (
      ids.length &&
      (result.total === undefined
        ? ids.length >= limit
        : offset + ids.length < result.total)
    ) {
      value.continuation_cursor = context.encode(offset + ids.length);
      help.push(
        `Run \`${suggestion} --cursor ${String(value.continuation_cursor)}\` for the next page`,
      );
    }
    return { value, help };
  }
  const file = name.startsWith("file-change ");
  const ioc = name.startsWith("ioc ");
  const sessionList = name.startsWith("rtr session ");
  const show = name.endsWith(" show");
  const queryOperation = file
    ? "highVolumeQueryChanges"
    : ioc
      ? "indicator_search_v1"
      : sessionList
        ? "RTR_ListAllSessions"
        : "RTRAuditSessions";
  const detailOperation = file
    ? "getChanges"
    : ioc
      ? "indicator_get_v1"
      : "RTR_ListSessions";
  const key = file
    ? "file_changes"
    : ioc
      ? "iocs"
      : sessionList
        ? "sessions"
        : "audit_sessions";
  const context = cursor(
    queryOperation,
    filter,
    file || ioc ? "token" : "offset",
    file ? "action_timestamp|desc" : null,
  );
  const position = flags.has("--cursor")
    ? context.decode(flags.get("--cursor")!)
    : file || ioc
      ? undefined
      : 0;
  const result = show
    ? undefined
    : await read(queryOperation, {
        limit,
        ...(file ? { sort: "action_timestamp|desc" } : {}),
        ...(filter ? { filter } : {}),
        ...(position !== undefined
          ? { [file || ioc ? "after" : "offset"]: position }
          : {}),
      });
  const listed = show ? [id] : result!.rows;
  if (file && listed.some((value) => typeof value !== "string" || !value))
    invalid("Falcon returned invalid file change identifiers");
  const ids = listed.filter(
    (value): value is string => typeof value === "string",
  );
  const records =
    !file && !ioc && !sessionList
      ? listed.filter(object)
      : await hydrate(
          detailOperation,
          ids,
          file ? 500 : 100,
          "id",
          sessionList ? "ids" : undefined,
        );
  if (file && records.length !== ids.length && !show)
    invalid("Falcon omitted requested file change identifiers");
  if (show) {
    const record = records[0];
    if (!record)
      throw new CliError(
        "NOT_FOUND",
        file
          ? "no file change matched that identifier"
          : ioc
            ? "no custom IOC matched that identifier"
            : "no record matched that identifier",
        [
          file
            ? "Run `falcon-axi file-change list` to find identifiers"
            : ioc
              ? "Run `falcon-axi ioc list`"
              : "Run `falcon-axi rtr session list`",
        ],
      );
    if (file) {
      const detail: RecordValue = {
        id: record.id,
        ...project(record, [
          "action_timestamp",
          "action_type",
          "entity_type",
          "entity_path",
          "host",
          "severity",
          "process_id",
          "process_image_file_name",
          "command_line",
          "parent_process_image_file_name",
          "grandparent_process_image_file_name",
          "diff",
        ]),
      };
      detail.host = object(record.host)
        ? (record.host.name ?? "unknown")
        : "unknown";
      return { value: { file_change: detail }, help: [] };
    }
    if (ioc)
      return {
        value: {
          ioc: Object.fromEntries(
            [
              "id",
              "type",
              "value",
              "action",
              "severity",
              "description",
              "source",
              "platforms",
              "host_groups",
              "tags",
              "applied_globally",
              "expiration",
              "expired",
              "created_on",
              "modified_on",
              "metadata",
            ]
              .filter((key) => key in record)
              .map((key) => [key, record[key]]),
          ),
        },
        help: [],
      };
    const detail = (value: unknown): unknown =>
      typeof value === "string"
        ? preview(value)
        : Array.isArray(value)
          ? value.map(detail)
          : object(value)
            ? Object.fromEntries(
                Object.entries(redact(value) as RecordValue).map(
                  ([key, entry]) => [key, detail(entry)],
                ),
              )
            : value;
    const value = { rtr_session: detail(record) };
    return {
      value,
      help: shortened
        ? [`Run \`${suggestion} --full\` for untruncated detail`]
        : [],
    };
  }
  if (!listed.length && !file && !ioc)
    return {
      value: {
        [key]: new Raw(
          flags.has("--cursor")
            ? `no more ${key}`
            : `0 ${key} matching this query`,
        ),
      },
      help: [],
    };
  const rows = records.map((record) => {
    const row = project(
      record,
      file
        ? [
            "action_timestamp",
            "action_type",
            "entity_type",
            "entity_path",
            "host",
            "severity",
          ]
        : ioc
          ? ["id", "type", "value", "action"]
          : ["id", "hostname", "user_id", "created_at"],
    );
    if (file)
      row.host = object(record.host)
        ? (record.host.name ?? "unknown")
        : "unknown";
    return row;
  });
  const value: RecordValue = {
    count: new Raw(
      file && result!.total === undefined
        ? String(rows.length)
        : `${rows.length} of ${result!.total ?? "unknown"} total`,
    ),
    [key]:
      rows.length || ids.length
        ? rows
        : new Raw(
            file
              ? "no file changes; this can mean no matching data or a tenant without Falcon FileVantage licensing"
              : "0 custom IOCs matching this query",
          ),
  };
  const help: string[] =
    file && rows.length
      ? [
          "Run `falcon-axi file-change show <id>` with a change_ids entry in row order",
        ]
      : ioc
        ? ["Run `falcon-axi ioc show <id>` for the indicator record"]
        : sessionList
          ? ["Run `falcon-axi rtr session show <id>` for the full record"]
          : [];
  if (file && rows.length)
    value.change_ids = records.map((record) => record.id);
  const next: string | number | undefined =
    file || ioc
      ? file && !ids.length
        ? undefined
        : text(result!.pagination.after)
      : typeof position === "number" &&
          listed.length &&
          (result!.total === undefined
            ? listed.length >= limit
            : position + listed.length < result!.total)
        ? Number(position) + listed.length
        : undefined;
  if (next !== undefined) {
    value.continuation_cursor = context.encode(next);
    help.push(
      `Run \`${suggestion} --cursor ${String(value.continuation_cursor)}\` for the next page`,
    );
  }
  return { value, help };
}
