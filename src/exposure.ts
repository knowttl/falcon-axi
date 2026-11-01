import { CliError, object } from "./core.js";
import { Domain, count, ids, more, project, text } from "./domain.js";
import type { Output, RecordValue, Query } from "./domain.js";
import { Raw, redact, truncate } from "./render.js";
import { malformed } from "./response.js";

const exactMatch =
  "Filters use exact whole-value matching; wildcards and partial names are not supported, so 0 rows does not prove absence. Check the complete name, version, or CVE identifier.";
export function shieldFilters(flags: ReadonlyMap<string, string>): Query {
  const query: Query = {};
  for (const key of ["impact", "status"])
    if (flags.has(`--${key}`)) {
      const choices =
        key === "impact"
          ? ["Low", "Medium", "High"]
          : [
              "Passed",
              "Failed",
              "Dismissed",
              "Pending",
              "Can't Run",
              "Stale",
              "NA",
              "Not Available",
            ];
      const normalized = choices.find(
        (value) => value.toLowerCase() === flags.get(`--${key}`)!.toLowerCase(),
      );
      if (!normalized)
        throw new CliError(
          "VALIDATION_ERROR",
          `--${key} must be one of ${choices.join(", ")}`,
        );
      query[key] = normalized;
    }
  return query;
}
const cell = (value: unknown): string =>
  typeof value === "number" || typeof value === "bigint"
    ? String(value)
    : (text(value) ?? "unknown");
const nested = (record: RecordValue, name: string): RecordValue =>
  object(record[name]) ? record[name] : {};
const joined = (values: unknown, key?: string): string | undefined =>
  text(values) ??
  (Array.isArray(values)
    ? [
        ...new Set(
          values.flatMap((value) => {
            const part = text(key && object(value) ? value[key] : value);
            return part ? [part] : [];
          }),
        ),
      ].join(",") || undefined
    : undefined);
const extras = [
  "description",
  "base_score",
  "exprt_rating",
  "status",
  "created",
  "updated",
  "product",
  "remediation",
  "platform",
  "os",
  "local_ip",
];
function vulnerability(
  record: RecordValue,
  fields: readonly string[],
): RecordValue {
  const cve = nested(record, "cve"),
    host = nested(record, "host_info");
  const values: RecordValue = {
    description: cve.description,
    base_score: cve.base_score,
    exprt_rating: cve.exprt_rating,
    status: record.status,
    created: record.created_timestamp,
    updated: record.updated_timestamp,
    product:
      joined(record.apps, "product_name_version") ??
      text(nested(record, "app").product_name_version),
    remediation: joined(nested(record, "remediation").ids),
    platform: host.platform_name ?? host.platform,
    os: host.os_version,
    local_ip: host.local_ip,
  };
  return {
    id: text(record.id) ?? "unknown",
    cve: text(cve.id) ?? "unknown",
    severity: text(cve.severity) ?? "unknown",
    hostname: text(host.hostname) ?? "unknown",
    ...Object.fromEntries(fields.map((field) => [field, cell(values[field])])),
  };
}
const cloudFields: Record<
  string,
  { key: string; columns: string[]; detail: string[]; token: boolean }
> = {
  "cloud-asset": {
    key: "cloud_assets",
    columns: ["id", "resource_name", "resource_type", "cloud_provider"],
    detail: [
      "resource_id",
      "account_id",
      "account_name",
      "region",
      "service",
      "active",
      "first_seen",
      "updated_at",
      "cloud_context.publicly_exposed",
      "cloud_context.detections.highest_severity",
    ],
    token: true,
  },
  iom: {
    key: "ioms",
    columns: ["id", "evaluation.severity", "evaluation.status", "resource.id"],
    detail: [
      "cloud.provider",
      "cloud.account_id",
      "cloud.region",
      "resource.service",
      "evaluation.first_detected",
      "evaluation.last_detected",
    ],
    token: false,
  },
  "cloud-risk": {
    key: "cloud_risks",
    columns: ["id", "rule_name", "severity", "status"],
    detail: [],
    token: false,
  },
};
const flatten = (record: RecordValue, fields: string[]): RecordValue =>
  Object.fromEntries(
    fields.map((path) => {
      const value = path
        .split(".")
        .reduce<unknown>(
          (value, part) => (object(value) ? value[part] : undefined),
          record,
        );
      return [
        path.replaceAll(".", "_"),
        ["string", "boolean", "number", "bigint"].includes(typeof value)
          ? value
          : "unknown",
      ];
    }),
  );

export async function exposure(
  domain: Domain,
  filter: string | undefined,
): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const name = command.name,
    noun = name.split(" ")[0]!,
    operation = command.operations[0]!;
  const suppliedCursor = flags.get("--cursor");
  if (noun === "vuln") {
    if (name === "vuln show") {
      const result = await domain.read(
        operation,
        "vulnerabilities",
        { ids: [id!] },
        undefined,
        true,
      );
      if (!result.rows.length)
        throw new CliError(
          "NOT_FOUND",
          "no vulnerability matched that identifier",
          [
            "Run `falcon-axi vuln list --status open` to find Spotlight record identifiers",
          ],
        );
      const record = result.rows.find(
        (row): row is RecordValue => object(row) && row.id === id,
      );
      if (!record)
        throw new CliError(
          "UPSTREAM_ERROR",
          "Falcon returned a vulnerability resource without the requested identifier",
        );
      const base = vulnerability(record, []);
      return {
        value: {
          vulnerability: {
            ...base,
            device_id: text(record.aid) ?? "unknown",
            ...Object.fromEntries(
              extras
                .filter((field) => field !== "remediation")
                .map((field) => [field, vulnerability(record, [field])[field]]),
            ),
          },
        },
        help: [],
      };
    }
    const context = domain.cursor(operation, filter, "token");
    let position = suppliedCursor
      ? String(context.decode(suppliedCursor))
      : undefined;
    const fields =
      flags
        .get("--fields")
        ?.split(",")
        .map((field) => field.trim()) ?? [];
    const facet = [
      "cve",
      "host_info",
      ...(fields.includes("remediation") ? ["remediation"] : []),
    ];
    const rows: RecordValue[] = [];
    let remaining = flags.has("--all")
      ? Number(flags.get("--max-rows") ?? 1000)
      : limit;
    let total: number | undefined;
    const seen = new Set<string>();
    do {
      const size = Math.min(
        remaining,
        flags.has("--all") ? command.ceiling! : limit,
      );
      const result = await domain.read(operation, "vulnerabilities", {
        limit: size,
        filter: filter!,
        facet,
        ...(position ? { after: position } : {}),
      });
      const records = result.rows.filter(object);
      total = result.total;
      rows.push(...records.map((record) => vulnerability(record, fields)));
      remaining -= records.length;
      const next =
        records.length >= size ? text(result.pagination.after) : undefined;
      if (flags.has("--all") && next && seen.has(next))
        throw new CliError(
          "UPSTREAM_ERROR",
          "Falcon repeated a vulnerability continuation token",
        );
      if (next) seen.add(next);
      position = next;
    } while (flags.has("--all") && position && remaining > 0);
    if (!rows.length) {
      const description = [
        flags.has("--severity")
          ? `${flags.get("--severity")!.toLowerCase()} severity`
          : "",
        flags.has("--status")
          ? `status ${flags.get("--status")!.toLowerCase()}`
          : "",
        flags.has("--host") ? "on that host" : "",
        flags.has("--since")
          ? `created in the last ${flags.get("--since")!.toLowerCase()}`
          : "",
        flags.has("--filter") ? "the supplied filter" : "",
      ]
        .filter(Boolean)
        .join(" ");
      return {
        value: {
          vulnerabilities: new Raw(
            suppliedCursor
              ? "no more vulnerabilities"
              : description
                ? `0 vulnerabilities matching ${description}`
                : "0 vulnerabilities",
          ),
        },
        help: suppliedCursor
          ? [exactMatch]
          : [
              exactMatch,
              "Run `falcon-axi vuln list --status open` to see every open vulnerability",
              "Run `falcon-axi host list` to find the host you meant",
            ],
      };
    }
    const output: Output = {
      value: { count: count(rows, total) },
      help: [
        "Run `falcon-axi host list --filter \"hostname:'<name>'\"` to read an affected host",
      ],
    };
    if (flags.has("--all") && position) {
      output.value.partial = true;
      output.value.stop_reason = "max_rows";
      output.help.push(
        "Raise --max-rows, or follow continuation_cursor to resume from this position",
      );
    }
    domain.continuation(output, context, position);
    output.value.vulnerabilities = rows;
    return output;
  }
  const cloud = cloudFields[noun];
  if (cloud) {
    if (name.endsWith(" show")) {
      const records = await domain.hydrate(operation, noun, [id!]);
      if (!records.length)
        throw new CliError("NOT_FOUND", `no ${noun} matched that identifier`, [
          `Run \`falcon-axi ${noun} list\``,
        ]);
      return {
        value: {
          [noun]: flatten(records[0]!, [...cloud.columns, ...cloud.detail]),
        },
        help: [],
      };
    }
    const sort = flags.get("--sort");
    const context = domain.cursor(
      operation,
      filter,
      cloud.token ? "token" : "offset",
      sort ?? null,
    );
    const position = suppliedCursor
      ? context.decode(suppliedCursor)
      : cloud.token
        ? undefined
        : 0;
    const result = await domain.read(operation, noun, {
      limit,
      ...(filter ? { filter } : {}),
      ...(sort ? { sort } : {}),
      ...(position === undefined
        ? {}
        : { [cloud.token ? "after" : "offset"]: position }),
    });
    const records = command.operations[1]
      ? await domain.hydrate(command.operations[1], noun, ids(result.rows))
      : result.rows.filter(object);
    const rows = records.map((record) => flatten(record, cloud.columns));
    const output: Output = {
      value: {
        count:
          result.total === undefined
            ? new Raw(String(rows.length))
            : count(rows, result.total),
        [cloud.key]: rows.length
          ? rows
          : new Raw(
              filter
                ? `0 ${cloud.key} matching the supplied filter`
                : `0 ${cloud.key} in this tenant`,
            ),
      },
      help: command.operations[1]
        ? [`Run \`falcon-axi ${noun} show <id>\` for resource detail`]
        : [],
    };
    domain.continuation(
      output,
      context,
      !result.rows.length
        ? undefined
        : cloud.token
          ? text(result.meta.next)
          : more(result.rows.length, Number(position), result.total, limit)
            ? Number(position) + result.rows.length
            : undefined,
    );
    if (noun === "cloud-risk")
      output.help.push(
        "Risk detail is not offered: the official API has no risk-detail endpoint or risk-id filter.",
      );
    return output;
  }
  if (noun === "shield") {
    const query = shieldFilters(flags);
    const context = domain.cursor(
      operation,
      JSON.stringify(query).replaceAll(":", ": ").replaceAll(",", ", "),
    );
    const offset = suppliedCursor ? Number(context.decode(suppliedCursor)) : 0;
    const show = name.endsWith(" show");
    const response = await domain.response(
      operation,
      "Shield checks",
      show ? { id: id! } : { ...query, limit, offset },
      undefined,
      show,
    );
    const rows = response.status === 404 ? [] : response.body;
    if (!Array.isArray(rows))
      malformed(response, "Falcon returned an invalid Shield check array");
    const checks = rows as unknown[];
    if (checks.some((row) => !object(row) || !text(row.id)))
      malformed(
        response,
        "Falcon returned a Shield check without an identifier",
      );
    if (show) {
      if (!checks.length)
        throw new CliError(
          "NOT_FOUND",
          "no Shield check matched that identifier",
          ["Run `falcon-axi shield list` for check IDs"],
        );
      const record = checks.find(
        (row): row is RecordValue => object(row) && row.id === id,
      );
      if (!record)
        malformed(
          response,
          "Falcon returned Shield checks without the requested identifier",
        );
      let shortened = false;
      const preview = (value: unknown): unknown => {
        if (typeof value === "string" && !flags.has("--full")) {
          const next = truncate(value);
          shortened ||= next !== value;
          return next;
        }
        if (Array.isArray(value)) return value.map(preview);
        return object(value)
          ? Object.fromEntries(
              Object.entries(value).map(([key, entry]) => [
                key,
                preview(entry),
              ]),
            )
          : value;
      };
      return {
        value: { check: preview(redact(record)) },
        help: shortened
          ? [`Run \`falcon-axi shield show ${id} --full\` for untruncated text`]
          : [],
      };
    }
    if (!checks.length)
      return {
        value: {
          checks: new Raw(
            offset
              ? "no more Shield checks"
              : "0 Shield checks matching this query",
          ),
        },
        help: [],
      };
    const output: Output = {
      value: { count: count(checks, undefined) },
      help: ["Run `falcon-axi shield show <id>` for the full posture check"],
    };
    domain.continuation(
      output,
      context,
      checks.length === limit ? offset + checks.length : undefined,
    );
    output.value.checks = checks
      .filter(object)
      .map((row) => project(row, ["id", "name", "status", "impact"]));
    return output;
  }
  if (noun === "cve") return cves(domain, filter);
  const serverless = noun === "serverless";
  const columns =
    noun === "container"
      ? ["container_id", "container_name", "namespace", "running_status"]
      : name === "image vulnerabilities"
        ? ["cve_id", "severity", "cvss_score", "images_impacted"]
        : ["image_id", "repository", "tag", "highest_vulnerability_severity"];
  const sort = serverless
    ? "cve_id"
    : `${columns[0] === "container_id" ? "container_name" : columns[0]}.asc`;
  const context = domain.cursor(operation, filter, "offset", sort);
  const offset = suppliedCursor ? Number(context.decode(suppliedCursor)) : 0;
  if (!serverless && offset >= 10000)
    throw new CliError(
      "PAGINATION_LIMIT",
      "Falcon's 10000-record inventory window is exhausted",
      ["Narrow --filter"],
    );
  const size = serverless ? limit : Math.min(limit, 10000 - offset);
  const query = { limit: size, offset, sort, ...(filter ? { filter } : {}) };
  if (serverless) {
    const response = await domain.response(
      operation,
      "serverless vulnerabilities",
      query,
    );
    const envelope = object(response.body) ? response.body : {};
    const sarif = Object.hasOwn(envelope, "resources")
      ? envelope.resources
      : envelope;
    const runs = object(sarif) ? sarif.runs : undefined;
    if (!Array.isArray(runs) || runs.some((run) => !object(run)))
      malformed(
        response,
        "Falcon returned an invalid serverless SARIF document",
      );
    const rows = runs as RecordValue[];
    if (!rows.length)
      return {
        value: {
          runs: new Raw("0 serverless SARIF runs matching the supplied query"),
        },
        help: [],
      };
    const output: Output = {
      value: {
        count: new Raw(
          `${rows.length} SARIF runs; vulnerability total unknown`,
        ),
        runs: rows,
      },
      help: [
        "SARIF runs are not vulnerability rows; the next page may be empty",
      ],
    };
    domain.continuation(output, context, offset + limit);
    return output;
  }
  const result = await domain.read(
    operation,
    noun === "container"
      ? "containers"
      : name === "image vulnerabilities"
        ? "vulnerabilities"
        : "images",
    query,
  );
  if (result.rows.some((row) => !object(row) || !row[columns[0]!]))
    throw new CliError(
      "UPSTREAM_ERROR",
      "Falcon returned an invalid inventory page",
    );
  const key =
    noun === "container"
      ? "containers"
      : name === "image vulnerabilities"
        ? "vulnerabilities"
        : "images";
  if (!result.rows.length)
    return {
      value: {
        [key]: new Raw(
          suppliedCursor
            ? `no more ${key}`
            : `0 ${key} matching the supplied query`,
        ),
      },
      help: [],
    };
  const rows = result.rows.filter(object).map((row) => project(row, columns));
  const output: Output = {
    value: { count: count(rows, result.total), [key]: rows },
    help: [],
  };
  if (more(rows.length, offset, result.total, size)) {
    if (offset + rows.length < 10000)
      domain.continuation(output, context, offset + rows.length);
    else {
      output.value.partial = true;
      output.value.stop_reason = "pagination_limit";
      output.help.push(
        "Falcon's 10000-record inventory window is exhausted; narrow --filter",
      );
    }
  }
  return output;
}

async function cves(
  domain: Domain,
  filter: string | undefined,
): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const show = command.name === "cve show";
  const score = (record: RecordValue): unknown => {
    const value = nested(record, "cvss_v3_base").score;
    return typeof value === "number" || typeof value === "bigint"
      ? value
      : "unknown";
  };
  if (show) {
    const result = await domain.read(
      "GetVulnerabilities",
      "CVE intelligence",
      {},
      { ids: [id!] },
      true,
    );
    if (!result.rows.length)
      return {
        value: { vulnerabilities: new Raw(`0 vulnerabilities matching ${id}`) },
        help: [
          "CrowdStrike Intelligence has no entry for that CVE, which is not the same as no host exposure",
          `Run \`falcon-axi vuln list --filter "cve.id:'${id}'"\` for tenant exposure`,
        ],
      };
    const record = result.rows.find(
      (row): row is RecordValue => object(row) && row.cve === id,
    );
    if (!record)
      throw new CliError(
        "UPSTREAM_ERROR",
        "Falcon returned a CVE intelligence resource without the requested CVE",
      );
    return {
      value: {
        cve: {
          cve: id,
          severity: cell(record.severity),
          cvss_v3_score: score(record),
          exploit_status: cell(record.exploit_status),
          publish_date: cell(record.publish_date),
          updated: cell(record.updated_timestamp),
          description: cell(record.description),
          ...Object.fromEntries(
            [
              "affected_products",
              "related_actors",
              "related_reports",
              "related_threats",
            ].map((key) => [
              key,
              Array.isArray(record[key]) ? record[key].length : 0,
            ]),
          ),
        },
      },
      help: [
        "Related actor, report, threat, and affected-product lists are counts; this command does not expand them",
        `Run \`falcon-axi vuln list --filter "cve.id:'${id}'"\` for tenant exposure`,
      ],
    };
  }
  const context = domain.cursor("QueryVulnerabilities", filter);
  const offset = flags.has("--cursor")
    ? Number(context.decode(flags.get("--cursor")!))
    : 0;
  const result = await domain.read("QueryVulnerabilities", "CVE intelligence", {
    limit,
    offset: String(offset),
    ...(filter ? { filter } : {}),
  });
  const listed = ids(result.rows);
  if (!listed.length)
    return {
      value: {
        cves: new Raw(
          offset
            ? "no more CVEs"
            : filter
              ? "0 CVEs matching the supplied filters"
              : "0 CVEs in Falcon Intelligence",
        ),
      },
      help: [],
    };
  const records = await domain.hydrate(
    "GetVulnerabilities",
    "CVE intelligence",
    listed,
    "cve",
    true,
  );
  const rows = records.map((record) => ({
    cve: record.cve,
    severity: cell(record.severity),
    cvss_v3_score: score(record),
    exploit_status: cell(record.exploit_status),
  }));
  const output: Output = {
    value: { count: count(rows, result.total) },
    help: [
      "Run `falcon-axi cve show <CVE-ID>` for CVE intelligence and tenant-exposure guidance",
    ],
  };
  domain.continuation(
    output,
    context,
    more(listed.length, offset, result.total, limit)
      ? offset + listed.length
      : undefined,
  );
  output.value.cves = rows;
  return output;
}
