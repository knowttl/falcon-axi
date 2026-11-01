import { CliError, object } from "./core.js";
import { Domain, count, more, project, text } from "./domain.js";
import type { Output, Query, RecordValue } from "./domain.js";
import { Raw, redact, truncate } from "./render.js";
import { operation } from "./transport/operations.js";
import { malformed } from "./response.js";

export const policyTypes: Readonly<Record<string, readonly [string, string]>> =
  {
    prevention: [
      "queryCombinedPreventionPolicies",
      "queryCombinedPreventionPolicyMembers",
    ],
    "sensor-update": [
      "queryCombinedSensorUpdatePoliciesV2",
      "queryCombinedSensorUpdatePolicyMembers",
    ],
    firewall: [
      "queryCombinedFirewallPolicies",
      "queryCombinedFirewallPolicyMembers",
    ],
    "device-control": [
      "queryDeviceControlPolicies",
      "queryCombinedDeviceControlPolicyMembers",
    ],
    response: [
      "queryCombinedRTResponsePolicies",
      "queryCombinedRTResponsePolicyMembers",
    ],
    "content-update": [
      "queryCombinedContentUpdatePolicies",
      "queryCombinedContentUpdatePolicyMembers",
    ],
  };
export const exclusionTypes: Readonly<
  Record<string, readonly [string, string]>
> = {
  ml: ["exclusions_search_v2", "exclusions_get_v2"],
  ioa: ["ss_ioa_exclusions_search_v2", "ss_ioa_exclusions_get_v2"],
  "sensor-visibility": [
    "querySensorVisibilityExclusionsV1",
    "getSensorVisibilityExclusionsV1",
  ],
  certificate: ["cb_exclusions_query_v1", "cb_exclusions_get_v1"],
};
export function validateInspection(
  name: string,
  flags: ReadonlyMap<string, string>,
  limit: number,
): void {
  const type = flags.get("--type") ?? "";
  if (name.startsWith("policy ")) {
    if (!Object.hasOwn(policyTypes, type))
      throw new CliError(
        "VALIDATION_ERROR",
        "--type requires one of: " + Object.keys(policyTypes).join(", "),
        [
          "Run `falcon-axi policy list --type prevention` to list prevention policies",
        ],
      );
    if (name === "policy show" && type !== "device-control")
      throw new CliError(
        "VALIDATION_ERROR",
        "policy show supports only --type device-control",
      );
  }
  if (name.startsWith("exclusion ")) {
    if (!Object.hasOwn(exclusionTypes, type))
      throw new CliError(
        "VALIDATION_ERROR",
        "--type must be one of ml, ioa, sensor-visibility, certificate",
      );
    if (type === "certificate" && limit > 100)
      throw new CliError(
        "VALIDATION_ERROR",
        "--limit must be an integer from 1 to 100 for certificate exclusions",
      );
  }
  if (
    name === "data-policy list" &&
    !["win", "mac"].includes(flags.get("--platform") ?? "")
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "--platform is required: win or mac",
      ["Run `falcon-axi data-policy list --platform win` for Windows policies"],
    );
  if (
    ["classification list", "data-policy list"].includes(name) &&
    flags.has("--sort")
  ) {
    const fields = [
      "name",
      "created_at",
      "modified_at",
      ...(name === "data-policy list" ? ["precedence"] : []),
    ];
    if (
      !fields.some((field) =>
        ["asc", "desc"].some(
          (direction) => flags.get("--sort") === `${field}.${direction}`,
        ),
      )
    )
      throw new CliError(
        "VALIDATION_ERROR",
        "--sort must use a supported field and .asc or .desc",
        [`valid sort fields: ${fields.join(", ")}`],
      );
  }
  if (name === "identity rule list")
    for (const flag of ["--enabled", "--simulation-mode"])
      if (flags.has(flag) && !["true", "false"].includes(flags.get(flag)!))
        throw new CliError("VALIDATION_ERROR", `${flag} must be true or false`);
  if (name === "sandbox list") sandboxFilter(flags);
}
function sandboxFilter(flags: ReadonlyMap<string, string>): string {
  const hash = flags.get("--sha256"),
    filter = flags.get("--filter");
  const help = [
    "Run `falcon-axi sandbox list --sha256 <64-hex-hash>` or `falcon-axi sandbox list --filter \"verdict:'malicious'\"`",
  ];
  if ((hash === undefined) === (filter === undefined))
    throw new CliError(
      "VALIDATION_ERROR",
      "supply exactly one of --sha256 or --filter",
      help,
    );
  if (hash !== undefined && !/^[a-fA-F0-9]{64}$/.test(hash))
    throw new CliError(
      "VALIDATION_ERROR",
      "--sha256 requires exactly 64 hex characters",
      help,
    );
  return hash === undefined ? filter! : `sandbox.sha256:'${hash}'`;
}
function invalid(message: string): never {
  throw new CliError("UPSTREAM_ERROR", message);
}

// Recon and Device Control entity reads also have documented top-level array responses.
async function read(
  domain: Domain,
  op: string,
  query: Query = {},
  body?: unknown,
  missing = false,
  raw = false,
) {
  const name = domain.invocation.command.name,
    noun = name.split(" ")[0]!;
  const subject = ["actor", "report"].includes(noun)
    ? `${noun}s`
    : noun === "classification" || noun === "data-policy"
      ? "Data Protection"
      : noun === "policy"
        ? name.endsWith("members")
          ? "policy members"
          : "policies"
        : noun === "sandbox"
          ? "sandbox reports"
          : name;
  let response;
  try {
    response = await domain.response(op, subject, query, body, missing);
  } catch (error) {
    if (error instanceof CliError && error.code === "FQL_INVALID") {
      const list = name.replace(/ (show|members)$/, " list");
      const type = domain.invocation.flags.get("--type");
      const command = `${list}${type ? ` --type ${type}` : ""}`;
      throw new CliError(
        error.code,
        error.message,
        [
          "FQL uses + for AND, `,` for OR, and values must be quoted",
          `Run \`falcon-axi ${command} --help\` for the filterable fields`,
        ],
        error.details,
      );
    }
    throw error;
  }
  if (missing && response.status === 404)
    return {
      rows: [] as unknown[],
      total: undefined,
      pagination: {} as RecordValue,
    };
  const envelope = object(response.body) ? response.body : {};
  const rows: unknown =
    raw && Array.isArray(response.body) ? response.body : envelope.resources;
  if (
    !Array.isArray(rows) ||
    (Array.isArray(envelope.errors) && envelope.errors.length)
  )
    malformed(response, "Falcon returned a malformed resources array");
  const meta = object(envelope.meta) ? envelope.meta : {};
  const pagination = object(meta.pagination) ? meta.pagination : {};
  const total =
    typeof pagination.total === "number" &&
    Number.isSafeInteger(pagination.total) &&
    pagination.total >= 0
      ? pagination.total
      : undefined;
  return { rows: rows as unknown[], total, pagination };
}
async function hydrate(
  domain: Domain,
  op: string,
  ids: string[],
  raw = false,
  missing = false,
  strict = false,
): Promise<RecordValue[]> {
  const records = new Map<string, RecordValue>();
  for (let start = 0; start < ids.length; start += 100) {
    const batch = ids.slice(start, start + 100);
    const post = operation(op).method === "POST";
    const result = await read(
      domain,
      op,
      post ? {} : { ids: batch },
      post ? { ids: batch } : undefined,
      missing,
      raw,
    );
    for (const row of result.rows) {
      if (!object(row) || !text(row.id)) {
        if (strict) invalid("Falcon returned an invalid entity identifier");
        continue;
      }
      records.set(row.id as string, row);
    }
  }
  if (strict && ids.some((id) => !records.has(id)))
    invalid("Falcon omitted a requested entity");
  return ids.flatMap((id) => (records.has(id) ? [records.get(id)!] : []));
}
function detail(
  domain: Domain,
  key: string,
  record: RecordValue,
  recursive = false,
  message = "for untruncated detail",
): Output {
  let shortened = false;
  const preview = (value: unknown): unknown => {
    if (typeof value === "string" && !domain.invocation.flags.has("--full")) {
      const next = truncate(value);
      shortened ||= next !== value;
      return next;
    }
    if (recursive && Array.isArray(value)) return value.map(preview);
    if (recursive && object(value))
      return Object.fromEntries(
        Object.entries(value).map(([key, value]) => [key, preview(value)]),
      );
    return value;
  };
  return {
    value: {
      [key]: Object.fromEntries(
        Object.entries(redact(record) as RecordValue).map(([key, value]) => [
          key,
          preview(value),
        ]),
      ),
    },
    help: shortened ? [`Run \`${domain.suggestion} --full\` ${message}`] : [],
  };
}
interface Collection {
  key: string;
  columns: string[];
  model?: "offset-or-token";
}
const collections: Readonly<Record<string, Collection>> = {
  "firewall rule": {
    key: "firewall_rules",
    columns: ["id", "name", "enabled", "action"],
    model: "offset-or-token",
  },
  "firewall group": {
    key: "firewall_groups",
    columns: ["id", "name", "enabled", "platform"],
    model: "offset-or-token",
  },
  "ioa group": {
    key: "ioa_groups",
    columns: ["id", "name", "enabled", "platform"],
  },
  "correlation-rule": {
    key: "correlation_rules",
    columns: ["rule_id", "name", "status", "severity"],
  },
  case: { key: "cases", columns: ["id", "name", "status", "severity"] },
};

export async function inspection(
  domain: Domain,
  filter: string | undefined,
): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const name = command.name,
    noun = name.split(" ")[0]!,
    show = name.endsWith(" show");
  const supplied = flags.get("--cursor");
  let op = command.operations[0]!,
    entity = command.operations[1];
  const recon = noun.startsWith("recon-");
  const intel = ["actor", "report"].includes(noun);
  const collectionNoun = name.split(" ").slice(0, -1).join(" ");
  const collection = collections[collectionNoun];
  const type = flags.get("--type") ?? "";
  const members = name === "policy members";
  if (noun === "policy" && !show)
    [op, entity] = [
      policyTypes[type]![members ? 1 : 0],
      !members && type === "device-control"
        ? "getDeviceControlPoliciesV2"
        : undefined,
    ];
  if (noun === "exclusion") {
    const pair = exclusionTypes[type]!;
    op = pair[show ? 1 : 0];
    entity = show ? undefined : pair[1];
  }
  if (show) {
    if (intel) {
      const result = await read(
        domain,
        op,
        { ids: [id!], fields: ["__full__"] },
        undefined,
        true,
      );
      if (!result.rows.length)
        throw new CliError("NOT_FOUND", `no ${noun} matched that identifier`, [
          `Run \`falcon-axi ${noun} list\` to see current ${noun} identifiers`,
        ]);
      const record = result.rows.find(
        (row): row is RecordValue => object(row) && String(row.id) === id,
      );
      if (!record)
        invalid(
          `Falcon returned a ${noun} resource without the requested identifier`,
        );
      const output = detail(
        domain,
        noun,
        record,
        false,
        "to see complete text fields",
      );
      if (flags.has("--mitre")) {
        const response = await domain.response(
          "GetMitreReport",
          "actor ATT&CK mappings",
          { actor_id: id!, format: "json" },
        );
        if (
          response.body !== null &&
          (!Array.isArray(response.body) ||
            response.body.some((row) => !object(row)))
        )
          invalid("Falcon returned an invalid JSON ATT&CK report");
        output.value.mitre =
          Array.isArray(response.body) && response.body.length
            ? response.body
            : new Raw("0 ATT&CK mappings for this actor");
      }
      return output;
    }
    if (noun === "malware") {
      const result = await read(domain, op, { ids: [id!] }, undefined, true);
      const record = result.rows.find(
        (row): row is RecordValue => object(row) && row.slug === id,
      );
      if (!record)
        throw new CliError(
          "NOT_FOUND",
          "no malware family matched that identifier",
          ["Run `falcon-axi malware list` to see family identifiers"],
        );
      const output = {
        value: { malware: redact(record) as RecordValue },
        help: [] as string[],
      };
      if (!flags.has("--full") && typeof record.description === "string") {
        const preview = truncate(record.description);
        output.value.malware.description = preview;
        if (preview !== record.description)
          output.help.push(
            `Run \`${domain.suggestion} --full\` for the full description`,
          );
      }
      return output;
    }
    if (noun === "policy") {
      const result = await read(
        domain,
        op,
        { ids: [id!] },
        undefined,
        true,
        true,
      );
      if (result.rows.some((row) => !object(row) || typeof row.id !== "string"))
        invalid("Falcon returned invalid device-control policies");
      if (!result.rows.length)
        throw new CliError(
          "NOT_FOUND",
          "no device-control policy: not licensed or no data for that identifier",
          [
            "Run `falcon-axi policy list --type device-control` to see current identifiers",
          ],
        );
      const record = result.rows.find(
        (row): row is RecordValue => object(row) && row.id === id,
      );
      if (!record)
        invalid("Falcon omitted the requested device-control policy");
      return {
        value: {
          policy: {
            ...project(record, [
              "id",
              "name",
              "platform_name",
              "enabled",
              "description",
            ]),
            usb_settings:
              record.usb_settings ?? new Raw("no USB settings recorded"),
          },
        },
        help: [
          `Run \`falcon-axi policy members ${id} --type device-control\` for assigned hosts`,
        ],
      };
    }
    if (noun === "indicator" || noun === "sandbox") {
      const post = operation(op).method === "POST";
      const result = await read(
        domain,
        op,
        post ? {} : { ids: [id!] },
        post ? { ids: [id!] } : undefined,
        noun === "indicator",
      );
      if (!result.rows.length)
        throw new CliError(
          "NOT_FOUND",
          noun === "indicator"
            ? "no intelligence indicator matched that identifier"
            : "no sandbox report matched that identifier",
        );
      const record = result.rows.find(
        (row): row is RecordValue => object(row) && row.id === id,
      );
      if (!record)
        invalid(
          noun === "indicator"
            ? "Falcon returned an indicator without the requested identifier"
            : "Falcon omitted the requested sandbox report summary",
        );
      return noun === "sandbox"
        ? sandboxDetail(record)
        : {
            value: {
              indicator: Object.fromEntries(
                Object.entries(record).filter(([key]) => key !== "_marker"),
              ),
            },
            help: [],
          };
    }
    const records = await hydrate(
      domain,
      op,
      [id!],
      recon,
      recon || ["exclusion", "quarantine", "identity"].includes(noun),
    );
    if (!records.length)
      throw new CliError(
        "NOT_FOUND",
        recon || collection
          ? "no record matched that identifier"
          : noun === "identity"
            ? "no identity policy rule matched that identifier"
            : `no ${noun === "data-policy" ? "policy" : noun} matched that identifier`,
        recon || collection
          ? [
              `Run \`falcon-axi ${collectionNoun} list\`${recon ? " for identifiers" : ""}`,
            ]
          : ["classification", "data-policy"].includes(noun)
            ? [`Run \`falcon-axi ${noun} list --help\` to find identifiers`]
            : [],
      );
    const record = records[0]!;
    if (recon || collection)
      return detail(
        domain,
        recon ? "record" : collectionNoun.replaceAll(" ", "_"),
        record,
        true,
        recon ? "for untruncated content" : "for untruncated detail",
      );
    return {
      value: {
        [noun === "data-policy"
          ? "policy"
          : noun === "identity"
            ? "rule"
            : noun]: record,
      },
      help: [],
    };
  }
  if (name === "identity rule list") {
    const query: Query = {};
    for (const key of ["name", "enabled", "simulation-mode"])
      if (flags.has(`--${key}`))
        query[key.replaceAll("-", "_")] = flags.get(`--${key}`)!;
    const result = await read(domain, op, query);
    const ids = result.rows.filter(
      (row): row is string => typeof row === "string",
    );
    if (!ids.length)
      return {
        value: {
          rules: new Raw("0 identity policy rules matching this query"),
        },
        help: [],
      };
    const records = await hydrate(domain, entity!, ids, false, true);
    return {
      value: {
        count: count(records, ids.length),
        rules: records.map((record) => ({
          ...project(record, ["id", "name", "enabled"]),
          simulation_mode: record.simulationMode ?? "unknown",
        })),
      },
      help: [
        "Run `falcon-axi identity rule show <id>` for the full policy rule",
      ],
    };
  }
  const data = ["classification", "data-policy"].includes(noun);
  if (noun === "sandbox") filter = sandboxFilter(flags);
  const sort = noun === "indicator" ? "_marker.asc" : flags.get("--sort");
  const contextFilter = data
    ? JSON.stringify([filter ?? null, flags.get("--platform") ?? null])
    : noun === "policy"
      ? JSON.stringify([filter ?? null, members ? id : null])
      : filter;
  const context = domain.cursor(
    op,
    contextFilter,
    noun === "indicator" ? "marker" : (collection?.model ?? "offset"),
    sort ?? null,
  );
  const position = supplied
    ? context.decode(supplied)
    : collection?.model || noun === "indicator"
      ? undefined
      : 0;
  const offset = typeof position === "number" ? position : 0;
  if ((recon && offset >= 10000) || (data && offset > 10000))
    throw new CliError(
      "PAGINATION_LIMIT",
      recon
        ? "Recon queries stop at 10000 results"
        : "Data Protection queries cannot continue beyond offset 10000",
      ["Narrow --filter and start again"],
    );
  const size = recon ? Math.min(limit, 10000 - offset) : limit;
  const query: Query = { limit: size };
  if (noun !== "indicator" && (!collection?.model || position !== undefined))
    query[typeof position === "string" ? "after" : "offset"] = position ?? 0;
  if (filter) query.filter = filter;
  if (sort) query.sort = sort;
  if (noun === "indicator" && typeof position === "string") {
    const term = `_marker:>'${position.replaceAll("\\", "\\\\").replaceAll("'", "\\'")}'`;
    query.filter = filter ? `(${filter})+${term}` : term;
  }
  if (noun === "data-policy") query.platform_name = flags.get("--platform")!;
  if (members) query.id = id!;
  const result = await read(domain, op, query);
  const key =
    collection?.key ??
    (recon
      ? "records"
      : noun === "malware"
        ? "malware"
        : noun === "sandbox"
          ? "sandbox_reports"
          : noun === "policy" || noun === "data-policy"
            ? members
              ? "members"
              : "policies"
            : noun === "exclusion"
              ? "exclusions"
              : noun === "quarantine"
                ? "quarantined_files"
                : `${noun}s`);
  if (!result.rows.length) {
    let empty = supplied ? `no more ${key}` : `0 ${key} matching this query`;
    const help: string[] = [];
    if (intel)
      empty = offset
        ? `no more ${noun}s`
        : filter
          ? `0 ${noun}s matching the supplied filter`
          : `0 ${noun}s`;
    if (noun === "indicator")
      empty = supplied
        ? "no more indicators"
        : "0 indicators matching the supplied query";
    if (noun === "malware")
      empty = offset
        ? "no more malware families"
        : "0 malware families matching this query";
    if (recon || ["exclusion", "quarantine"].includes(noun))
      empty = offset
        ? `no more ${key}`
        : filter
          ? `0 ${key} matching the supplied filter`
          : `0 ${key}`;
    if (noun === "sandbox")
      empty =
        "0 sandbox reports: not licensed or no data; reports exist only for files submitted to this tenant's Falcon Intelligence (Sandbox)";
    if (noun === "policy") {
      const subject = `${type} ${members ? "policy members" : "policies"}`;
      empty =
        (offset ? `no more ${subject}` : `0 ${subject} matching this query`) +
        (type === "device-control" && !members
          ? ": not licensed or no data"
          : "");
      if (!offset)
        help.push(
          members
            ? "Run `falcon-axi host show <device_id>` for a member's host details"
            : `Run \`falcon-axi policy members <id> --type ${type}\` for assigned hosts`,
        );
    }
    return { value: { [key]: new Raw(empty) }, help };
  }
  const requestedIds = result.rows.filter(
    (row): row is string => typeof row === "string",
  );
  if (
    entity
      ? requestedIds.length !== result.rows.length
      : result.rows.some((row) => !object(row))
  )
    invalid("Falcon returned invalid collection resources");
  if (
    (noun === "sandbox" ||
      (noun === "policy" && type === "device-control" && !members)) &&
    requestedIds.length !== result.rows.length
  )
    invalid("Falcon returned invalid entity identifiers");
  const records = entity
    ? await hydrate(
        domain,
        entity,
        requestedIds,
        recon || (noun === "policy" && type === "device-control"),
        recon || ["exclusion", "quarantine"].includes(noun),
        noun === "sandbox" || (noun === "policy" && type === "device-control"),
      )
    : result.rows.filter(object);
  if (
    (intel || noun === "indicator") &&
    records.some((record) => !text(record.id) && typeof record.id !== "number")
  )
    invalid(`Falcon returned an invalid ${noun} resource`);
  let columns = collection?.columns ?? [
    "id",
    "name",
    "created_date",
    "last_modified_date",
  ];
  if (noun === "indicator")
    columns = ["id", "indicator", "type", "malicious_confidence"];
  if (noun === "policy")
    columns = members
      ? ["device_id", "hostname", "platform_name", "status"]
      : ["id", "name", "platform_name", "enabled"];
  if (noun === "exclusion")
    columns =
      type === "ioa"
        ? ["id", "name", "pattern_id"]
        : type === "certificate"
          ? ["id", "name", "status"]
          : ["id", "value", "applied_globally"];
  if (noun === "quarantine") columns = ["id", "hostname", "sha256", "state"];
  if (recon)
    columns =
      noun === "recon-rule"
        ? ["id", "name", "status", "priority"]
        : noun === "recon-record"
          ? ["id", "domain", "credential_status", "notification_id"]
          : ["id", "status", "rule_name", "created_date"];
  const rows = records.flatMap((record) => {
    if (noun === "sandbox") return sandboxRows(record);
    if (noun === "malware")
      return [
        { id: record.slug ?? "unknown", family_name: record.name ?? "unknown" },
      ];
    if (data)
      return [
        {
          ...project(record, ["id", "name"]),
          ...(noun === "data-policy"
            ? project(record, ["is_enabled", "precedence"])
            : {
                protection_mode: object(record.classification_properties)
                  ? (record.classification_properties.protection_mode ??
                    "unknown")
                  : "unknown",
              }),
        },
      ];
    if (noun === "recon-notification")
      return [
        {
          id: record.id ?? null,
          ...Object.fromEntries(
            ["status", "rule_name", "created_date"].map((field) => [
              field,
              object(record.notification)
                ? (record.notification[field] ?? null)
                : null,
            ]),
          ),
        },
      ];
    return [
      recon
        ? Object.fromEntries(
            columns.map((field) => [field, record[field] ?? null]),
          )
        : project(record, columns),
    ];
  });
  const output: Output = {
    value: {
      count:
        noun === "sandbox"
          ? new Raw(
              `${result.rows.length} of ${result.total ?? "unknown"} total reports`,
            )
          : count(rows, result.total),
    },
    help: [],
  };
  if (noun === "policy") {
    if (type === "device-control" && !members)
      output.help.push(
        "Run `falcon-axi policy show <id> --type device-control` for USB classes and exceptions",
      );
    output.help.push(
      members
        ? "Run `falcon-axi host show <device_id>` for a member's host details"
        : `Run \`falcon-axi policy members <id> --type ${type}\` for assigned hosts`,
    );
  } else if (intel)
    output.help.push(
      `Run \`falcon-axi ${noun} show <id>\` for the full ${noun} record`,
    );
  else if (noun === "indicator")
    output.help.push(
      "Run `falcon-axi indicator show <id>` for the full indicator record",
    );
  else if (noun === "malware")
    output.help.push(
      "Run `falcon-axi malware show <id>` for the malware family record",
    );
  else if (noun === "sandbox")
    output.help.push(
      "Run `falcon-axi sandbox show <report-id>` for report details",
    );
  else if (!collection || (entity && collectionNoun !== "firewall group"))
    output.help.push(
      `Run \`falcon-axi ${collectionNoun} show <id>${noun === "exclusion" ? ` --type ${type}` : ""}\` for the full record`,
    );
  let next: string | number | undefined;
  if (noun === "indicator") {
    if (
      result.total === undefined
        ? records.length >= limit
        : records.length < result.total
    ) {
      next = text(records.at(-1)?._marker);
      if (!next || (typeof position === "string" && next <= position))
        invalid("Falcon returned no advancing indicator marker");
    }
  } else {
    if (collection?.model)
      next = text(result.pagination.next) ?? text(result.pagination.after);
    const base =
      typeof result.pagination.offset === "number"
        ? result.pagination.offset
        : offset;
    if (
      next === undefined &&
      (typeof position !== "string" ||
        typeof result.pagination.offset === "number") &&
      more(result.rows.length, base, result.total, size)
    )
      next = base + result.rows.length;
    if (
      typeof next === "number" &&
      ((recon && next >= 10000) || (data && next > 10000))
    ) {
      next = undefined;
      output.value.stop_reason = "pagination_limit";
      if (data) output.value.partial = true;
      output.help.push(
        recon
          ? "Recon queries stop at 10000 results; narrow --filter and start again"
          : "Narrow --filter to read beyond the Data Protection offset limit",
      );
    }
  }
  domain.continuation(output, context, next);
  output.value[key] = rows;
  return output;
}
const environmentFields = [
  "threat_score",
  "environment_description",
  "submit_name",
];
function environments(record: RecordValue, fields: string[]): RecordValue[] {
  const rows = record.sandbox ?? [];
  if (!Array.isArray(rows) || rows.some((row) => !object(row)))
    invalid("Falcon returned invalid sandbox environments");
  return rows.map((row) => project(row as RecordValue, fields));
}
function sandboxRows(record: RecordValue): RecordValue[] {
  const rows = environments(record, environmentFields);
  return (rows.length ? rows : [project({}, environmentFields)]).map((row) => ({
    id: record.id,
    verdict: record.verdict ?? "unknown",
    ...row,
    created_timestamp: record.created_timestamp ?? "unknown",
  }));
}
function sandboxDetail(record: RecordValue): Output {
  const rows = environments(record, [
    ...environmentFields,
    "file_type",
    "classification_tags",
    "submit_url",
    "sha256",
  ]);
  return {
    value: {
      sandbox_report: {
        ...project(record, ["id", "verdict", "created_timestamp"]),
        sandbox: rows.length
          ? rows
          : new Raw("no sandbox environments recorded"),
      },
    },
    help: [],
  };
}
