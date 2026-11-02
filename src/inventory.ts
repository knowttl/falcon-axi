import { CliError, object } from "./core.js";
import { pythonJson } from "./cursor.js";
import { Domain, count, ids, more, project, quote, text } from "./domain.js";
import type { Output, RecordValue, Query } from "./domain.js";
import { Raw, redact, truncate } from "./render.js";

export const applicationFields = [
  "id",
  "name",
  "version",
  "vendor",
  "host",
  "account_name",
  "account_type",
  "admin_privileges",
  "architectures",
  "browser_extension",
  "category",
  "cid",
  "dev_package",
  "discovery_methods",
  "extension_id",
  "first_seen_timestamp",
  "groups",
  "homepage",
  "host_application",
  "ide_extension",
  "installation_paths",
  "installation_timestamp",
  "is_malicious",
  "is_normalized",
  "is_suspicious",
  "last_published",
  "last_updated_timestamp",
  "last_used_file_hash",
  "last_used_file_name",
  "last_used_timestamp",
  "last_used_user_name",
  "last_used_user_sid",
  "local_admin_privileges",
  "malicious_indicators",
  "name_vendor",
  "name_vendor_version",
  "registry_latest_version_available",
  "software_type",
  "store_listing",
  "store_listing_status",
  "suspicious_indicators",
  "threat_level",
  "versioning_scheme",
];
const scalar = (value: unknown): string =>
  typeof value === "boolean" ||
  typeof value === "number" ||
  typeof value === "bigint"
    ? String(value)
    : (text(value) ?? "unknown");
const accountFields = {
  id: "id",
  username: "username",
  account_type: "account_type",
  login_domain: "login_domain",
  admin_privileges: "admin_privileges",
  last_login: "last_successful_login_timestamp",
};
const accountDetail = {
  id: "id",
  username: "username",
  account_name: "account_name",
  account_type: "account_type",
  login_domain: "login_domain",
  user_sid: "user_sid",
  admin_privileges: "admin_privileges",
  local_admin_privileges: "local_admin_privileges",
  password_last_set: "password_last_set_timestamp",
  first_seen: "first_seen_timestamp",
  last_login: "last_successful_login_timestamp",
  last_login_hostname: "last_successful_login_hostname",
  last_login_type: "last_successful_login_type",
  last_failed_login: "last_failed_login_timestamp",
  last_failed_login_hostname: "last_failed_login_hostname",
};
const accountRow = (record: RecordValue, detail = false): RecordValue =>
  Object.fromEntries(
    Object.entries(detail ? accountDetail : accountFields).map(
      ([name, source]) => [name, scalar(record[source])],
    ),
  );

export async function inventory(
  domain: Domain,
  filter: string | undefined,
): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const name = command.name;
  const operation = command.operations[0]!;
  const sensor = name.startsWith("identity sensor ");
  const noun = sensor ? "identity sensor" : name.split(" ")[0]!;
  const subject = sensor
    ? "identity sensors"
    : noun === "iot"
      ? "IoT assets"
      : `${noun}s`;
  const key = sensor ? "sensors" : noun === "iot" ? "iot" : `${noun}s`;
  const context = domain.cursor(operation, filter);
  const offset = (): number =>
    flags.has("--cursor") ? Number(context.decode(flags.get("--cursor")!)) : 0;
  const sensorRow = (record: RecordValue): RecordValue =>
    Object.fromEntries(
      ["device_id", "hostname", "status", "agent_version"].map((field) => [
        field,
        text(record[field]) ?? "unknown",
      ]),
    );
  if (name.endsWith(" show")) {
    const records = await domain.hydrate(
      operation,
      subject,
      [id!],
      sensor ? "device_id" : "id",
      sensor,
    );
    const record = records[0];
    if (!record)
      throw new CliError("NOT_FOUND", `no ${noun} matched that identifier`, [
        `Run \`falcon-axi ${noun} list\` to see current ${sensor ? "sensor" : noun === "asset" ? "Discover asset" : noun} identifiers`,
      ]);
    if (sensor)
      return {
        value: {
          sensor: {
            ...sensorRow(record),
            ...Object.fromEntries(
              [
                "heartbeat_time",
                "idp_policy_id",
                "idp_policy_name",
                "directory_auditing",
                "status_causes",
              ]
                .filter((field) => field in record)
                .map((field) => [field, record[field]]),
            ),
          },
        },
        help: [],
      };
    if (noun === "asset")
      return {
        value: {
          asset: {
            ...Object.fromEntries(
              [
                "id",
                "hostname",
                "entity_type",
                "platform_name",
                "os_version",
                "aid",
                "criticality",
                "current_local_ip",
                "external_ip",
                "first_seen_timestamp",
                "last_seen_timestamp",
              ].map((field) => [field, text(record[field]) ?? "unknown"]),
            ),
            mac_addresses: Array.isArray(record.network_interfaces)
              ? record.network_interfaces.flatMap((entry) =>
                  object(entry) && text(entry.mac_address)
                    ? [entry.mac_address]
                    : [],
                )
              : [],
          },
        },
        help: [],
      };
    const help = ["Run `falcon-axi account list` to see more accounts"];
    if (text(record.last_successful_login_aid))
      help.unshift(
        `Run \`falcon-axi host logins ${quote(String(record.last_successful_login_aid))}\` for recent interactive logins on its last login host`,
      );
    return { value: { account: accountRow(record, true) }, help };
  }
  if (noun === "sensor-usage") {
    const result = await domain.read(
      operation,
      "sensor usage",
      filter ? { filter } : {},
    );
    const rows = result.rows.filter(object);
    if (rows.length !== result.rows.length)
      throw new CliError(
        "UPSTREAM_ERROR",
        "Falcon returned an invalid report array",
      );
    return {
      value: {
        count: rows.length,
        usage: rows.length ? rows : new Raw("0 weekly sensor usage reports"),
      },
      help: [],
    };
  }
  if (noun === "host-group") {
    const members = name.endsWith("members");
    const sort = members ? null : "name.asc";
    const context = domain.cursor(
      operation,
      pythonJson([id ? [id] : [], filter ?? null]),
      "offset",
      sort,
    );
    const position = flags.has("--cursor")
      ? Number(context.decode(flags.get("--cursor")!))
      : 0;
    const result = await domain.read(
      operation,
      members ? "host-group members" : "host groups",
      {
        limit,
        offset: position,
        ...(members ? { id: id! } : { sort: "name.asc" }),
        ...(filter ? { filter } : {}),
      },
    );
    const rows = result.rows
      .filter(object)
      .map((row) =>
        Object.fromEntries(
          (members
            ? ["device_id", "hostname", "platform_name", "status"]
            : ["id", "name", "group_type", "description"]
          ).map((key) => [key, row[key] ?? null]),
        ),
      );
    const output: Output = {
      value: {
        count: count(rows, result.total),
        [members ? "members" : "host_groups"]: rows.length
          ? rows
          : new Raw(
              members
                ? "0 members in this host group"
                : "0 host groups matching this query",
            ),
      },
      help: [
        members
          ? "Run `falcon-axi host show <device_id>` for host details"
          : "Run `falcon-axi host-group members <id>` for the hosts in a group",
      ],
    };
    domain.continuation(
      output,
      context,
      more(result.rows.length, position, result.total, limit)
        ? position + result.rows.length
        : undefined,
    );
    return output;
  }
  if (noun === "account" || sensor) {
    let position = offset();
    let remaining = flags.has("--all")
      ? Number(flags.get("--max-rows") ?? 1000)
      : limit;
    let total: number | undefined;
    let next = false;
    let consumed = 0;
    const rows: RecordValue[] = [];
    do {
      const size = Math.min(
        remaining,
        flags.has("--all") ? command.ceiling! : limit,
      );
      const result = await domain.read(operation, subject, {
        limit: size,
        offset: position,
        ...(filter ? { filter } : {}),
      });
      total = result.total;
      const listed = ids(result.rows);
      rows.push(
        ...(
          await domain.hydrate(
            command.operations[1]!,
            subject,
            listed,
            sensor ? "device_id" : "id",
            sensor,
          )
        ).map((record) => (sensor ? sensorRow(record) : accountRow(record))),
      );
      next = more(listed.length, position, total, size);
      position += listed.length;
      consumed += listed.length;
      remaining -= listed.length;
    } while (flags.has("--all") && next && remaining > 0);
    if (!consumed)
      return {
        value: {
          [key]: new Raw(
            flags.has("--cursor")
              ? `no more ${subject}`
              : sensor
                ? "0 identity sensors matching this query"
                : filter
                  ? "0 accounts matching the supplied filter"
                  : "0 accounts in this tenant",
          ),
        },
        help:
          sensor || flags.has("--cursor")
            ? []
            : [
                "Run `falcon-axi account list` without a filter to see every observed account",
              ],
      };
    const output: Output = {
      value: { count: count(rows, total) },
      help: [
        sensor
          ? "Run `falcon-axi identity sensor show <device_id>` for sensor details"
          : "Run `falcon-axi account show <id>` for the full account record",
      ],
    };
    if (flags.has("--all") && next) {
      output.value.partial = true;
      output.value.stop_reason = "max_rows";
      output.help.push(
        "Raise --max-rows, or follow continuation_cursor to resume from this position",
      );
    }
    domain.continuation(output, context, next ? position : undefined);
    output.value[key] = rows;
    return output;
  }
  const token = noun !== "login";
  const queryFilter =
    filter ??
    (noun === "asset"
      ? "id:'*'"
      : noun === "application"
        ? "name:'*'"
        : undefined);
  const pageContext = domain.cursor(
    operation,
    queryFilter,
    token ? "token" : "offset",
  );
  const position = flags.has("--cursor")
    ? pageContext.decode(flags.get("--cursor")!)
    : token
      ? undefined
      : 0;
  const query: Query = {
    limit,
    ...(queryFilter ? { filter: queryFilter } : {}),
    ...(position === undefined
      ? {}
      : { [token ? "after" : "offset"]: position }),
    ...(noun === "application"
      ? {
          facet: [
            "browser_extension",
            "host_info",
            "install_usage",
            "dev_package",
            "ide_extension",
            "llm",
            "mcp",
          ],
        }
      : {}),
  };
  const result = await domain.read(operation, subject, query);
  const listed = ids(result.rows);
  if (noun === "iot" && !listed.length)
    return {
      value: {
        iot: new Raw(
          flags.has("--cursor")
            ? "no more IoT assets"
            : "0 IoT assets matching this query",
        ),
      },
      help: [],
    };
  const records =
    noun === "iot" || noun === "login"
      ? await domain.hydrate(command.operations[1]!, subject, listed)
      : result.rows.filter(object);
  let shortened = false;
  const preview = (value: unknown): unknown => {
    if (typeof value === "string" && !flags.has("--full")) {
      const next = truncate(value, 500);
      shortened ||= next !== value;
      return next;
    }
    if (Array.isArray(value)) return value.map(preview);
    if (object(value))
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [key, preview(entry)]),
      );
    return value;
  };
  const fields = flags
    .get("--fields")
    ?.split(",")
    .map((field) => field.trim());
  const rows = records.map((record) =>
    noun === "application"
      ? preview(
          redact(
            fields
              ? Object.fromEntries(
                  fields.map((field) => [field, record[field] ?? null]),
                )
              : record,
          ),
        )
      : noun === "iot"
        ? project(record, ["id", "hostname", "device_type", "device_family"])
        : Object.fromEntries(
            (noun === "asset"
              ? ["id", "hostname", "entity_type", "platform_name"]
              : ["id", "username", "hostname", "login_timestamp"]
            ).map((field) => [field, text(record[field]) ?? "unknown"]),
          ),
  );
  const output: Output = {
    value: { count: count(rows, result.total) },
    help:
      noun === "asset"
        ? ["Run `falcon-axi asset show <id>` for asset details"]
        : [],
  };
  if (shortened)
    output.help.push(
      `Run \`${domain.suggestion}${flags.has("--cursor") ? ` --cursor ${quote(flags.get("--cursor")!)}` : ""} --full\` for untruncated application fields`,
    );
  if (!rows.length && noun === "application")
    output.help.push(
      "Filters use exact whole-value matching; wildcards and partial names are not supported, so 0 rows does not prove absence. Check the complete name, version, or CVE identifier.",
    );
  domain.continuation(
    output,
    pageContext,
    token
      ? text(result.pagination.after)
      : more(listed.length, Number(position), result.total, limit)
        ? Number(position) + listed.length
        : undefined,
  );
  output.value[key] =
    rows.length || (noun === "iot" && listed.length)
      ? rows
      : new Raw(`0 ${key} returned for this Discover query`);
  return output;
}
