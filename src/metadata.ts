export interface Command {
  readonly name: string;
  readonly summary: string;
  readonly order: number;
  readonly values: readonly string[];
  readonly booleans: readonly string[];
  readonly operations: readonly string[];
  readonly positional?: string;
  readonly ceiling?: number;
  readonly fields?: readonly string[];
}
const list = ["filter", "limit", "cursor"];
const detection = ["filter", "severity", "status", "product", "since"];
const host = ["filter", "hostname", "platform", "status", "since"];
const declarations: Command[] = [
  {
    name: "auth status",
    summary:
      "  auth status               whether a credential resolved, and where to",
    order: 2400,
    values: [],
    booleans: [],
    operations: [],
  },
  {
    name: "config path",
    summary: "  config path               config and write-journal paths",
    order: 2600,
    values: [],
    booleans: [],
    operations: [],
  },
  {
    name: "profile list",
    summary:
      "  profile list              configured profile names, without reading secrets",
    order: 2500,
    values: [],
    booleans: [],
    operations: [],
  },
  {
    name: "scopes",
    summary:
      "  scopes                    the command-to-scope matrix, with no request made",
    order: 2700,
    values: [],
    booleans: [],
    operations: [],
  },
  {
    name: "detection list",
    summary:
      "  detection list            list detections from the Falcon Alerts collection",
    order: 200,
    fields: [
      "id",
      "severity",
      "tactic",
      "hostname",
      "status",
      "technique",
      "created_timestamp",
    ],
    values: [...detection, "limit", "cursor", "max-rows", "fields"],
    booleans: ["all"],
    ceiling: 10000,
    operations: ["GetQueriesAlertsV2", "PostEntitiesAlertsV2"],
  },
  {
    name: "detection summary",
    summary: "  detection summary         counts of detections by severity",
    order: 100,
    values: detection,
    booleans: [],
    operations: ["PostAggregatesAlertsV2"],
  },
  {
    name: "detection show",
    summary: "  detection show <id>       the full detail for one detection",
    order: 300,
    values: [],
    booleans: ["full"],
    positional: "detection identifier",
    operations: ["PostEntitiesAlertsV2"],
  },
  {
    name: "detection process",
    summary:
      "  detection process <id>    process lineage recorded on one detection",
    order: 350,
    values: [],
    booleans: ["full"],
    positional: "detection identifier",
    operations: ["PostEntitiesAlertsV2"],
  },
  {
    name: "host list",
    summary:
      "  host list                 list hosts from the Falcon Hosts collection",
    order: 400,
    fields: [
      "device_id",
      "hostname",
      "platform",
      "last_seen",
      "os_version",
      "agent_version",
      "status",
      "first_seen",
      "machine_domain",
    ],
    values: [...host, "limit", "cursor", "max-rows", "fields"],
    booleans: ["all"],
    ceiling: 5000,
    operations: ["QueryDevicesByFilter", "PostDeviceDetailsV2"],
  },
  {
    name: "host show",
    summary: "  host show <device id>     the full detail for one host",
    order: 500,
    values: [],
    booleans: [],
    positional: "device identifier",
    operations: ["PostDeviceDetailsV2"],
  },
  {
    name: "host logins",
    summary:
      "  host logins <device id>   recent interactive logins on one host",
    order: 600,
    values: ["hostname", "since", "limit"],
    booleans: [],
    positional: "device identifier",
    ceiling: 100,
    operations: ["QueryDeviceLoginHistoryV2", "QueryDevicesByFilter"],
  },
  {
    name: "host network",
    summary:
      "  host network <device id>  IP and MAC address history for one host",
    order: 601,
    values: ["hostname"],
    booleans: [],
    positional: "device identifier",
    operations: ["QueryGetNetworkAddressHistoryV1", "QueryDevicesByFilter"],
  },
  {
    name: "ioc list",
    summary: "  ioc list                  list custom indicators",
    order: 2304,
    values: list,
    booleans: [],
    ceiling: 500,
    operations: ["indicator_search_v1", "indicator_get_v1"],
  },
  {
    name: "ioc show",
    summary: "  ioc show <id>             read one custom indicator",
    order: 2305,
    values: [],
    booleans: [],
    positional: "IOC identifier",
    operations: ["indicator_get_v1"],
  },
  {
    name: "ioc hosts",
    summary: "  ioc hosts <type:value>  list observed hosts for a custom IOC",
    order: 2306,
    values: ["limit", "cursor"],
    booleans: [],
    positional: "indicator type:value",
    ceiling: 100,
    operations: ["DevicesRanOn"],
  },
  {
    name: "ioc processes",
    summary:
      "  ioc processes <type:value>  list observed processes for a custom IOC",
    order: 2307,
    values: ["host", "limit", "cursor"],
    booleans: [],
    positional: "indicator type:value",
    ceiling: 100,
    operations: ["ProcessesRanOn"],
  },
  {
    name: "file-change list",
    summary: "  file-change list              list FileVantage change history",
    order: 2307.81,
    values: list,
    booleans: [],
    ceiling: 5000,
    operations: ["highVolumeQueryChanges", "getChanges"],
  },
  {
    name: "file-change show",
    summary: "  file-change show <id>         inspect one FileVantage change",
    order: 2307.82,
    values: [],
    booleans: [],
    positional: "file change identifier",
    operations: ["getChanges"],
  },
  {
    name: "process show",
    summary: "  process show <pid-id>     read one observed process",
    order: 2307.5,
    values: [],
    booleans: ["full"],
    positional: "process identifier",
    operations: ["entities_processes"],
  },
  {
    name: "process tree",
    summary:
      "  process tree <pid-id>     process, up to five ancestors, and one child level",
    order: 2307.6,
    values: ["cursor"],
    booleans: ["full"],
    positional: "process graph identifier",
    operations: ["combined_summary_get", "combined_edges_get"],
  },
  {
    name: "rtr session list",
    summary: "  rtr session list           read sessions",
    order: 2380,
    values: list,
    booleans: [],
    ceiling: 5000,
    operations: ["RTR_ListAllSessions", "RTR_ListSessions"],
  },
  {
    name: "rtr session show",
    summary: "  rtr session show <id>      read one record",
    order: 2381,
    values: [],
    booleans: ["full"],
    positional: "identifier",
    operations: ["RTR_ListSessions"],
  },
  {
    name: "rtr audit list",
    summary: "  rtr audit list             read audit_sessions",
    order: 2382,
    values: list,
    booleans: [],
    ceiling: 1000,
    operations: ["RTRAuditSessions"],
  },
];
export const commands: readonly Command[] = declarations.sort(
  (a, b) => a.order - b.order,
);
export const valueFlags: readonly string[] = [
  "--config",
  "--profile",
  "--region",
  "--member-cid",
];
export const boolFlags: readonly string[] = [
  "--help",
  "--allow-unknown-origin",
  "--no-member-cid",
];
export const commandNames = commands.map((command) => command.name);
for (const flag of [
  ...valueFlags,
  ...boolFlags,
  ...commands.flatMap((command) => [...command.values, ...command.booleans]),
])
  if (/(secret|password|token|key|passphrase)/i.test(flag))
    throw new Error(`secret-shaped flag ${flag} is forbidden`);
