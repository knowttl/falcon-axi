import { CliError, object } from "./core.js";
import { Domain, text } from "./domain.js";
import type { Output, RecordValue } from "./domain.js";
import type { Invocation } from "./parser.js";
import { Raw } from "./render.js";
import { seconds } from "./search.js";
import { requestException } from "./transport/https.js";
import { document } from "./transport/search-authority.js";
import { observeRate, responseFailure } from "./auth.js";
import { malformed } from "./response.js";

const mapping = (value: unknown): RecordValue => (object(value) ? value : {});
const objects = (value: unknown): RecordValue[] =>
  Array.isArray(value) ? value.filter(object) : [];
const nodes = (value: unknown): RecordValue[] => objects(mapping(value).nodes);
const cell = (value: unknown): string => text(value) ?? "unknown";
const categories = [
  "activity",
  "notification",
  "threat",
  "entity",
  "audit",
  "policy",
  "system",
];
export function parseCategories(value: string): string[] {
  const names = value.split(",").map((name) => name.trim().toLowerCase());
  const unknown = names.filter((name) => !categories.includes(name));
  if (unknown.length)
    throw new CliError(
      "VALIDATION_ERROR",
      `unknown --category ${unknown.map((name) => name || "(empty)").join(", ")}`,
      [`valid values for --category: ${categories.join(", ")}`],
    );
  return [...new Set(names)];
}
export function entityId(value: string): string {
  const candidate = value.trim();
  const compact = candidate
    .replace(/^urn:uuid:/, "")
    .replaceAll("{", "")
    .replaceAll("}", "")
    .replaceAll("-", "");
  if (!/^[a-fA-F0-9]{32}$/.test(compact))
    throw new CliError(
      "VALIDATION_ERROR",
      "an identity id must be an entity GUID",
      [
        "Run `falcon-axi identity list --name '<name>'` to find an identity id",
        "For an Active Directory user the id may be the account object GUID, as in an identity detection's `source_account_object_guid`, which is unverified",
      ],
    );
  return candidate;
}
export function validateIdentity({ command, flags, id }: Invocation): void {
  if (["identity list", "identity assessment"].includes(command.name)) {
    const type = flags.get("--type");
    if (
      type !== undefined &&
      !["user", "endpoint"].includes(type.toLowerCase())
    )
      throw new CliError("VALIDATION_ERROR", `unknown type ${type}`, [
        "valid values for --type: user, endpoint",
      ]);
    for (const flag of ["name", "email"])
      if (
        flags.has(`--${flag}`) &&
        !flags.get(`--${flag}`)!.replaceAll("*", "").trim()
      )
        throw new CliError(
          "VALIDATION_ERROR",
          `--${flag} requires a value, and a bare wildcard matches every identity`,
          [`Pass a more specific pattern, for example \`--${flag} 'Admin*'\``],
        );
    if (flags.has("--domain") && !flags.get("--domain")!.trim())
      throw new CliError("VALIDATION_ERROR", "--domain requires a value");
  }
  if (["identity show", "identity timeline"].includes(command.name))
    entityId(id!);
  if (command.name === "identity timeline") {
    if (flags.has("--category")) parseCategories(flags.get("--category")!);
    seconds(flags.get("--since") ?? "7d");
  }
}
const risk = (node: RecordValue): string =>
  `${cell(node.riskScoreSeverity)}${typeof node.riskScore === "number" ? ` (${node.riskScore})` : ""}`;
const summary = (node: RecordValue): RecordValue => ({
  id: cell(node.entityId),
  name: cell(node.primaryDisplayName),
  secondary: cell(node.secondaryDisplayName),
  type: cell(node.type),
  risk: risk(node),
});

export async function identity(domain: Domain): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const query = async (
    name: string,
    variables: RecordValue,
    subject: string,
  ): Promise<RecordValue> => {
    const response = await requestException(
      "api_preempt_proxy_post_graphql",
      domain.session.base,
      domain.session.token,
      { document: name, variables },
      domain.allowUnknown,
      domain.signal,
    );
    observeRate(domain.session, response);
    if (response.status === 403) {
      const scopes = [
        "Identity Protection GraphQL:write",
        ...document(name).readScopes,
      ];
      throw new CliError(
        "SCOPE_DENIED",
        `this API client is not permitted to read ${subject}`,
        [
          `Grant ${scopes.join(" and ")} to the API client in the Falcon console under Support and resources > API clients and keys`,
          "The GraphQL scope is labelled write because Falcon requires it even for read-only queries; falcon-axi sends only its own fixed read queries (captain exception N2)",
          "The Identity Protection scopes appear in the console only for tenants licensed for Falcon Identity Protection",
          "Run `falcon-axi scopes` for the matrix",
        ],
        { required_scopes: scopes },
      );
    }
    if (response.status !== 200)
      responseFailure(
        response,
        subject,
        false,
        false,
        "api_preempt_proxy_post_graphql",
      );
    const body = mapping(response.body);
    if (
      (body.errors && (!Array.isArray(body.errors) || body.errors.length)) ||
      !object(body.data)
    ) {
      try {
        malformed(
          response,
          `Falcon reported an error while answering the Identity Protection query for ${subject}`,
          [
            "Retry shortly",
            "Quote the trace_id when opening a CrowdStrike support case",
          ],
        );
      } catch (error) {
        if (
          error instanceof CliError &&
          object(body.meta) &&
          typeof body.meta.trace_id === "string"
        )
          throw new CliError(error.code, error.message, error.help, {
            ...error.details,
            trace_id: body.meta.trace_id,
          });
        throw error;
      }
    }
    return body.data as RecordValue;
  };
  if (command.name === "identity assessment") {
    const name = flags.get("--domain");
    const data = await query(
      "identity_assessment",
      name === undefined ? {} : { domain: name },
      "identity security assessment",
    );
    const assessment = mapping(data.securityAssessment);
    if (!Object.keys(assessment).length)
      return {
        value: { assessment: "0 security assessments" },
        help: [
          "Run `falcon-axi identity assessment --domain <name>` for a configured domain",
        ],
      };
    return {
      value: {
        assessment: {
          ...(name === undefined ? {} : { domain: name }),
          score: assessment.overallScore ?? null,
          level: cell(assessment.overallScoreLevel),
          factors: objects(assessment.assessmentFactors).map((factor) => ({
            type: cell(factor.riskFactorType),
            severity: cell(factor.severity),
            likelihood: cell(factor.likelihood),
          })),
        },
      },
      help: [],
    };
  }
  if (command.name === "identity show") {
    const data = await query(
      "identity_show",
      { entityIds: [entityId(id!)] },
      "identities",
    );
    const node = nodes(data.entities)[0];
    if (!node)
      throw new CliError("NOT_FOUND", "no identity matched that identifier", [
        "Run `falcon-axi identity list --name '<name>'` to find current identity ids",
      ]);
    const associations = objects(node.associations).map((entry) => {
      const related = mapping(entry.entity),
        place = mapping(entry.geoLocation);
      return {
        ["binding"]: cell(entry.bindingType),
        name:
          text(related.primaryDisplayName) ??
          text(entry.accountName) ??
          ([text(place.city), text(place.country)].filter(Boolean).join(", ") ||
            "unknown"),
        ...(text(related.entityId) ? { entity_id: related.entityId } : {}),
      };
    });
    const shown = flags.has("--full")
      ? associations
      : associations.slice(0, 25);
    const detail: RecordValue = {
      ...summary(node),
      risk_factors: objects(node.riskFactors).map((factor) => ({
        type: cell(factor.type),
        severity: cell(factor.severity),
      })),
      accounts: objects(node.accounts).map((account) =>
        Object.fromEntries(
          Object.entries({
            domain: account.domain,
            account: account.samAccountName,
            source: account.dataSource,
            title: account.title,
            ou: account.ou,
            password_last_changed: mapping(account.passwordAttributes)
              .lastChange,
            expires: account.expirationTime,
          }).filter(([, value]) => text(value)),
        ),
      ),
      associations: shown,
      open_incidents: nodes(node.openIncidents).map((incident) => ({
        type: cell(incident.type),
        start: cell(incident.startTime),
        end: cell(incident.endTime),
        compromised:
          objects(incident.compromisedEntities)
            .map((entry) => text(entry.primaryDisplayName))
            .filter(Boolean)
            .join(",") || "unknown",
      })),
    };
    const help = [
      `Run \`falcon-axi identity timeline ${detail.id}\` for this identity's recent activity`,
    ];
    if (shown.length < associations.length) {
      detail.associations_total = associations.length;
      help.push(
        `Run \`falcon-axi identity show ${detail.id} --full\` to list every association`,
      );
    }
    if (mapping(mapping(node.openIncidents).pageInfo).hasNextPage === true) {
      detail.open_incidents_partial = true;
      help.push(
        `Open incidents are limited to the first ${nodes(node.openIncidents).length}; more exist in Falcon. --full expands associations only`,
      );
    }
    return { value: { identity: detail }, help };
  }
  const timeline = command.name === "identity timeline";
  const since = flags.get("--since") ?? "7d";
  const chosen = flags.has("--category")
    ? parseCategories(flags.get("--category")!)
    : [];
  const type = flags.get("--type")?.toLowerCase();
  const fingerprint = timeline
    ? [entityId(id!).toLowerCase(), since.toLowerCase(), chosen.join(",")].join(
        "|",
      )
    : JSON.stringify([
        type ?? null,
        flags.get("--name") ?? null,
        flags.get("--email") ?? null,
        flags.get("--domain") ?? null,
      ]);
  const context = domain.cursor(
    "api_preempt_proxy_post_graphql",
    fingerprint,
    "token",
  );
  const variables: RecordValue = { first: limit };
  let start = new Date(Date.now() - seconds(since) * 1000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
  if (timeline) {
    variables.entityIds = [entityId(id!)];
    if (chosen.length)
      variables.categories = chosen.map((name) => name.toUpperCase());
  } else {
    for (const key of ["name", "email"])
      if (flags.has(`--${key}`)) variables[key] = flags.get(`--${key}`)!;
    if (flags.has("--domain")) variables.domains = [flags.get("--domain")!];
  }
  if (flags.has("--cursor")) {
    const after = context.decode(flags.get("--cursor")!) as string;
    if (timeline) {
      const separator = after.indexOf("|");
      start = separator < 0 ? after : after.slice(0, separator);
      variables.after = separator < 0 ? "" : after.slice(separator + 1);
    } else variables.after = after;
  }
  if (timeline) variables.startTime = start;
  const data = await query(
    timeline
      ? "identity_timeline"
      : type === "user"
        ? "identity_list_users"
        : type === "endpoint"
          ? "identity_list_endpoints"
          : "identity_list",
    variables,
    timeline ? "identity timelines" : "identities",
  );
  const connection = mapping(data[timeline ? "timeline" : "entities"]);
  const rows = nodes(connection);
  if (!rows.length) {
    const describe = [
      type,
      flags.has("--name") ? `name ${flags.get("--name")}` : undefined,
      flags.has("--email") ? `email ${flags.get("--email")}` : undefined,
      flags.has("--domain") ? `domain ${flags.get("--domain")}` : undefined,
    ]
      .filter(Boolean)
      .join(" ");
    return timeline
      ? {
          value: { events: `0 events for this identity in the last ${since}` },
          help: [
            `Run \`falcon-axi identity timeline ${entityId(id!)} --since 30d\` to widen the window`,
            `Run \`falcon-axi identity show ${entityId(id!)}\` to confirm the identity exists`,
          ],
        }
      : {
          value: {
            identities: `0 identities${describe ? ` matching ${describe}` : ""}`,
          },
          help: [
            "Run `falcon-axi identity list` without filters to see the directory",
            "Name and email patterns accept `*` wildcards, for example `--name 'Admin*'`",
          ],
        };
  }
  const output: Output = {
    value: {
      ...(timeline ? { window: `the last ${since}` } : {}),
      count: new Raw(`${rows.length} shown`),
    },
    help: timeline
      ? [
          `Run \`falcon-axi identity show ${entityId(id!)}\` for this identity's risk, accounts, and associations`,
          `Run \`falcon-axi identity timeline ${entityId(id!)} --category threat\` to narrow to threat events`,
        ]
      : [
          "Run `falcon-axi identity show <id>` for accounts, risk factors, associations, and open incidents",
          "Run `falcon-axi identity timeline <id>` for recent activity",
        ],
  };
  const page = mapping(connection.pageInfo);
  if (page.hasNextPage === true && text(page.endCursor))
    domain.continuation(
      output,
      context,
      timeline ? `${start}|${page.endCursor}` : String(page.endCursor),
    );
  output.value[timeline ? "events" : "identities"] = timeline
    ? rows.map((event) => ({
        time: cell(event.timestamp),
        type: cell(event.eventType),
        severity: cell(event.eventSeverity),
        user:
          text(event.userDisplayName) ??
          cell(mapping(event.sourceEntity).primaryDisplayName),
        endpoint:
          text(event.endpointDisplayName) ??
          cell(mapping(event.targetEntity).primaryDisplayName),
        ip: cell(event.ipAddress),
      }))
    : rows.map(summary);
  return output;
}
