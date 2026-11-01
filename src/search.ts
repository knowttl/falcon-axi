import { setTimeout as delay } from "node:timers/promises";
import { CliError, object } from "./core.js";
import { Domain, text, quote } from "./domain.js";
import type { Output } from "./domain.js";
import type { Invocation } from "./parser.js";
import { Raw } from "./render.js";
import { requestException } from "./transport/https.js";
import { pathValue, searchBody } from "./transport/search-authority.js";
import { validateQuery } from "./cql.js";
import { observeRate, responseFailure } from "./auth.js";
import { malformed } from "./response.js";

export function seconds(since: string): number {
  const match = /^(\d+)([mhd])$/i.exec(since);
  const value = match
    ? Number(match[1]) * { m: 60, h: 3600, d: 86400 }[match[2]!.toLowerCase()]!
    : 0;
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new CliError(
      "VALIDATION_ERROR",
      "--since must be a relative window such as 24h",
      [
        "valid units for --since: m (minutes), h (hours), d (days)",
        "Example: `--since 7d`",
      ],
    );
  return value;
}
export function activityQuery(subject: string): string {
  const guid = /^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$/.test(
    subject,
  );
  if (!guid && !/^[A-Za-z0-9._@$-]{1,256}$/.test(subject))
    throw new CliError(
      "VALIDATION_ERROR",
      "identity activity takes an account objectGUID or an account name",
      [
        "An account name may contain letters, digits, and `. _ @ $ -` only; no wildcard is accepted",
        "Run `falcon-axi detection show <id>` for an identity detection's account and account_id",
      ],
    );
  const fields = guid
    ? [
        "SourceAccountObjectGuid",
        "PerformedOnAccountObjectGuid",
        "AccountObjectGuid",
      ]
    : [
        "SourceAccountSamAccountName",
        "SourceAccountUserName",
        "PerformedOnAccountName",
        "SamAccountName",
      ];
  const pattern = guid
    ? subject
    : subject.replaceAll(".", "\\.").replaceAll("$", "\\$");
  return `#event_simpleName=/^(ActiveDirectory|Sso|IdpEntityRiskScoreChange)/ | ${fields.map((field) => `${field}=/^${pattern}$/i`).join(" OR ")} | table([@timestamp, #event_simpleName, SourceAccountSamAccountName, SourceAccountUserName, PerformedByAccountObjectName, PerformedOnAccountName, SourceEndpointHostName, source.ip, TargetServiceAccessIdentifier, ActiveDirectoryAuditActionType], limit=200, sortby=@timestamp, order=desc)`;
}
export function usbQuery(id: string): string {
  if (!/^[a-fA-F0-9]{32}$/.test(id))
    throw new CliError(
      "VALIDATION_ERROR",
      "host usb requires a 32-character hexadecimal device id (AID)",
      ["Run `falcon-axi host list` to see current device identifiers"],
    );
  return `#event_simpleName=/^(DcUsbDeviceConnected|DcUsbDeviceDisconnected|DcUsbDevicePolicyViolation)$/ aid=${id.toLowerCase()} | table([@timestamp, #event_simpleName, ComputerName, DeviceManufacturer, DeviceProduct, DevicePropertyDeviceDescription, DeviceUsbClass, DcPolicyAction, event_platform], limit=200, sortby=@timestamp, order=desc)`;
}
export function validateSearch(invocation: Invocation): void {
  const { command, flags, id, limit } = invocation;
  if (
    flags.has("--wait") &&
    (!/^\d+$/.test(flags.get("--wait")!) ||
      Number(flags.get("--wait")) < 1 ||
      Number(flags.get("--wait")) > 50)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "--wait must be an integer from 1 to 50 seconds",
    );
  if (command.name === "search start")
    validateQuery(flags.get("--query") ?? "");
  if (command.name.startsWith("search ")) {
    pathValue("repository", flags.get("--repository") ?? "search-all");
    if (id) pathValue("id", id);
  }
  if (command.name === "identity activity") activityQuery(id!);
  if (command.name === "host usb") usbQuery(id!);
  if (command.name === "malquery search")
    searchBody(flags.get("--string"), flags.get("--hex"), limit);
  if (command.name === "malquery show" && !/^[a-fA-F0-9]{64}$/.test(id!))
    throw new CliError(
      "VALIDATION_ERROR",
      "sha256 requires exactly 64 hex characters",
    );
  if (
    command.name === "malquery status" &&
    !/^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$/.test(id!)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "MalQuery request id must be a UUID",
    );
}
export async function search(domain: Domain): Promise<Output> {
  const { command, flags } = domain.invocation;
  const repository = flags.get("--repository") ?? "search-all";
  const since = flags.get("--since") ?? "24h";
  const wait = Number(flags.get("--wait") ?? 0);
  let id = domain.invocation.id!;
  let submitted: string | undefined;
  const follow = (verb: string): string =>
    `falcon-axi search ${verb} ${quote(id)}${repository === "search-all" ? "" : ` --repository ${quote(repository)}`}`;
  const request = async (operation: string, body?: unknown) => {
    const response = await requestException(
      operation,
      domain.session.base,
      domain.session.token,
      operation === "StartSearchV1" ? { repository, body } : { repository, id },
      domain.allowUnknown,
      domain.signal,
    );
    observeRate(domain.session, response);
    if (response.status === 404 && operation !== "StartSearchV1")
      throw new CliError(
        "NOT_FOUND",
        "no NG-SIEM search job matched that identifier",
        [
          "A job id comes from `falcon-axi search start`, and a completed or cancelled job expires",
          "Pass the same `--repository` the job was started against",
        ],
      );
    if (operation === "StartSearchV1" && [400, 404].includes(response.status)) {
      const errors =
        object(response.body) && Array.isArray(response.body.errors)
          ? response.body.errors
          : [];
      const message = errors
        .filter(object)
        .map((entry) => text(entry.message))
        .filter(Boolean)
        .join("; ");
      throw new CliError(
        "VALIDATION_ERROR",
        message || "NG-SIEM rejected this search",
        [
          "CQL is pipe-based and is neither FQL nor SQL: `#event_simpleName=ProcessRollup2 | head(5)`",
          "Check the repository name and the query, then run `falcon-axi search start --help`",
        ],
      );
    }
    if (
      response.status !== 200 &&
      !(operation === "StopSearchV1" && response.status === 204)
    )
      responseFailure(
        response,
        operation === "GetSearchStatusV1"
          ? "NG-SIEM search status"
          : "NG-SIEM searches",
        false,
        false,
        operation,
      );
    return response;
  };
  if (command.name === "search stop") {
    await request("StopSearchV1");
    return {
      value: { stopped: id, repository },
      help: [
        `Run \`${follow("status")}\` to confirm the job reports cancelled`,
        "Run `falcon-axi search start --query '<cql>'` to run a narrower search",
      ],
    };
  }
  if (command.name !== "search status") {
    submitted =
      command.name === "identity activity"
        ? activityQuery(id)
        : command.name === "host usb"
          ? usbQuery(id)
          : flags.get("--query")!;
    const end = Date.now();
    const response = await request("StartSearchV1", {
      queryString: submitted,
      start: end - seconds(since) * 1000,
      end,
    });
    id = object(response.body) ? text(response.body.id)! : undefined!;
    if (!id)
      malformed(
        response,
        "the NG-SIEM search started but returned no job identifier",
        [
          "The creation outcome is unknown; a job may be running. No creation request was replayed",
        ],
      );
    if (!wait)
      return {
        value: {
          search_id: id,
          repository,
          query: submitted,
          window: `the last ${since}`,
        },
        help: [
          `Run \`${follow("status")}\` to poll this job and read its events`,
          `Run \`${follow("stop")}\` to cancel it`,
          "A job keeps running until it completes or is stopped, so stop one you no longer need",
        ],
      };
  }
  let body: Record<string, unknown> = {};
  while (!wait || !domain.signal.aborted) {
    try {
      const response = await request("GetSearchStatusV1");
      body = object(response.body) ? response.body : {};
    } catch (error) {
      if (wait && error instanceof CliError) {
        if (error.code === "WAIT_TIMEOUT") break;
        throw new CliError(
          error.code,
          error.message,
          [
            ...error.help,
            `Run \`${follow("status")}\` to resume polling this job`,
            `Run \`${follow("stop")}\` to cancel it`,
          ],
          { ...error.details, search_id: id, repository },
        );
      }
      throw error;
    }
    if (!wait || body.done || body.cancelled) break;
    try {
      await delay(1000, undefined, { signal: domain.signal });
    } catch {
      break;
    }
  }
  if (body.cancelled)
    return {
      value: { state: "cancelled", search_id: id },
      help: [
        "Run `falcon-axi search start --query '<cql>'` to run the search again",
      ],
    };
  const meta = object(body.metaData) ? body.metaData : {};
  const scanned =
    typeof meta.processedEvents === "number" &&
    Number.isInteger(meta.processedEvents)
      ? { events_scanned: meta.processedEvents }
      : {};
  if (!body.done)
    return {
      value: { state: "running", search_id: id, ...scanned },
      help: [
        `Run \`${follow("status")}${wait ? " --wait 30" : ""}\` again in a few seconds; the job is still running`,
        `Run \`${follow("stop")}\` to cancel it`,
      ],
    };
  const events = Array.isArray(body.events) ? body.events.filter(object) : [];
  const parsed = object(meta.filterQuery)
    ? text(meta.filterQuery.queryString)
    : undefined;
  const warnings = Array.isArray(body.warnings)
    ? body.warnings
        .filter(object)
        .filter((entry) => typeof entry.message === "string")
        .map((entry) => ({ code: entry.code ?? null, message: entry.message }))
    : [];
  const help: string[] = [];
  if (
    parsed &&
    submitted &&
    !(
      submitted.trim() === parsed.trim() ||
      (submitted.trim().startsWith(parsed.trim()) &&
        submitted
          .trim()
          .slice(parsed.trim().length)
          .trimStart()
          .startsWith("|"))
    )
  )
    help.push(
      "The normalized filter differs from the submitted filter; review parsed_query for words treated as free text. Normalization can also change formatting; this is advisory",
    );
  help.push(
    "parsed_query echoes the filter part only; stages after the first pipe are not echoed. Compare it with the filter you sent: NG-SIEM turns an unrecognised word into a free-text stage rather than an error",
    "Bound a large result set in the query itself, with `| head(N)` or an aggregate such as `groupBy([...], function=count())`",
  );
  return {
    value: {
      state: "done",
      count: new Raw(
        `${events.length} of ${typeof meta.eventCount === "number" && Number.isInteger(meta.eventCount) ? meta.eventCount : "unknown"} matching events`,
      ),
      ...scanned,
      ...(parsed ? { parsed_query: parsed } : {}),
      ...(warnings.length ? { warnings } : {}),
      events: events.length ? events : new Raw("0 events matched this search"),
    },
    help,
  };
}
