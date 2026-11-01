import { CliError, object } from "./core.js";
import type { Invocation } from "./parser.js";
import type { Credential } from "./credentials.js";
import type { Session } from "./auth.js";
import { responseFailure } from "./auth.js";
import { requestRead } from "./transport/https.js";
import { malformed } from "./response.js";
import { Cursor } from "./cursor.js";
import { Raw } from "./render.js";

export type RecordValue = Record<string, unknown>;
export type Query = Record<string, string | number | readonly string[]>;
export interface Output {
  value: RecordValue;
  help: string[];
}
export const text = (value: unknown): string | undefined =>
  typeof value === "string" && value ? value : undefined;
export const quote = (value: string): string =>
  /^[\w@%+=:,./-]+$/.test(value)
    ? value
    : `'${value.replaceAll("'", `'"'"'`)}'`;
export const project = (
  record: RecordValue,
  fields: readonly string[],
): RecordValue =>
  Object.fromEntries(
    fields.map((field) => [field, record[field] ?? "unknown"]),
  );

export class Domain {
  readonly suggestion: string;
  constructor(
    readonly invocation: Invocation,
    readonly credential: Credential,
    readonly session: Session,
    readonly allowUnknown: boolean,
    readonly signal: AbortSignal,
  ) {
    const { command, flags, id } = invocation;
    const values = /^(exclusion|policy) /.test(command.name)
      ? [...command.values.filter((value) => value !== "type"), "type"]
      : command.values;
    this.suggestion = `falcon-axi ${command.name}${id ? ` ${quote(id)}` : ""}${flags.has("--all") ? " --all" : ""}${values
      .filter((key) => key !== "cursor" && flags.has(`--${key}`))
      .map(
        (key) =>
          ` --${key} ${quote(key === "filter" && /\b(?:cid|member_cid)\s*:/i.test(flags.get(`--${key}`)!) ? "<original-filter>" : flags.get(`--${key}`)!)}`,
      )
      .join("")}`;
  }
  async response(
    operation: string,
    subject: string,
    query: Query = {},
    body?: unknown,
    missing = false,
  ) {
    const response = await requestRead(
      operation,
      this.session.base,
      this.session.token,
      query,
      body,
      this.allowUnknown,
      this.signal,
    );
    if (response.status === 404 && !missing) {
      const noun = this.invocation.command.name.startsWith("identity sensor ")
        ? "identity sensor"
        : this.invocation.command.name.split(" ")[0]!;
      throw new CliError(
        "NOT_FOUND",
        noun === "host-group"
          ? "no host group matched that identifier"
          : `no ${subject} matched that identifier`,
        [
          `Run \`falcon-axi ${noun} list${noun === "policy" ? ` --type ${this.invocation.flags.get("--type")}` : ""}\`${noun === "host-group" ? "" : " to see current identifiers"}`,
        ],
      );
    }
    if (
      response.status === 403 &&
      operation === "GetVulnerabilities" &&
      this.invocation.command.name === "cve show"
    ) {
      try {
        responseFailure(response, subject, false, false, operation);
      } catch (error) {
        if (error instanceof CliError && error.code === "SCOPE_DENIED")
          throw new CliError(
            error.code,
            error.message,
            [
              ...error.help,
              "This scope requires a Falcon Intelligence subscription; Spotlight's Vulnerabilities:read does not satisfy it",
              "If the scope is missing from the API client picker, ask your Falcon administrator about the license",
            ],
            error.details,
          );
        throw error;
      }
    }
    if (response.status !== 200 && !(missing && response.status === 404))
      responseFailure(response, subject, false, false, operation);
    return response;
  }
  async read(
    operation: string,
    subject: string,
    query: Query = {},
    body?: unknown,
    missing = false,
  ) {
    const response = await this.response(
      operation,
      subject,
      query,
      body,
      missing,
    );
    if (missing && response.status === 404)
      return {
        rows: [] as unknown[],
        total: undefined,
        pagination: {} as RecordValue,
        meta: {} as RecordValue,
      };
    const envelope = object(response.body) ? response.body : {};
    const rows: unknown =
      operation === "GetSensorUsageWeekly" && Array.isArray(response.body)
        ? response.body
        : envelope.resources;
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
    return { rows: rows as unknown[], total, pagination, meta };
  }
  async hydrate(
    operation: string,
    subject: string,
    ids: string[],
    key = "id",
    body = false,
  ): Promise<RecordValue[]> {
    const records = new Map<string, RecordValue>();
    const chunk = operation === "GetSensorDetails" ? 200 : 100;
    for (let start = 0; start < ids.length; start += chunk) {
      const batch = ids.slice(start, start + chunk);
      const result = await this.read(
        operation,
        subject,
        body ? {} : { ids: batch },
        body ? { ids: batch } : undefined,
        ["get_accounts", "get_iot_hosts", "GetVulnerabilities"].includes(
          operation,
        ),
      );
      for (const row of result.rows)
        if (object(row) && text(row[key])) records.set(String(row[key]), row);
    }
    return ids.flatMap((id) => (records.has(id) ? [records.get(id)!] : []));
  }
  cursor(
    operation: string,
    filter?: string,
    model: "offset" | "token" | "marker" | "offset-or-token" = "offset",
    sort: string | null = null,
  ): Cursor {
    return new Cursor(
      this.credential,
      this.session.base,
      operation,
      filter,
      model,
      sort,
    );
  }
  continuation(
    output: Output,
    context: Cursor,
    next: string | number | undefined,
  ): void {
    if (next === undefined) return;
    const token = context.encode(next);
    output.value.continuation_cursor = token;
    output.help.push(
      `Run \`${this.suggestion}${this.invocation.flags.has("--full") ? " --full" : ""} --cursor ${token}\` for the next page`,
    );
  }
}
export const count = (
  rows: readonly unknown[],
  total: number | undefined,
): Raw => new Raw(`${rows.length} of ${total ?? "unknown"} total`);
export const ids = (rows: unknown[]): string[] =>
  rows.filter((row): row is string => typeof row === "string");
export const more = (
  length: number,
  offset: number,
  total: number | undefined,
  limit: number,
): boolean =>
  length > 0 &&
  (total === undefined ? length >= limit : offset + length < total);
