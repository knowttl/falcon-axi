import { CliError, object } from "./core.js";
import { Domain, project } from "./domain.js";
import type { Output } from "./domain.js";
import { Raw } from "./render.js";
import { searchBody } from "./transport/search-authority.js";
import { requestException, requestRead } from "./transport/https.js";
import { observeRate, responseFailure } from "./auth.js";
import { malformed } from "./response.js";

const quotaFields = [
  "days_left",
  "download_count",
  "download_counts",
  "download_limit",
  "hunt_count",
  "hunt_counts",
  "hunt_limit",
  "monitor_count",
  "monitor_limit",
  "refresh_time",
];
export async function malquery(domain: Domain): Promise<Output> {
  const { command, flags, id, limit } = domain.invocation;
  const submit = command.name === "malquery search";
  const status = command.name === "malquery status";
  const metadata = command.name === "malquery show";
  const fuzzy = flags.has("--fuzzy");
  const operation = submit
    ? fuzzy
      ? "PostMalQueryFuzzySearchV1"
      : "PostMalQueryExactSearchV1"
    : command.operations[0]!;
  const response = submit
    ? await requestException(
        operation,
        domain.session.base,
        domain.session.token,
        { body: searchBody(flags.get("--string"), flags.get("--hex"), limit) },
        domain.allowUnknown,
        domain.signal,
      )
    : await requestRead(
        operation,
        domain.session.base,
        domain.session.token,
        id ? { ids: [metadata ? id.toLowerCase() : id] } : {},
        undefined,
        domain.allowUnknown,
        domain.signal,
      );
  observeRate(domain.session, response);
  if (response.status === 400 && (submit || status))
    throw new CliError(
      "UPSTREAM_ERROR",
      "Falcon rejected the MalQuery patterns or request",
      [
        "Check `falcon-axi malquery search --help` for the supported literal pattern grammar",
      ],
    );
  if (response.status === 404)
    throw new CliError(
      "NOT_FOUND",
      `no ${metadata ? "MalQuery metadata" : status || submit ? "MalQuery search" : "MalQuery quota"} matched that identifier`,
      ["Run `falcon-axi malquery quota` to see current identifiers"],
    );
  if (response.status !== 200)
    responseFailure(
      response,
      metadata
        ? "MalQuery metadata"
        : status || submit
          ? "MalQuery search"
          : "MalQuery quota",
      false,
      false,
      operation,
    );
  const body = object(response.body) ? response.body : {};
  const invalid = (): never =>
    malformed(
      response,
      submit || status
        ? "Falcon returned an invalid MalQuery search response"
        : "Falcon returned an invalid MalQuery response",
    );
  if (body.errors && (!Array.isArray(body.errors) || body.errors.length))
    invalid();
  if (metadata) {
    const rows = Array.isArray(response.body) ? response.body : body.resources;
    if (!Array.isArray(rows)) return invalid();
    if (!rows.length)
      return {
        value: {
          malquery: new Raw(
            "0 indexed files for that SHA-256; no MalQuery metadata found. No data or missing Falcon MalQuery licensing can cause an empty result",
          ),
        },
        help: [],
      };
    if (
      rows.length !== 1 ||
      !object(rows[0]) ||
      typeof rows[0].sha256 !== "string" ||
      rows[0].sha256.toLowerCase() !== id!.toLowerCase()
    )
      return invalid();
    return {
      value: {
        malquery: project(rows[0], [
          "family",
          "filesize",
          "filetype",
          "first_seen",
          "label",
          "md5",
          "sha1",
          "sha256",
        ]),
      },
      help: [],
    };
  }
  if (!object(body.meta)) return invalid();
  const meta = body.meta;
  if (!submit && !status) {
    if (!quotaFields.some((field) => Object.hasOwn(meta, field)))
      return invalid();
    return { value: { quota: project(meta, quotaFields) }, help: [] };
  }
  const value: Record<string, unknown> = {};
  if (status || !fuzzy) {
    if (
      typeof meta.reqid !== "string" ||
      !/^[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}$/.test(
        meta.reqid,
      ) ||
      typeof meta.status !== "string" ||
      !meta.status.trim() ||
      (status && meta.reqid.toLowerCase() !== id!.toLowerCase())
    )
      return invalid();
    value.request = { id: meta.reqid, status: meta.status };
    if (submit)
      return {
        value,
        help: [
          `Run \`falcon-axi malquery status ${meta.reqid}\` for status and results`,
        ],
      };
  }
  const records = body.resources ?? (status ? [] : undefined);
  if (!Array.isArray(records) || records.some((record) => !object(record)))
    return invalid();
  const rows = records
    .slice(0, limit)
    .map((record: unknown) =>
      project(record as Record<string, unknown>, [
        "sha256",
        "family",
        "filetype",
        "filesize",
      ]),
    );
  const pagination = object(meta.pagination) ? meta.pagination : {};
  const total =
    typeof pagination.total === "number" && Number.isInteger(pagination.total)
      ? pagination.total
      : undefined;
  value.count = new Raw(
    total === undefined
      ? `${rows.length} shown; total unknown`
      : `${rows.length} of ${total} total`,
  );
  value.samples = rows.length
    ? rows
    : new Raw(
        status
          ? "0 samples returned; the request may still be running, no patterns matched, or Falcon MalQuery licensing is absent"
          : "0 samples matched; no data or missing Falcon MalQuery licensing can cause an empty result",
      );
  const help: string[] = [];
  if (
    records.length > limit ||
    (total !== undefined && total > rows.length) ||
    (total === undefined && records.length === limit)
  ) {
    value.partial = true;
    help.push(
      "Results reached the requested limit; narrow the patterns to avoid an incomplete result",
    );
  }
  if (rows.length)
    help.push(
      "Run `falcon-axi malquery show <sha256>` for indexed file metadata",
    );
  if (status)
    help.push(
      `Run \`falcon-axi malquery status ${meta.reqid} --limit ${limit}\` to read the request again`,
    );
  return { value, help };
}
