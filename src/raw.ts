import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { observeRate, authenticate } from "./auth.js";
import { CliError, object, parseRawResponse } from "./core.js";
import { writeLogPath } from "./credentials.js";
import type { Credential } from "./credentials.js";
import {
  hasDuplicateJsonMembers,
  isSecretKey,
  positionalSecretPairs,
  Raw,
  redact,
  redactRawEnvelope,
  render,
} from "./render.js";
import { origin } from "./origin.js";
import { openRetainedFile } from "./rtr-filesystem.js";
import { readOnly } from "./rtr-policy.js";
import type { Invocation } from "./parser.js";
import { requestRaw } from "./transport/https.js";
import type { Response } from "./transport/https.js";
import { routeProblem } from "./transport/raw-authority.js";

interface Claim {
  readonly origin: string;
  readonly method: string;
  readonly path: string;
  readonly body: string;
}
const grants = new WeakMap<object, Claim>();
const deny = (): CliError =>
  new CliError(
    "READ_ONLY_VIOLATION",
    "raw write does not match this run's execution authority",
  );
export function consumeRawGrant(
  grant: object | undefined,
  prepared: { origin: string; method: string; path: string; body: string },
): void {
  const claim = grant && grants.get(grant);
  if (
    !claim ||
    readOnly() ||
    claim.origin !== prepared.origin ||
    claim.method !== prepared.method ||
    claim.path !== prepared.path ||
    claim.body !== prepared.body
  )
    throw deny();
  grants.delete(grant!);
}

const BODY_LIMIT = 1024 * 1024;
function readJsonInput(file: string, flag: string): { text: string; value: unknown } {
  try {
    const bytes = readFileSync(file === "-" ? 0 : file);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    if (bytes.length > BODY_LIMIT || hasDuplicateJsonMembers(text))
      throw new Error("invalid input");
    return { text, value };
  } catch {
    throw new CliError(
      "VALIDATION_ERROR",
      `${flag} must contain valid UTF-8 JSON of at most 1 MiB without duplicate members`,
    );
  }
}
interface RawRequest {
  method: string;
  path: string;
  query: string;
  target: string;
  body: string;
}
export function validateRawInvocation(
  invocation: Invocation,
): RawRequest & { executing: boolean; confirm: string | undefined } {
  const { command, flags } = invocation;
  const writing = command.name === "raw write";
  const method = writing ? (flags.get("--method") ?? "").toUpperCase() : "GET";
  const path = flags.get("--path");
  if (writing && !["POST", "PUT", "PATCH", "DELETE"].includes(method))
    throw new CliError(
      "VALIDATION_ERROR",
      "raw write requires --method POST, PUT, PATCH or DELETE",
    );
  if (path === undefined)
    throw new CliError("VALIDATION_ERROR", `${command.name} requires --path`);
  const problem = routeProblem(method, path);
  if (problem) throw new CliError("VALIDATION_ERROR", `--path: ${problem}`);
  const queryText = flags.get("--query") ?? "";
  if (
    queryText.length > 4096 ||
    queryText.startsWith("?") ||
    /[\x00-\x1f\x7f]/.test(queryText)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "--query must be key=value pairs joined by &, at most 4096 characters, without a leading ?",
    );
  const params = new URLSearchParams(queryText);
  const argvEntries = params.size;
  if ([...params.keys()].some(isSecretKey))
    throw new CliError(
      "VALIDATION_ERROR",
      "--query cannot contain secret-named parameters",
      ["Use --query-file <path|-> with a JSON object for secret query values"],
    );
  if ([...params.values()].some((value) => redact(value) !== value))
    throw new CliError(
      "VALIDATION_ERROR",
      "--query cannot contain recognized secret values",
      ["Use --query-file <path|-> with a JSON object for secret query values"],
    );
  const queryFile = flags.get("--query-file");
  if (queryFile === "-" && flags.get("--body-file") === "-")
    throw new CliError(
      "VALIDATION_ERROR",
      "--query-file and --body-file cannot both read stdin",
    );
  if (queryFile !== undefined) {
    const { value } = readJsonInput(queryFile, "--query-file");
    if (
      !object(value) ||
      Object.values(value).some(
        (entry) =>
          typeof entry !== "string" &&
          (!Array.isArray(entry) || entry.some((item) => typeof item !== "string")),
      )
    )
      throw new CliError(
        "VALIDATION_ERROR",
        "--query-file must contain a JSON object with string or string-array values",
      );
    for (const [key, entry] of Object.entries(value))
      for (const item of Array.isArray(entry) ? entry : [entry])
        params.append(key, item as string);
  }
  if (
    [...positionalSecretPairs([...params])].some((index) => index < argvEntries)
  )
    throw new CliError(
      "VALIDATION_ERROR",
      "--query cannot contain values paired with secret names",
      ["Use --query-file <path|-> with a JSON object for secret query values"],
    );
  const query = params.toString();
  if (query.length > 4096)
    throw new CliError("VALIDATION_ERROR", "the combined query exceeds 4096 characters");
  let body = "";
  if (flags.has("--body-file")) {
    if (!writing)
      throw new CliError(
        "VALIDATION_ERROR",
        "--body-file is only valid for raw write",
      );
    const input = readJsonInput(flags.get("--body-file")!, "--body-file");
    if (!(object(input.value) || Array.isArray(input.value)))
      throw new CliError(
        "VALIDATION_ERROR",
        "--body-file must contain one JSON object or array of at most 1 MiB without duplicate members",
      );
    body = input.text;
  }
  const executing = flags.has("--execute");
  if (writing && executing && readOnly())
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "FALCON_AXI_READ_ONLY forbids raw writes",
    );
  if (!writing && (executing || flags.has("--confirm")))
    throw new CliError(
      "VALIDATION_ERROR",
      "--execute and --confirm are only valid for raw write",
    );
  if (flags.has("--confirm") && !executing)
    throw new CliError("VALIDATION_ERROR", "--confirm requires --execute");
  return {
    method,
    path,
    query,
    target: query ? `${path}?${query}` : path,
    body,
    executing,
    confirm: flags.get("--confirm"),
  };
}

function responseBody(response: Response): unknown {
  if (response.binary)
    throw new CliError(
      "UPSTREAM_ERROR",
      "the response is binary, which raw requests do not print",
      [],
      { status: response.status },
    );
  if (
    (object(response.body) || Array.isArray(response.body)) &&
    response.text &&
    hasDuplicateJsonMembers(response.text)
  )
    return response.text;
  return response.body !== undefined
    ? response.body
    : response.text
      ? response.text
      : undefined;
}

function redactQueryPairs(query: string): string {
  const safe = new URLSearchParams();
  const entries = [...new URLSearchParams(query)];
  const pairs = positionalSecretPairs(entries);
  for (const [index, [key, value]] of entries.entries()) {
    safe.append(
      key,
      isSecretKey(key) || pairs.has(index)
        ? "[redacted]"
        : String(redact(value)),
    );
  }
  return safe.toString();
}

function failure(response: Response, writing = false): CliError {
  const { status } = response;
  const body = responseBody(response);
  const details = {
    upstream_status: status,
    ...(body === undefined
      ? {}
      : { upstream_body: body === null ? new Raw("null") : body }),
  };
  if (status >= 300 && status < 400)
    return new CliError(
      "ORIGIN_NOT_ALLOWED",
      "Falcon answered with a redirect and no credential was replayed",
      [],
      details,
    );
  const [code, message, help]: [string, string, string[]] =
    status === 401
      ? [
          "AUTH_FAILED",
          "the Falcon credential was rejected",
          ["Run `falcon-axi auth status` after updating the credential"],
        ]
      : status === 403
        ? [
            "SCOPE_DENIED",
            "this API client is not permitted to call that route",
            [
              "Grant the scope CrowdStrike documents for this route in the Falcon console under Support and resources > API clients and keys",
            ],
          ]
        : status === 404
          ? ["NOT_FOUND", "Falcon has no resource at that path", []]
          : status === 429
            ? [
                "RATE_LIMITED",
                "Falcon rate limited this API client",
                [
                  writing
                    ? "Reconcile the target before retrying"
                    : "Wait for the rate limit window to reset and retry",
                ],
              ]
            : [502, 503, 504].includes(status)
              ? [
                  "UPSTREAM_UNAVAILABLE",
                  "Falcon is temporarily unavailable",
                  [
                    writing
                      ? "Reconcile the target before retrying"
                      : "Retry shortly",
                  ],
                ]
              : [
                  "UPSTREAM_ERROR",
                  "Falcon rejected or could not answer the request",
                  [
                    "Check the path, query and body against CrowdStrike's API reference",
                  ],
                ];
  return new CliError(code, message, help, details);
}

function present(response: Response): Record<string, unknown> {
  const body = responseBody(response);
  return {
    status: response.status,
    content_type: response.headers["content-type"],
    body: body === null ? new Raw("null") : body,
  };
}

export async function rawRun(
  request: ReturnType<typeof validateRawInvocation>,
  credential: Credential,
  base: string,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<void> {
  const { method, path, query, target, body } = request;
  if (method === "GET") {
    const session = await authenticate(credential, base, allowUnknown, signal);
    const response = await requestRaw(
      method,
      path,
      query,
      "",
      undefined,
      session.base,
      session.token,
      allowUnknown,
      signal,
    );
    observeRate(session, response);
    if (response.status < 200 || response.status >= 300)
      throw failure(response);
    process.stdout.write(render(present(response), [], true));
    return;
  }
  if (
    credential.channel !== "file" ||
    !credential.writes?.allowWrites ||
    !credential.writes.operations.includes("raw-write")
  )
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "raw writes require explicit profile opt-in",
      [
        'Set "writes": {"allowWrites": true, "operations": ["raw-write"]} on the selected file profile',
      ],
    );
  const digest = createHash("sha256").update(body).digest("hex");
  const destination = origin(base, allowUnknown);
  const identity = createHash("sha256")
    .update(
      JSON.stringify([
        credential.profile,
        credential.clientId,
        destination,
        credential.memberCid ?? "",
      ]),
    )
    .digest("hex");
  const safeQuery = redactQueryPairs(query);
  const safeTarget = safeQuery ? `${path}?${safeQuery}` : path;
  const queryDigest = createHash("sha256").update(query).digest("hex");
  const confirmationHash = createHash("sha256")
    .update(
      JSON.stringify([
        identity,
        method,
        redact(safeTarget),
        createHash("sha256").update(path).digest("hex"),
        queryDigest,
        digest,
        redact(body),
      ]),
    )
    .digest("hex");
  const confirm = `${credential.profile}:${method} sha256:${confirmationHash}`;
  if (request.executing && request.confirm !== redact(confirm))
    throw new CliError(
      "VALIDATION_ERROR",
      "--confirm must match the preview's confirm value exactly",
      ["Run without --execute to print the exact confirm value"],
    );
  process.stdout.write(
    render(
      {
        preview: {
          profile: credential.profile,
          origin: base,
          method,
          path: safeTarget,
          query_sha256: queryDigest,
          body_bytes: Buffer.byteLength(body),
          body_sha256: body ? digest : undefined,
          journal: writeLogPath(),
          confirm,
          ...(body ? { body: parseRawResponse(body) } : {}),
        },
      },
      request.executing
        ? []
        : [
            "Add --execute --confirm '<confirm>' to send this request once; it is never replayed automatically",
            "Raw writes read no target state and detect no no-ops; reconcile an unknown outcome before retrying",
          ],
      true,
    ),
  );
  if (!request.executing) return;
  const journal = openRetainedFile(writeLogPath());
  const run = randomUUID().replaceAll("-", "");
  const append = (record: Record<string, unknown>, sent = false): void => {
    try {
      journal.append(
        Buffer.from(
          JSON.stringify(
            redactRawEnvelope(
              {
                run,
                profile: credential.profile,
                method,
                path: safeTarget,
                body_sha256: body ? digest : undefined,
                ...record,
                timestamp: new Date().toISOString(),
              },
              "journal",
            ),
          ) + "\n",
        ),
      );
    } catch (error) {
      if (sent)
        throw new CliError(
          "CONFIG_INSECURE",
          "the raw write was sent but its outcome could not be recorded",
          ["Reconcile the target before retrying"],
          {
            ...(record.status === undefined
              ? {}
              : { upstream_status: record.status }),
          },
        );
      throw error;
    }
  };
  try {
    append({ phase: "intent", outcome: "not_sent" });
    let sent = false;
    let response: Response;
    try {
      const session = await authenticate(
        credential,
        base,
        allowUnknown,
        signal,
      );
      if (origin(session.base, allowUnknown) !== destination)
        throw new CliError(
          "REGION_MISMATCH",
          "authentication selected a different region than the preview",
          ["Repeat the preview with the correct --region"],
        );
      const grant = {};
      grants.set(grant, {
        origin: origin(session.base, allowUnknown),
        method,
        path: target,
        body,
      });
      sent = true;
      response = await requestRaw(
        method,
        path,
        query,
        body,
        grant,
        session.base,
        session.token,
        allowUnknown,
        signal,
      );
      observeRate(session, response);
    } catch (error) {
      append(
        { phase: "outcome", outcome: sent ? "unknown" : "not_sent" },
        sent,
      );
      if (sent)
        throw error instanceof CliError
          ? new CliError(
              error.code,
              error.message,
              ["Reconcile the target before retrying"],
              error.details,
            )
          : new CliError("UNKNOWN", "the raw write outcome is unknown", [
              "Reconcile the target before retrying",
            ]);
      throw error;
    }
    append(
      { phase: "outcome", outcome: "responded", status: response.status },
      true,
    );
    if (response.binary)
      throw new CliError(
        "UPSTREAM_ERROR",
        "the raw write was sent but the response is binary",
        ["Reconcile the target before retrying"],
        { status: response.status },
      );
    if (response.status < 200 || response.status >= 300)
      throw failure(response, true);
    process.stdout.write(render({ run, ...present(response) }, [], true));
  } finally {
    journal.close();
  }
}
