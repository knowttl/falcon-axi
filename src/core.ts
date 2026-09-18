/** Stable error codes and exit codes (docs/design/v1.md §9.2). */
export type ErrorCode =
  | "VALIDATION_ERROR"
  | "CREDENTIAL_INCOMPLETE"
  | "FQL_INVALID"
  | "AUTH_REQUIRED"
  | "AUTH_FAILED"
  | "SCOPE_DENIED"
  | "TENANT_DENIED"
  | "ORIGIN_NOT_ALLOWED"
  | "REGION_MISMATCH"
  | "NOT_FOUND"
  | "PAGINATION_LIMIT"
  | "RATE_LIMITED"
  | "UPSTREAM_ERROR"
  | "UPSTREAM_UNAVAILABLE"
  | "NETWORK_UNREACHABLE"
  | "TLS_UNTRUSTED"
  | "READ_ONLY_VIOLATION"
  | "UNKNOWN";

const USAGE_CODES = new Set<ErrorCode>(["VALIDATION_ERROR", "CREDENTIAL_INCOMPLETE", "FQL_INVALID"]);

/**
 * A failure carrying everything the error envelope prints.
 * `details` holds the extra structured fields a specific code owes the caller, such as
 * `required_scopes` on SCOPE_DENIED or `trace_id` on an upstream failure (§9.2, §9.4).
 */
export class CliError extends Error {
  readonly exitCode: number;

  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly help: readonly string[] = [],
    readonly details: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.exitCode = USAGE_CODES.has(code) ? 2 : 1;
  }
}
