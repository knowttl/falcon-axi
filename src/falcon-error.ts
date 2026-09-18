import { CliError } from "./core.js";
import { operation, type OperationId } from "./transport/operations.js";
import type { FalconResponse } from "./transport/types.js";

type FalconErrorBody = { errors?: { code?: number; message?: string }[]; meta?: { trace_id?: string } };

function bodyOf(response: FalconResponse): FalconErrorBody {
  return (response.body && typeof response.body === "object" ? response.body : {}) as FalconErrorBody;
}

/** Falcon's error detail lives in the body, never only in the status line (§9.4). */
export function falconMessages(response: FalconResponse): string[] {
  return (bodyOf(response).errors ?? []).map(entry => entry.message).filter((text): text is string => Boolean(text));
}

export function traceId(response: FalconResponse): string | undefined {
  return bodyOf(response).meta?.trace_id;
}

function looksLikeFilterProblem(messages: readonly string[]): boolean {
  return messages.some(message => /\b(fql|filter|query)\b/i.test(message));
}

/**
 * Maps a Falcon failure onto falcon-axi's own envelope (§9.2, §9.4).
 * Raw Falcon bodies, HTTP status numbers, and endpoint paths never reach stdout.
 */
export function translateFalconError(response: FalconResponse, id: OperationId, subject: string): CliError {
  const messages = falconMessages(response);
  const trace = traceId(response);
  const scopes = operation(id).scopes;
  switch (response.status) {
    case 400:
      if (looksLikeFilterProblem(messages)) {
        return new CliError("FQL_INVALID", `the filter for ${subject} was rejected`, [
          "FQL uses + for AND, `,` for OR, and values must be quoted",
          "Example: `--filter \"severity_name:'High'+status:'new'\"`",
          "Run `falcon-axi detection list --help` for the filterable fields",
        ]);
      }
      return new CliError("UPSTREAM_ERROR", `Falcon rejected the request for ${subject}`, [
        "Check the flags for this command with `--help`",
      ], trace ? { trace_id: trace } : {});
    case 401:
      return new CliError("AUTH_FAILED", "the Falcon credential was rejected", [
        "The client ID or secret is wrong, or the API client was revoked",
        "Run `falcon-axi auth status` after updating the credential",
      ]);
    case 403:
      return new CliError("SCOPE_DENIED", `this API client is not permitted to read ${subject}`, [
        `Grant ${scopes.join(" and ")} (read only) to the API client in the Falcon console under Support and resources > API clients and keys`,
        "A 403 can also mean the API client is disabled",
      ], { required_scopes: [...scopes] });
    case 404:
      return new CliError("NOT_FOUND", `no ${subject} matched that identifier`, [
        "Run `falcon-axi detection list` to see current identifiers",
      ]);
    case 429:
      return new CliError("RATE_LIMITED", "Falcon rate limited this API client", [
        "Wait for the rate limit window to reset and retry",
        "Narrow the FQL filter or lower `--limit` to issue fewer requests",
      ]);
    case 502:
    case 503:
    case 504:
      return new CliError("UPSTREAM_UNAVAILABLE", "Falcon is temporarily unavailable", [
        "Retry shortly",
        "Quote the trace_id when opening a CrowdStrike support case",
      ], trace ? { trace_id: trace } : {});
    default:
      return new CliError("UPSTREAM_ERROR", `Falcon could not answer the request for ${subject}`, [
        "Retry shortly",
        "Quote the trace_id when opening a CrowdStrike support case",
      ], trace ? { trace_id: trace } : {});
  }
}
