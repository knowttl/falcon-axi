/**
 * Retry policy for transient upstream failures (docs/design/v1.md §7.4).
 * Pure by design so the rules are exercised offline: it decides, the transport waits.
 * Retrying is unconditionally safe because every registered operation is a read (§3).
 */
export const MAX_ATTEMPTS = 3;

const BASE_BACKOFF_MS = 500;
const RETRYABLE = new Set([429, 500, 502, 503, 504]);

export type RetryDecision = Readonly<{ waitMs: number; reason: "retry_after" | "backoff" }> | undefined;

function backoff(attempt: number, random: number): number {
  const base = BASE_BACKOFF_MS * 2 ** (attempt - 1);
  return Math.round(base * (1 + random));
}

/**
 * @param attempt 1-based number of the attempt that just failed.
 * @param nowMs current epoch milliseconds.
 * @param random jitter source in [0, 1).
 */
export function retryPlan(
  status: number,
  headers: Readonly<Record<string, string>>,
  attempt: number,
  nowMs: number,
  random = Math.random(),
): RetryDecision {
  if (attempt >= MAX_ATTEMPTS || !RETRYABLE.has(status)) return undefined;
  if (status === 429) {
    // gofalcon 208826a: X-RateLimit-RetryAfter is an epoch-seconds timestamp, honored only on 429.
    const header = headers["x-ratelimit-retryafter"];
    const seconds = header === undefined ? Number.NaN : Number(header);
    if (Number.isFinite(seconds) && seconds * 1000 > nowMs) {
      return { waitMs: seconds * 1000 - nowMs, reason: "retry_after" };
    }
  }
  return { waitMs: backoff(attempt, random), reason: "backoff" };
}
