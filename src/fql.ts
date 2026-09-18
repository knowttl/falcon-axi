import { CliError } from "./core.js";

/**
 * Filter shorthands for the Alerts domain (docs/design/v1.md §11.3).
 * Field names follow the documented Alerts filter fields that falcon-mcp's detections module uses:
 * `severity_name`, `status`, and `created_timestamp`.
 */
export const SEVERITIES = ["informational", "low", "medium", "high", "critical"] as const;
export const STATUSES = ["new", "in_progress", "closed", "reopened"] as const;

const SINCE_PATTERN = /^(\d+)([mhd])$/;

export type DetectionQuery = Readonly<{
  filter?: string;
  severity?: string;
  status?: string;
  since?: string;
}>;

function severityTerm(value: string): string {
  const normalized = value.toLowerCase();
  if (!(SEVERITIES as readonly string[]).includes(normalized)) {
    throw new CliError("VALIDATION_ERROR", `unknown severity ${value}`, [`valid values for --severity: ${SEVERITIES.join(", ")}`]);
  }
  return `severity_name:'${normalized.charAt(0).toUpperCase()}${normalized.slice(1)}'`;
}

function statusTerm(value: string): string {
  const normalized = value.toLowerCase();
  if (!(STATUSES as readonly string[]).includes(normalized)) {
    throw new CliError("VALIDATION_ERROR", `unknown status ${value}`, [`valid values for --status: ${STATUSES.join(", ")}`]);
  }
  return `status:'${normalized}'`;
}

function sinceTerm(value: string): string {
  const match = SINCE_PATTERN.exec(value.toLowerCase());
  if (!match) {
    throw new CliError("VALIDATION_ERROR", `--since must be a relative window such as 24h`, [
      "valid units for --since: m (minutes), h (hours), d (days)",
      "Example: `--since 7d`",
    ]);
  }
  return `created_timestamp:>'now-${match[1]}${match[2]}'`;
}

/** Composes the shorthand flags and any raw `--filter` into one FQL string; `+` is AND. */
export function detectionFilter(query: DetectionQuery): string | undefined {
  const terms: string[] = [];
  if (query.severity !== undefined) terms.push(severityTerm(query.severity));
  if (query.status !== undefined) terms.push(statusTerm(query.status));
  if (query.since !== undefined) terms.push(sinceTerm(query.since));
  if (query.filter !== undefined) {
    if (!query.filter.trim()) throw new CliError("VALIDATION_ERROR", "--filter requires a value");
    terms.push(query.filter);
  }
  return terms.length ? terms.join("+") : undefined;
}

/**
 * Plain-language restatement of the query, so an empty result says what produced it (§10.5).
 * Returns an empty string when nothing narrowed the read.
 */
export function describeDetectionQuery(query: DetectionQuery): string {
  const parts: string[] = [];
  if (query.severity) parts.push(`${query.severity.toLowerCase()} severity`);
  if (query.status) parts.push(`status ${query.status.toLowerCase()}`);
  if (query.since) parts.push(`in the last ${query.since.toLowerCase()}`);
  if (query.filter) parts.push("the supplied filter");
  return parts.join(" ");
}
