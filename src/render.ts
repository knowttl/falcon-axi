import { encode, escapeString } from "@toon-format/toon";

/** Keys redacted on every stream, taken from falconpy's `sanitize_dictionary` (docs/design/v1.md §5.5). */
const REDACTED_KEYS = new Set(["access_token", "client_id", "client_secret", "member_cid", "token", "authorization"]);

const RAW = Symbol("falcon-axi raw line");

type Raw = Readonly<{ [RAW]: string }>;

/** Emits `key: text` verbatim, for the hand-formatted lines `encode()` would mangle (§10.1). */
export function raw(text: string): Raw {
  return { [RAW]: text };
}

function isRaw(value: unknown): value is Raw {
  return typeof value === "object" && value !== null && RAW in value;
}

export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) =>
        REDACTED_KEYS.has(key.toLowerCase()) ? [key, "[redacted]"] : [key, redact(entry)],
      ),
    );
  }
  return value;
}

/** Masks a tenant identifier to its suffix; no v1 output reveals the value (§5.5). */
export function maskCid(cid: string): string {
  return cid.length <= 4 ? "…" : `…${cid.slice(-4)}`;
}

function helpBlock(help: readonly string[]): string {
  if (!help.length) return "";
  return `help[${help.length}]: ${help.map(item => `"${escapeString(item)}"`).join(",")}\n`;
}

/**
 * Renders one TOON document on stdout (§10.1).
 * Row data goes through `encode()`; raw lines and the help block are hand-formatted, because
 * `encode()` inlines primitive arrays and would break the help block shape.
 */
export function render(value: Record<string, unknown>, help: readonly string[] = []): string {
  let output = "";
  let pending: Record<string, unknown> = {};
  const flush = (): void => {
    if (!Object.keys(pending).length) return;
    output += `${encode(redact(pending) as never).trimEnd()}\n`;
    pending = {};
  };
  for (const [key, entry] of Object.entries(value)) {
    if (entry === undefined) continue;
    if (isRaw(entry)) {
      flush();
      output += `${key}: ${entry[RAW]}\n`;
      continue;
    }
    pending[key] = entry;
  }
  flush();
  return `${output}${helpBlock(help)}`;
}

/** Truncates a long field and says how much is missing (§10.4). */
export function truncate(value: string, maximum = 800): { text: string; truncated: boolean } {
  if (value.length <= maximum) return { text: value, truncated: false };
  return { text: `${value.slice(0, maximum)}… (truncated, ${value.length} chars total)`, truncated: true };
}
