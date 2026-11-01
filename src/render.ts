import { encode } from "@toon-format/toon";
import { object } from "./core.js";

const secrets = new Set<string>();
const memberCids = new Set<string>();
export function registerMemberCid(value: string): void {
  if (value) memberCids.add(value);
}
export function registerSecret(value: string): void {
  if (value) {
    secrets.add(value);
    secrets.add(JSON.stringify(value).slice(1, -1));
    secrets.add(encodeURIComponent(value));
    secrets.add(new URLSearchParams({ value }).toString().slice(6));
  }
}
export function redactText(value: string): string {
  for (const secret of [...secrets].sort((a, b) => b.length - a.length))
    value = value.replaceAll(secret, "[redacted]");
  for (const cid of memberCids)
    value = value.replaceAll(cid, (match, offset: number) =>
      /^:(?:ind|automated-lead):[^\s"'`,]+/.test(
        value.slice(offset + cid.length),
      )
        ? match
        : "[redacted]",
    );
  return value;
}
const secretKeys = new Set([
  "access_token",
  "client_id",
  "client_secret",
  "member_cid",
  "token",
  "authorization",
  "cid",
  "customer_id",
  "#repo.cid",
  "children_cids",
  "clientsecret",
  "clientid",
  "membercid",
  "refresh_token",
  "privatekey",
]);
export function redact(value: unknown): unknown {
  if (typeof value === "string")
    return redactText(value).replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|AccountKey=[^;\s]+|sig=[A-Za-z0-9%+/=]+/gi,
      "[redacted]",
    );
  if (Array.isArray(value)) return value.map(redact);
  if (object(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        redactText(key),
        secretKeys.has(key.toLowerCase()) ? "[redacted]" : redact(entry),
      ]),
    );
  return value;
}
export class Raw {
  constructor(readonly text: string) {}
}
function quote(value: string): string {
  return JSON.stringify(redactText(value)).replace(
    /[\u0000-\u001f]/g,
    (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}
export function render(
  value: Record<string, unknown>,
  help: readonly string[] = [],
): string {
  let output = "";
  let pending: Record<string, unknown> = {};
  const flush = (): void => {
    if (Object.keys(pending).length)
      output += encode(redact(pending)).trimEnd() + "\n";
    pending = {};
  };
  for (const [key, entry] of Object.entries(value)) {
    if (entry === null || entry === undefined) continue;
    if (entry instanceof Raw) {
      flush();
      output += `${key}: ${redactText(entry.text)}\n`;
    } else pending[key] = entry;
  }
  flush();
  if (help.length)
    output += `help[${help.length}]: ${help.map(quote).join(",")}\n`;
  return output;
}
export function truncate(value: string, maximum = 800): string {
  const points = Array.from(value);
  return points.length <= maximum
    ? value
    : `${points.slice(0, maximum).join("")}… (truncated, ${points.length} chars total)`;
}
