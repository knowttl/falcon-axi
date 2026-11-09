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
  "password",
  "passwd",
  "passphrase",
  "secret",
  "api_key",
  "apikey",
  "private_key",
  "secret_key",
  "access_key",
  "sig",
  "accountkey",
]);
const pairNameFields = ["key", "name", "field", "property", "attribute"];
const pairValueFields = ["value", "data", "values", "val", "string_value"];
export const isSecretKey = (name: string): boolean =>
  secretKeys.has(name.toLowerCase());
const assignment = new RegExp(
  `(?<![\\w.#-])(${[...secretKeys].map((key) => key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(["']?[ \\t]*[:=][ \\t]*)(?:bearer[ \\t]+)?("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\r\\n]+?(?=[\\r\\n]|[ \\t,;&]+[\\w.#-]+[ \\t]*[:=]|$))`,
  "gi",
);
export function redactAssignments(value: string): string {
  return value.replace(
    assignment,
    (_match, key: string, separator: string) => `${key}${separator}[redacted]`,
  );
}
function namesSecret(entry: Record<string, unknown>): boolean {
  return Object.entries(entry).some(
    ([field, name]) =>
      pairNameFields.includes(field.toLowerCase()) &&
      typeof name === "string" &&
      isSecretKey(name),
  );
}
function redactSerialized(text: string): string {
  type Node = {
    start: number;
    end: number;
    entries?: { key: string; keyNode: Node; node: Node }[];
    children?: Node[];
  };
  let position = 0;
  const space = (): void => {
    while (/\s/.test(text[position] ?? "") && position < text.length)
      position++;
  };
  const parse = (): Node => {
    space();
    const start = position;
    const character = text[position];
    if (character === "{" || character === "[") {
      position++;
      const entries: { key: string; keyNode: Node; node: Node }[] = [];
      const children: Node[] = [];
      space();
      while (text[position] !== (character === "{" ? "}" : "]")) {
        if (character === "{") {
          const key = parse();
          space();
          position++;
          entries.push({
            key: JSON.parse(text.slice(key.start, key.end)) as string,
            keyNode: key,
            node: parse(),
          });
        } else children.push(parse());
        space();
        if (text[position] !== ",") break;
        position++;
      }
      position++;
      return { start, end: position, entries, children };
    }
    if (character === '"') {
      position++;
      while (text[position] !== '"') {
        if (text[position] === "\\") position++;
        position++;
      }
      position++;
    } else {
      while (position < text.length && !/[\s,\]}]/.test(text[position]!))
        position++;
    }
    return { start, end: position };
  };
  const root = parse();
  const edits: { start: number; end: number; value: string }[] = [];
  const visit = (node: Node): void => {
    if (node.entries?.length) {
      const pair = node.entries.some(
        ({ key, node: entry }) =>
          pairNameFields.includes(key.toLowerCase()) &&
          text[entry.start] === '"' &&
          isSecretKey(JSON.parse(text.slice(entry.start, entry.end)) as string),
      );
      for (const { key, keyNode, node: entry } of node.entries) {
        const safeKey = redactText(key);
        if (safeKey !== key)
          edits.push({
            start: keyNode.start,
            end: keyNode.end,
            value: JSON.stringify(safeKey),
          });
        if (
          isSecretKey(key) ||
          (pair && pairValueFields.includes(key.toLowerCase()))
        )
          edits.push({
            start: entry.start,
            end: entry.end,
            value: '"[redacted]"',
          });
        else visit(entry);
      }
    }
    for (const child of node.children ?? []) visit(child);
    if (!node.entries && !node.children && text[node.start] === '"') {
      const original = JSON.parse(text.slice(node.start, node.end)) as string;
      const cleaned = redact(original) as string;
      if (cleaned !== original)
        edits.push({
          start: node.start,
          end: node.end,
          value: JSON.stringify(cleaned),
        });
    }
  };
  visit(root);
  for (const edit of edits.sort((a, b) => b.start - a.start))
    text = text.slice(0, edit.start) + edit.value + text.slice(edit.end);
  return text;
}
export function redact(value: unknown): unknown {
  if (typeof value === "string") {
    if (/^\s*[\[{]/.test(value)) {
      let valid = false;
      try {
        JSON.parse(value);
        valid = true;
      } catch {
        valid = false;
      }
      if (valid) return redactSerialized(value);
    }
    return redactAssignments(redactText(value)).replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi,
      "[redacted]",
    );
  }
  if (Array.isArray(value)) return value.map(redact);
  if (object(value)) {
    const pair = namesSecret(value);
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        redactText(key),
        secretKeys.has(key.toLowerCase()) ||
        (pair && pairValueFields.includes(key.toLowerCase()))
          ? "[redacted]"
          : redact(entry),
      ]),
    );
  }
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
