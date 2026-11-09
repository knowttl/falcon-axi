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
export const isPairName = (name: string): boolean =>
  pairNameFields.includes(name.toLowerCase());
export const isPairValue = (name: string): boolean =>
  pairValueFields.includes(name.toLowerCase());
export const isSecretKey = (name: string): boolean =>
  secretKeys.has(name.toLowerCase());
const assignment = new RegExp(
  `(?<![\\w.#-])(${[...secretKeys].map((key) => key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(["']?[ \\t]*[:=][ \\t]*)(?:bearer[ \\t]+)?(\\[redacted\\]|"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,;&\\]})"']+)`,
  "gi",
);
export function redactAssignments(value: string): string {
  return value.replace(
    assignment,
    (_match, key: string, separator: string) => `${key}${separator}[redacted]`,
  );
}
export function positionalSecretPairs(
  entries: readonly (readonly [string, unknown])[],
): Set<number> {
  const sensitive = new Set<number>();
  let pending: { index: number; name: boolean } | undefined;
  entries.forEach(([key], index) => {
    const name = isPairName(key);
    if (!name && key.toLowerCase() !== "value") return;
    if (pending && pending.name !== name) {
      const nameIndex = name ? index : pending.index;
      const valueIndex = name ? pending.index : index;
      const pairName = entries[nameIndex]![1];
      if (typeof pairName === "string" && isSecretKey(pairName))
        sensitive.add(valueIndex);
      pending = undefined;
    } else pending = { index, name };
  });
  return sensitive;
}
function redactSerialized(text: string, detectOnly = false): string | boolean {
  type Node = {
    start: number;
    end: number;
    entries?: { key: string; keyNode: Node; node: Node }[];
    children?: Node[];
  };
  let position = 0;
  let duplicate = false;
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
      const keys = new Set<string>();
      space();
      while (text[position] !== (character === "{" ? "}" : "]")) {
        if (character === "{") {
          const key = parse();
          space();
          position++;
          const name = JSON.parse(text.slice(key.start, key.end)) as string;
          if (keys.has(name)) duplicate = true;
          keys.add(name);
          entries.push({
            key: name,
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
  if (detectOnly) return duplicate;
  const edits: { start: number; end: number; value: string }[] = [];
  const visit = (
    node: Node,
    withinSecret = false,
    hideScalar = false,
  ): void => {
    if (node.entries?.length) {
      const pairs = positionalSecretPairs(
        node.entries.map(({ key, node: entry }) => [
          key,
          text[entry.start] === '"'
            ? (JSON.parse(text.slice(entry.start, entry.end)) as string)
            : undefined,
        ]),
      );
      for (const [index, { key, keyNode, node: entry }] of node.entries.entries()) {
        const safeKey = redactText(key);
        if (safeKey !== key)
          edits.push({
            start: keyNode.start,
            end: keyNode.end,
            value: JSON.stringify(safeKey),
          });
        const sensitive =
          isSecretKey(key) ||
          pairs.has(index) ||
          (withinSecret && isPairValue(key));
        visit(entry, withinSecret || sensitive, sensitive);
      }
    }
    for (const child of node.children ?? [])
      visit(child, withinSecret, hideScalar);
    if (!node.entries && !node.children && hideScalar) {
      edits.push({ start: node.start, end: node.end, value: '"[redacted]"' });
    } else if (!node.entries && !node.children && text[node.start] === '"') {
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
  const parts: string[] = [];
  let cursor = 0;
  for (const edit of edits) {
    parts.push(text.slice(cursor, edit.start), edit.value);
    cursor = edit.end;
  }
  parts.push(text.slice(cursor));
  return parts.join("");
}
export function hasDuplicateJsonMembers(text: string): boolean {
  return redactSerialized(text, true) as boolean;
}
function redactValue(
  value: unknown,
  withinSecret = false,
  hideScalar = false,
): unknown {
  if (hideScalar && !object(value) && !Array.isArray(value))
    return "[redacted]";
  if (typeof value === "string") {
    if (/^\s*[\[{]/.test(value)) {
      let valid = false;
      try {
        JSON.parse(value);
        valid = true;
      } catch {
        valid = false;
      }
      if (valid) return redactSerialized(value) as string;
    }
    return redactAssignments(redactText(value)).replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi,
      "[redacted]",
    );
  }
  if (Array.isArray(value))
    return value.map((entry) =>
      redactValue(entry, withinSecret, hideScalar),
    );
  if (object(value)) {
    const entries = Object.entries(value);
    const pairs = positionalSecretPairs(entries);
    return Object.fromEntries(
      entries.map(([key, entry], index) => {
        const sensitive =
          isSecretKey(key) ||
          pairs.has(index) ||
          (withinSecret && isPairValue(key));
        return [
          redactText(key),
          redactValue(entry, withinSecret || sensitive, sensitive),
        ];
      }),
    );
  }
  return value;
}
export function redact(value: unknown): unknown {
  return redactValue(value);
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
