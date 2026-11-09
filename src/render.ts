import { encode } from "@toon-format/toon";
import { randomUUID } from "node:crypto";
import { object, RawNumber } from "./core.js";

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
function redactNumber(value: string): string {
  const normalize = (text: string): string | undefined => {
    const match = /^(-?)(0|[1-9]\d*)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(
      text,
    );
    if (!match) return undefined;
    const digits = (match[2]! + (match[3] ?? "")).replace(/^0+/, "");
    if (!digits) return "0";
    const coefficient = digits.replace(/0+$/, "");
    const exponent =
      BigInt(match[4] ?? "0") -
      BigInt((match[3] ?? "").length) +
      BigInt(digits.length - coefficient.length);
    return `${match[1]}${coefficient}e${exponent}`;
  };
  const number = normalize(value);
  if (
    number !== undefined &&
    [...secrets, ...memberCids].some((secret) => normalize(secret) === number)
  )
    return "[redacted]";
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
  const secretNames = new Set<number>();
  const laterSecret = new Set<number>();
  let upcomingSecret = false;
  for (let index = entries.length - 1; index >= 0; index--) {
    const [key, value] = entries[index]!;
    if (upcomingSecret) laterSecret.add(index);
    if (isPairName(key) && typeof value === "string" && isSecretKey(value)) {
      secretNames.add(index);
      upcomingSecret = true;
    } else if (isPairValue(key) && key.toLowerCase() !== "data")
      upcomingSecret = false;
  }
  let pending: { index: number; name: boolean } | undefined;
  entries.forEach(([key], index) => {
    const name = isPairName(key);
    if (!name && (!isPairValue(key) || key.toLowerCase() === "data")) return;
    if (
      name &&
      pending &&
      !pending.name &&
      !secretNames.has(index) &&
      laterSecret.has(index)
    )
      return;
    if (
      name &&
      pending?.name &&
      secretNames.has(pending.index) &&
      !secretNames.has(index)
    )
      return;
    if (pending && pending.name !== name) {
      const nameIndex = name ? index : pending.index;
      const valueIndex = name ? pending.index : index;
      if (secretNames.has(nameIndex)) sensitive.add(valueIndex);
      pending = undefined;
    } else pending = { index, name };
  });
  return sensitive;
}
function redactedKeys(keys: readonly string[]): string[] {
  const used = new Set(keys);
  let index = 0;
  return keys.map((key) => {
    if (![...secrets, ...memberCids].some((secret) => key.includes(secret)))
      return key;
    let replacement: string;
    do replacement = `[redacted-key-${++index}]`;
    while (used.has(replacement));
    used.add(replacement);
    return replacement;
  });
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
      const keys = redactedKeys(node.entries.map(({ key }) => key));
      for (const [index, { key, keyNode, node: entry }] of node.entries.entries()) {
        if (keys[index] !== key)
          edits.push({
            start: keyNode.start,
            end: keyNode.end,
            value: JSON.stringify(keys[index]),
          });
        const sensitive =
          isSecretKey(key) ||
          keys[index] !== key ||
          redactText(key) !== key ||
          pairs.has(index) ||
          (withinSecret && isPairValue(key));
        visit(entry, sensitive, sensitive);
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
    } else if (
      !node.entries &&
      !node.children &&
      /[-0-9]/.test(text[node.start] ?? "")
    ) {
      const original = text.slice(node.start, node.end);
      const cleaned = redactNumber(original);
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
  if (value instanceof RawNumber) {
    const cleaned = redactNumber(value.text);
    return hideScalar ? "[redacted]" : cleaned === value.text ? value : cleaned;
  }
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
    const keys = redactedKeys(entries.map(([key]) => key));
    return Object.fromEntries(
      entries.map(([key, entry], index) => {
        const sensitive =
          isSecretKey(key) ||
          keys[index] !== key ||
          redactText(key) !== key ||
          pairs.has(index) ||
          (withinSecret && isPairValue(key));
        return [
          keys[index]!,
          redactValue(entry, sensitive, sensitive),
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
    if (Object.keys(pending).length) {
      const numbers = new Map<string, string>();
      const prepare = (value: unknown): unknown => {
        if (value instanceof RawNumber) {
          const marker = `raw_number_${randomUUID().replaceAll("-", "")}`;
          numbers.set(marker, value.text);
          return marker;
        }
        if (Array.isArray(value)) return value.map(prepare);
        if (object(value))
          return Object.fromEntries(
            Object.entries(value).map(([key, entry]) => [key, prepare(entry)]),
          );
        return value;
      };
      let encoded = encode(prepare(redact(pending))).trimEnd();
      encoded = encoded.replace(/raw_number_[0-9a-f]{32}/g, (marker) =>
        numbers.get(marker) ?? marker,
      );
      output += encoded + "\n";
    }
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
