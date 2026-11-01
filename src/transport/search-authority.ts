import { createHash } from "node:crypto";
import { CliError, object } from "../core.js";
import documents from "./documents.json" with { type: "json" };

const refused = (): CliError =>
  new CliError("READ_ONLY_VIOLATION", "request authority was refused");
const canonical =
  "ca0f756891343c960c43af67894474901f8264a1e9d3d2c38f1665493ad0b06d";
if (
  createHash("sha256").update(JSON.stringify(documents)).digest("hex") !==
  canonical
)
  throw new Error("Canonical GraphQL document authority changed");
for (const entry of Object.values(documents)) {
  const tokens = entry.text.match(/[{}]|[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
  if (
    tokens[0] !== "query" ||
    /["#]|\b(?:mutation|subscription|fragment)\b/.test(entry.text)
  )
    throw new Error("Invalid read document");
  let depth = 0;
  let queries = 0;
  for (const token of tokens) {
    if (token === "{") depth++;
    else if (token === "}") depth--;
    else if (token === "query" && depth === 0) queries++;
    if (depth < 0) throw new Error("Invalid read document");
  }
  if (
    depth ||
    queries !== 1 ||
    !entry.readScopes.every((scope) => scope.endsWith(":read"))
  )
    throw new Error("Invalid read document");
  Object.freeze(entry.variables);
  Object.freeze(entry.readScopes);
  Object.freeze(entry);
}
Object.freeze(documents);
export function document(name: string) {
  if (!Object.hasOwn(documents, name)) throw refused();
  return documents[name as keyof typeof documents];
}
export function graphqlBody(
  name: string,
  variables: unknown,
): { query: string; variables: Record<string, unknown> } {
  const entry = document(name);
  if (
    !object(variables) ||
    Object.keys(variables).some(
      (key) => !(entry.variables as readonly string[]).includes(key),
    )
  )
    throw refused();
  return { query: entry.text, variables: { ...variables } };
}
export function registeredBody(body: unknown): boolean {
  if (
    !object(body) ||
    Object.keys(body).sort().join() !== "query,variables" ||
    !object(body.variables)
  )
    return false;
  return Object.values(documents).some(
    (entry) =>
      entry.text === body.query &&
      Object.keys(body.variables as Record<string, unknown>).every((key) =>
        (entry.variables as readonly string[]).includes(key),
      ),
  );
}
export function pathValue(name: string, value: string): string {
  if (!value.trim() || /[/\\%]/.test(value) || [".", ".."].includes(value))
    throw new CliError("VALIDATION_ERROR", `the ${name} must be a plain name`, [
      "`/`, `\\`, and `%` are refused, and so are `.` and `..`, because the value reaches a URL path",
      "Pass a bare repository or search name, for example `search-all`",
    ]);
  return encodeURIComponent(value);
}
export function searchBody(
  string: string | undefined,
  hex: string | undefined,
  limit: number,
) {
  const patterns: { type: string; value: string }[] = [];
  if (string !== undefined) {
    if (!/^[\x20-\x7e]{1,4096}$/.test(string) || !string.trim())
      throw new CliError(
        "VALIDATION_ERROR",
        "--string requires 1-4096 printable ASCII characters with nonblank content",
      );
    patterns.push({ type: "ascii", value: string });
  }
  if (hex !== undefined) {
    const compact = hex.replaceAll(" ", "");
    if (
      !compact ||
      compact.length > 8192 ||
      !/^(?:[a-fA-F0-9]{2})+$/.test(compact)
    )
      throw new CliError(
        "VALIDATION_ERROR",
        "--hex requires 1-4096 literal byte pairs with optional spaces",
      );
    patterns.push({ type: "hex", value: compact.toLowerCase() });
  }
  if (!patterns.length)
    throw new CliError(
      "VALIDATION_ERROR",
      "malquery search requires --string or --hex",
      ["Both flags may be combined"],
    );
  if (!Number.isInteger(limit) || limit < 1 || limit > 100)
    throw new CliError(
      "VALIDATION_ERROR",
      "MalQuery results require a limit from 1 to 100",
    );
  return { patterns, options: { limit } };
}
export function validateSearchBody(body: unknown) {
  if (
    !object(body) ||
    Object.keys(body).sort().join() !== "options,patterns" ||
    !object(body.options) ||
    Object.keys(body.options).join() !== "limit" ||
    !Array.isArray(body.patterns) ||
    body.patterns.length < 1 ||
    body.patterns.length > 2
  )
    throw refused();
  const values: Record<string, string> = {};
  for (const pattern of body.patterns) {
    if (
      !object(pattern) ||
      Object.keys(pattern).sort().join() !== "type,value" ||
      typeof pattern.type !== "string" ||
      !["ascii", "hex"].includes(pattern.type) ||
      Object.hasOwn(values, pattern.type) ||
      typeof pattern.value !== "string"
    )
      throw refused();
    values[pattern.type] = pattern.value;
  }
  try {
    return searchBody(values.ascii, values.hex, body.options.limit as number);
  } catch (error) {
    if (error instanceof CliError) throw refused();
    throw error;
  }
}
