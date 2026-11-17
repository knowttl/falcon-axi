import { createHash } from "node:crypto";
import {
  Kind,
  parse,
  type FieldNode,
  type DirectiveNode,
  type FragmentDefinitionNode,
  type SelectionNode,
} from "graphql";
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
export function parseQueryDocument(text: string): string {
  const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  if (!source.trim())
    throw new CliError(
      "VALIDATION_ERROR",
      "--query requires a GraphQL query document",
    );
  let definitions: readonly { kind: string; operation?: string }[];
  try {
    definitions = parse(source, { noLocation: true }).definitions;
  } catch {
    throw new CliError(
      "VALIDATION_ERROR",
      "--query is not a GraphQL document",
      ["A document that does not parse is refused and is not sent"],
    );
  }
  const operations = definitions.filter(
    (definition) => definition.kind === Kind.OPERATION_DEFINITION,
  );
  if (operations.length > 1)
    throw new CliError(
      "VALIDATION_ERROR",
      "--query must contain exactly one operation",
      ["A document with more than one operation is refused and is not sent"],
    );
  if (!operations.length)
    throw new CliError(
      "VALIDATION_ERROR",
      "--query must contain a query operation",
    );
  if (operations[0]?.operation !== "query")
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "identity graphql sends only query operations",
      [
        "A mutation or subscription is refused, including when named, commented, or preceded by a byte-order mark",
      ],
    );
  return source;
}
export type GraphqlConnection = {
  key: string;
  first: string;
  after: string;
  nodes?: string;
  edges?: string;
  pageInfo: string;
  hasNextPage: string;
  endCursor: string;
};
const selectionFields = (
  selections: readonly SelectionNode[],
  fragments: ReadonlyMap<string, FragmentDefinitionNode>,
  seen: ReadonlySet<string>,
  inherited: readonly DirectiveNode[] = [],
): FieldNode[] => {
  const fields: FieldNode[] = [];
  for (const selection of selections) {
    const directives = [...inherited, ...(selection.directives ?? [])];
    if (selection.kind === Kind.FIELD)
      fields.push({ ...selection, directives });
    else if (selection.kind === Kind.INLINE_FRAGMENT)
      fields.push(
        ...selectionFields(
          selection.selectionSet.selections,
          fragments,
          seen,
          directives,
        ),
      );
    else if (
      selection.kind === Kind.FRAGMENT_SPREAD &&
      !seen.has(selection.name.value)
    ) {
      const fragment = fragments.get(selection.name.value);
      if (!fragment) continue;
      const next = new Set(seen);
      next.add(selection.name.value);
      fields.push(
        ...selectionFields(fragment.selectionSet.selections, fragments, next, [
          ...directives,
          ...(fragment.directives ?? []),
        ]),
      );
    }
  }
  return fields;
};
const argumentVariable = (
  field: FieldNode,
  name: string,
): string | undefined => {
  const argument = field.arguments?.find((item) => item.name.value === name);
  return argument?.value.kind === Kind.VARIABLE
    ? argument.value.name.value
    : undefined;
};
export function graphqlConnections(text: string): {
  connections: GraphqlConnection[];
  alias?: string;
  directive?: string;
  bothRows?: boolean;
} {
  const source = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let definitions: ReturnType<typeof parse>["definitions"];
  try {
    definitions = parse(source, { noLocation: true }).definitions;
  } catch {
    return { connections: [] };
  }
  const fragments = new Map<string, FragmentDefinitionNode>();
  for (const definition of definitions)
    if (definition.kind === Kind.FRAGMENT_DEFINITION)
      fragments.set(definition.name.value, definition);
  const operation = definitions.find(
    (definition) =>
      definition.kind === Kind.OPERATION_DEFINITION &&
      definition.operation === "query",
  );
  if (!operation || operation.kind !== Kind.OPERATION_DEFINITION)
    return { connections: [] };
  const connections: GraphqlConnection[] = [];
  let alias: string | undefined;
  let directive: string | undefined;
  let bothRows = false;
  const topFields = selectionFields(
    operation.selectionSet.selections,
    fragments,
    new Set(),
  );
  const groups = new Map<string, FieldNode[]>();
  for (const field of topFields) {
    const key = field.alias?.value ?? field.name.value;
    groups.set(key, [...(groups.get(key) ?? []), field]);
  }
  for (const group of groups.values()) {
    const field = group[0]!;
    const first = argumentVariable(field, "first");
    const after = argumentVariable(field, "after");
    if (!first || !after || !field.selectionSet) continue;
    const fields = group.flatMap((item) => selectionFields(
      item.selectionSet?.selections ?? [], fragments, new Set(), item.directives,
    ));
    const pageInfos = fields.filter((item) => item.name.value === "pageInfo");
    const pageInfo = pageInfos[0];
    if (!pageInfo?.selectionSet) continue;
    const infoFields = selectionFields(
      pageInfo.selectionSet.selections,
      fragments,
      new Set(),
    );
    const names = new Set(infoFields.map((item) => item.name.value));
    const rows = fields.filter((item) =>
      ["nodes", "edges"].includes(item.name.value),
    );
    if (!rows.length) continue;
    const pagingFields = [
      ...pageInfos,
      ...pageInfos.flatMap((item) =>
        selectionFields(
          item.selectionSet?.selections ?? [],
          fragments,
          new Set(),
          item.directives,
        ).filter((child) =>
          ["hasNextPage", "endCursor"].includes(child.name.value),
        ),
      ),
      ...rows,
    ];
    const directed = [...group, ...pagingFields].find(
      (item) => item.directives?.length,
    );
    if (directed) {
      directive ??= directed.directives![0]!.name.value;
      continue;
    }
    if (!names.has("hasNextPage") || !names.has("endCursor")) continue;
    const responseKey = (item: FieldNode): string => item.alias?.value ?? item.name.value;
    const nodes = rows.find((item) => item.name.value === "nodes");
    const edges = rows.find((item) => item.name.value === "edges");
    connections.push({
      key: field.alias?.value ?? field.name.value,
      first,
      after,
      ...(nodes ? { nodes: responseKey(nodes) } : {}),
      ...(edges ? { edges: responseKey(edges) } : {}),
      pageInfo: responseKey(pageInfo),
      hasNextPage: responseKey(infoFields.find((item) => item.name.value === "hasNextPage")!),
      endCursor: responseKey(infoFields.find((item) => item.name.value === "endCursor")!),
    });
  }
  return {
    connections,
    ...(alias === undefined ? {} : { alias }),
    ...(directive === undefined ? {} : { directive }),
    bothRows,
  };
}
export function queryOnly(text: string): boolean {
  try {
    parseQueryDocument(text);
    return true;
  } catch {
    return false;
  }
}
export function graphqlQueryBody(
  query: string,
  variables: unknown,
): { query: string; variables: Record<string, unknown> } {
  if (!object(variables)) throw refused();
  return { query: parseQueryDocument(query), variables: { ...variables } };
}
export function acceptedGraphqlBody(body: unknown): boolean {
  if (registeredBody(body)) return true;
  return (
    object(body) &&
    Object.keys(body).sort().join() === "query,variables" &&
    typeof body.query === "string" &&
    object(body.variables) &&
    queryOnly(body.query)
  );
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
