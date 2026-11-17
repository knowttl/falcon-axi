import rows from "./descriptors.json" with { type: "json" };
import { createHash } from "node:crypto";
import { CliError } from "../core.js";

export type Descriptor = Readonly<{
  id: string;
  method: string;
  path: string;
  scopes: readonly string[];
  effect: string;
  evidence: Readonly<{
    doc_url: string;
    doc_scope: string;
    falcon_mcp: string;
  }>;
}>;
const exceptions: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "search-lifecycle": Object.freeze(["StartSearchV1", "StopSearchV1"]),
  "graphql-query": Object.freeze(["api_preempt_proxy_post_graphql"]),
  "rtr-read-only-execute": Object.freeze([
    "RTR_InitSession",
    "RTR_ExecuteCommand",
    "RTR_CheckCommandStatus",
    "RTR_DeleteSession",
  ]),
  "malquery-search": Object.freeze([
    "PostMalQueryExactSearchV1",
    "PostMalQueryFuzzySearchV1",
  ]),
  "identity-policy-write": Object.freeze([
    "post_policy_rules",
    "delete_policy_rules",
  ]),
});
const exceptionScopes: Readonly<Record<string, string>> = Object.freeze({
  "search-lifecycle": "NGSIEM:write",
  "graphql-query": "Identity Protection GraphQL:write",
  "rtr-read-only-execute": "Real time response:read",
  "malquery-search": "MalQuery:write",
  "identity-policy-write": "Identity Protection Policy Rules:write",
});
const otherOfficialSdks = Object.freeze([
  "PSFalcon",
  "gofalcon",
  "rusty-falcon",
  "falconjs",
]);
export function secondCitationAdmitted(
  row: Pick<Descriptor, "id" | "method" | "path" | "evidence">,
): boolean {
  const citation = row.evidence.falcon_mcp;
  if (!citation.includes(`falcon-mcp has no tool for ${row.id}`))
    return citation.includes(`api_scopes.py maps ${row.id} to `);
  const mapping = ` maps ${row.id} to ${row.method} ${row.path}`;
  return (
    [...citation.matchAll(/falconpy\/_endpoint\/[^\s]+\.py/g)].some((match) => {
      const rest = citation.slice(match.index + match[0].length);
      return (
        rest.startsWith(mapping) &&
        (rest.length === mapping.length ||
          /[\s.,;]/.test(rest[mapping.length]!))
      );
    }) &&
    otherOfficialSdks.some((sdk) => {
      const fragment = `${sdk} wraps ${row.id}`;
      return citation
        .split(fragment)
        .slice(1)
        .some((rest) => rest.length === 0 || /[\s.,;]/.test(rest[0]!));
    })
  );
}
const registry: Record<string, Descriptor> = Object.create(null) as Record<
  string,
  Descriptor
>;
if (
  rows.length !== 117 ||
  createHash("sha256").update(JSON.stringify(rows)).digest("hex") !==
    "92173388eb5596bc1a4f03965c97771560471af63c9fd3a5e919a5ae138edeb7"
)
  throw new Error("Canonical operation authority changed");
for (const row of rows) {
  if (
    Object.hasOwn(registry, row.id) ||
    !["GET", "POST", "DELETE"].includes(row.method) ||
    !row.path.startsWith("/") ||
    !row.evidence.doc_url ||
    !row.evidence.doc_scope ||
    !row.evidence.falcon_mcp ||
    !secondCitationAdmitted(row) ||
    (row.effect === "read"
      ? row.scopes.some((scope) => !scope.endsWith(":read"))
      : !Object.hasOwn(exceptions, row.effect) ||
        !exceptions[row.effect]!.includes(row.id) ||
        row.scopes.length !== 1 ||
        row.scopes[0] !== exceptionScopes[row.effect])
  )
    throw new Error("Invalid sealed operation registry");
  registry[row.id] = Object.freeze({
    ...row,
    scopes: Object.freeze([...row.scopes]),
    evidence: Object.freeze({ ...row.evidence }),
  });
}
Object.freeze(registry);
export function operation(id: string): Descriptor {
  if (!Object.hasOwn(registry, id))
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "this operation is outside the sealed Falcon surface",
    );
  return registry[id]!;
}
export const operationIds = Object.freeze(Object.keys(registry));
