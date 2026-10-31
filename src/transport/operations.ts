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
});
const exceptionScopes: Readonly<Record<string, string>> = Object.freeze({
  "search-lifecycle": "NGSIEM:write",
  "graphql-query": "Identity Protection GraphQL:write",
  "rtr-read-only-execute": "Real time response:read",
  "malquery-search": "MalQuery:write",
});
const registry: Record<string, Descriptor> = Object.create(null) as Record<
  string,
  Descriptor
>;
if (
  rows.length !== 114 ||
  createHash("sha256").update(JSON.stringify(rows)).digest("hex") !==
    "018194bb531b41bf54f1f1efd86badbc17f1667f37f2b056af225f9478181840"
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
