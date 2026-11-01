import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import ledger from "../../tests/migration/coverage-s11.json" with { type: "json" };
import contract from "../../tests/fixtures/migration/S11/contracts.json" with { type: "json" };

const seal = "1567a7930c794e6d05e5db764a259fdb4bf58528da66a81bd4ce6f9c98e7d03d";
const digest = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");
const observations: Readonly<Record<string, readonly string[]>> = {
  "SR-162": [
    "S11 local preview",
    "S11 grammar refuses",
    "S11 repeated interrupts",
    "S11 size lookup request timeout",
  ],
  "SR-163": [
    "S11 lost initialization",
    "S11 retained output cap",
    "S11 deletion failure",
    "S11 execution never admits an unknown origin",
  ],
  "SR-164": [
    "S11 installed lifecycle",
    "S11 selected",
    "S11 same-device uppercase contender",
    "S11 READ_ONLY and absent opt-in",
  ],
  "SR-165": [
    "S11 fixed command preview",
    "S11 profile policy refuses widening",
    "S11 command schema and platform help",
  ],
  "SR-166": [
    "S11 intent durability",
    "S11 pre-init durability",
    "S11 known-session durability",
    "S11 outcome durability",
    "S11 selected execution failure",
    "S11 shared execution deadline during listing polling",
  ],
  "SR-167": [
    "S11 accumulated output redacts",
    "S11 status exhaustion",
    "descriptor-relative leaf open",
    "refuses the origin's unsafe",
    "interrupted and short writes",
  ],
  "SR-168": [
    "S11 every lifecycle descriptor refuses passive",
    "S11 forged grants",
    "S11 mutation detector missing-grant",
    "S11 mutation detector tampered-body",
    "S11 READ_ONLY enabled after init",
  ],
  "SR-169": [
    "S11 accumulated output redacts",
    "S11 derived cat listing",
    "S11 installed lifecycle",
  ],
  "SR-170": [
    "S11 derived cat listing",
    "S11 cat without literal path",
    "S11 size lookup request timeout",
    "S11 cat shares all 64 status requests",
    "S11 derived listing cannot widen",
  ],
  "SR-171": [
    "S11 malformed sequence",
    "S11 selected execution failure",
    "S11 status exhaustion",
  ],
  "SR-172": [
    "S11 response acquisition cap",
    "S11 mutation detector tampered-body",
    "S11 mutation detector missing-grant",
  ],
  "SR-208": [
    "S11 local preview and exact confirmation",
    "S11 selected",
    "S11 READ_ONLY",
  ],
};

export function rtrCoverage(
  path: string,
  tap: string,
  primitives: string,
): Record<string, unknown> {
  if (digest(JSON.stringify(ledger)) !== seal)
    throw new Error("Frozen S11 safety ownership changed");
  if (
    JSON.stringify(ledger.groups.map((group) => group.id).sort()) !==
    JSON.stringify([...contract.safetyRequirementIds].sort())
  )
    throw new Error("S11 safety ownership differs from the slice contract");
  for (const group of ledger.groups)
    if (digest(readFileSync(resolve(group.source))) !== group.sourceSha256)
      throw new Error(`Pinned S11 source changed: ${group.source}`);
  const passed = [...(tap + primitives).matchAll(/^ok \d+ - (.*)$/gm)].map(
    (match) => match[1]!,
  );
  const required =
    path === "artium"
      ? contract.hostedObservations
      : [...new Set(Object.values(observations).flat())];
  for (const prefix of required)
    if (!passed.some((name) => name.startsWith(prefix)))
      throw new Error(`S11 ${path} has no passing observation for ${prefix}`);
  return {
    path,
    ledgerSha256: seal,
    sourceRevision: ledger.sourceRevision,
    reports: ledger.groups.map((group) => ({
      requirement: group.id,
      source: group.source,
      members: group.members,
      observations:
        path === "native"
          ? passed.filter((name) =>
              observations[group.id]!.some((prefix) => name.startsWith(prefix)),
            )
          : contract.hostedObservations,
      mode:
        path === "native"
          ? "installed native lifecycle and compiled primitive observations"
          : "repeated real hosted public API observations; standalone policy owned by native gate",
    })),
    nativeWindows: "pending",
  };
}
