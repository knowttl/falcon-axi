import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse } from "yaml";
import baseline from "../../tests/migration/coverage.json" with { type: "json" };
import inventory from "../../tests/migration/coverage-s04-s05.json" with { type: "json" };
import inspection from "../../tests/migration/coverage-s06-s07.json" with { type: "json" };
import search from "../../tests/migration/coverage-s08-s10.json" with { type: "json" };
import rtr from "../../tests/migration/coverage-s11.json" with { type: "json" };
import final from "../../tests/migration/coverage-final.json" with { type: "json" };
import corpus from "../../tests/migration/golden-corpus.json" with { type: "json" };
import { object } from "../../src/core.js";
import { checkRtrInputs } from "./rtr-coverage.js";

const digest = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");
const finalSeal =
  "e119af200b30eb18157b6bd0d670a940f9b1877971f515d07d3b7b6ab596983a";
const corpusSeal =
  "3509724fc07370f140d175f349f443bc3af809082f055874002117270eb41ee2";
const groups = [
  ...baseline.groups,
  ...inventory.groups,
  ...inspection.groups,
  ...search.groups,
  ...rtr.groups,
  ...final.groups,
];

export function checkWorkflow(text: string): void {
  const inspect = (value: unknown): void => {
    if (typeof value === "string") {
      if (/FALCON_AXI_LIVE|FALCON_(?:AXI_)?CLIENT_(?:ID|SECRET)/.test(value))
        throw new Error("Credential or live automation is forbidden");
    } else if (Array.isArray(value)) {
      value.forEach(inspect);
    } else if (object(value)) {
      for (const [key, setting] of Object.entries(value)) {
        inspect(key);
        inspect(setting);
      }
    }
  };
  inspect(parse(text));
}

export function checkFinalInputs(): void {
  checkRtrInputs();
  if (
    digest(JSON.stringify(final)) !== finalSeal ||
    digest(JSON.stringify(corpus)) !== corpusSeal
  )
    throw new Error("Frozen final safety or golden selection changed");
  if (
    groups.length !== 210 ||
    new Set(groups.map((group) => group.id)).size !== 210
  )
    throw new Error(
      "Final safety selection must reconcile all 210 distinct groups",
    );
  for (const group of groups) {
    const source = readFileSync(resolve(group.source), "utf8");
    if (digest(source) !== group.sourceSha256)
      throw new Error(`Pinned source changed: ${group.source}`);
    for (const member of group.members)
      if (!new RegExp(`^(?:async )?def ${member.symbol}\\(`, "m").test(source))
        throw new Error(`Missing selected source symbol ${member.symbol}`);
  }
  const names = readdirSync(resolve("tests/golden/scenarios"))
    .map((name) => name.replace(/\.json$/, ""))
    .sort();
  if (
    corpus.length !== 350 ||
    JSON.stringify(names) !==
      JSON.stringify(corpus.map((entry) => entry.name).sort())
  )
    throw new Error("Full parity requires the exact 350 retained definitions");
  for (const entry of corpus) {
    if (
      digest(
        readFileSync(resolve("tests/golden/scenarios", `${entry.name}.json`)),
      ) !== entry.definitionSha256 ||
      digest(readFileSync(resolve("tests/golden", `${entry.name}.txt`))) !==
        entry.expectedSha256
    )
      throw new Error(`Retained golden changed: ${entry.name}`);
  }
  const workflows = readdirSync(resolve(".github/workflows")).sort();
  if (
    JSON.stringify(workflows) !==
    JSON.stringify(["ci.yml", "release-please.yml"])
  )
    throw new Error("Unexpected offline automation configuration");
  for (const workflow of workflows)
    checkWorkflow(readFileSync(resolve(".github/workflows", workflow), "utf8"));
  for (const category of readdirSync(resolve("tests/fixtures"), {
    withFileTypes: true,
  }).filter((entry) => entry.isDirectory()))
    for (const name of readdirSync(
      resolve("tests/fixtures", category.name),
    ).filter((name) => name.endsWith(".json"))) {
      const text = readFileSync(
        resolve("tests/fixtures", category.name, name),
        "utf8",
      );
      const fixture: unknown = JSON.parse(text);
      if (
        !object(fixture) ||
        !object(fixture.provenance) ||
        fixture.provenance.provenance !== "synthetic" ||
        typeof fixture.provenance.operation !== "string" ||
        typeof fixture.provenance.reference !== "string" ||
        !fixture.provenance.reference.startsWith("https://") ||
        typeof fixture.provenance.schema_read !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(fixture.provenance.schema_read) ||
        !object(fixture.response) ||
        !Number.isInteger(fixture.response.status) ||
        /\b[0-9a-f]{32}\b/i.test(text)
      )
        throw new Error(
          `Invalid synthetic provenance: ${category.name}/${name}`,
        );
    }
}

const observations: Readonly<Record<string, readonly string[]>> = {
  "SR-003": ["sealed registry rejects"],
  "SR-004": [],
  "SR-005": ["public fast-version aliases", "version latency"],
  "SR-006": ["composite IDs survive", "golden auth-status"],
  "SR-007": ["verified-region re-mint", "OAuth 307 never follows"],
  "SR-008": ["CID redaction", "TOON boundaries"],
  "SR-009": ["golden help-top"],
  "SR-016": ["tenant selector"],
  "SR-017": ["S12 installed executable identity"],
  "SR-018": [],
  "SR-056": ["OAuth 429 after 3", "OAuth 500 after 3"],
  "SR-073": ["S13 generated parser"],
  "SR-074": ["H06 installed package"],
  "SR-075": ["S12 installed executable identity"],
  "SR-089": ["golden "],
  "SR-092": ["continuous response bytes", "DNS resolution settles"],
  "SR-098": ["H06 installed package", "OAuth 308 never follows"],
  "SR-099": ["TLS hostname rejection", "H07 installed malformed"],
  "SR-133": ["lexical origin refusal"],
  "SR-154": ["sealed registry rejects"],
  "SR-155": ["sealed registry rejects"],
  "SR-177": ["golden scopes"],
  "SR-184": ["S12 emitted hooks", "S12 retained TOML"],
  "SR-185": ["S12 non-durable", "S12 malformed", "S12 hook status"],
  "SR-188": ["S13 generated parser"],
  "SR-189": [
    "S13 bare home",
    "S13 installed user skill",
    "S13 ancestor skill",
    "S13 skill root override",
    "S13 Claude finds",
    "S13 discovery errors",
    "S13 authenticated home",
  ],
  "SR-194": ["TOON boundaries"],
  "SR-203": ["S12 installed executable identity"],
  "SR-204": ["golden help-", "golden unknown-flag"],
  "SR-205": ["H06 installed package", "H07 installed"],
  "SR-207": ["S12 emitted hooks"],
  "SR-210": ["S12 malformed", "S13 generated parser"],
};

export function finalCoverage(
  path: string,
  evidence: string,
): Record<string, unknown> {
  checkFinalInputs();
  const native = readFileSync(join(evidence, "S10/native.tap"), "utf8");
  const current = readFileSync(join(evidence, `${path}.tap`), "utf8");
  const local =
    path === "native" ? "" : readFileSync(join(evidence, "native.tap"), "utf8");
  const passed = [
    ...(native + local + current).matchAll(/^ok \d+ - (.*)$/gm),
  ].map((match) => match[1]!);
  if ([...(native + current).matchAll(/^not ok /gm)].length)
    throw new Error(
      "Final coverage requires passing native and selected-path observations",
    );
  if (passed.filter((name) => name.startsWith("golden ")).length !== 350)
    throw new Error("Final parity did not execute all 350 goldens");
  const prior = ["S10", "S11"].flatMap((slice) => {
    const result = JSON.parse(
      readFileSync(join(evidence, slice, `${path}-coverage.json`), "utf8"),
    ) as { reports: { requirement: string }[] };
    return result.reports;
  });
  const reports = final.groups.map((group) => {
    const prefixes = observations[group.id];
    if (!prefixes)
      throw new Error(`Unrepresented final safety group ${group.id}`);
    for (const prefix of prefixes)
      if (!passed.some((name) => name.startsWith(prefix)))
        throw new Error(`${group.id} has no passing observation for ${prefix}`);
    return {
      requirement: group.id,
      source: group.source,
      members: group.members,
      observations: passed.filter((name) =>
        prefixes.some((prefix) => name.startsWith(prefix)),
      ),
      mode: prefixes.length
        ? "installed public observations"
        : "sealed source, fixture and automation reconciliation",
    };
  });
  if (
    new Set([...prior, ...reports].map((report) => report.requirement)).size !==
    210
  )
    throw new Error("Final executed safety coverage is incomplete");
  return {
    path,
    reports: [...prior, ...reports],
    goldenScenarios: 350,
    nativeWindows: "pending",
    finalLedgerSha256: finalSeal,
    corpusSha256: corpusSeal,
  };
}

checkFinalInputs();
console.log(
  "Final inputs: 210 safety groups and 350 retained goldens reconciled; native Windows pending",
);
