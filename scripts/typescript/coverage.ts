import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { commands } from "../../src/metadata.js";
import s02 from "../../tests/fixtures/migration/S02/contracts.json" with { type: "json" };
import s03 from "../../tests/fixtures/migration/S03/contracts.json" with { type: "json" };
import ledger from "../../tests/migration/coverage.json" with { type: "json" };

const digest = (value: string | Buffer): string =>
  createHash("sha256").update(value).digest("hex");
const seal = "2e5ed16c25d3b8beeda2127ad9664a849b78b221ea7e65fa668eb69a7fdb1674";
if (digest(JSON.stringify(ledger)) !== seal)
  throw new Error(
    "Frozen safety ownership, members or parameter selections changed",
  );
const expectedCommands = [
  ...new Set([...s02.commandNames, ...s03.commandNames]),
]
  .filter((name) => name !== "home")
  .sort();
if (
  JSON.stringify(commands.map((command) => command.name).sort()) !==
  JSON.stringify(expectedCommands)
)
  throw new Error(
    "Implemented command coverage differs from frozen slice ownership",
  );
const operations = [
  ...new Set(commands.flatMap((command) => command.operations)),
].sort();
if (JSON.stringify(operations) !== JSON.stringify([...s03.operationIds].sort()))
  throw new Error("Operation coverage differs from frozen S03 ownership");
for (const group of ledger.groups) {
  if (digest(readFileSync(resolve(group.source))) !== group.sourceSha256)
    throw new Error(`Pinned source changed: ${group.source}`);
  const source = readFileSync(resolve(group.source), "utf8");
  for (const member of group.members)
    if (!source.includes(`def ${member.symbol}(`))
      throw new Error(`Missing source symbol ${member.symbol}`);
}
for (const flag of commands.flatMap((command) => [
  ...command.values,
  ...command.booleans,
]))
  if (/(secret|password|token|key|passphrase)/i.test(flag))
    throw new Error("Secret-shaped flag registration refused");

// Source symbols are adapted to public observations, not historical test counts.
// Structural entries run above; other entries bind to passing installed-artifact checks.
const bindings: Readonly<Record<string, readonly string[]>> = {
  "SR-010": [],
  "SR-011": ["SR-011/SR-191 continuation"],
  "SR-015": ["tenant selector"],
  "SR-019": ["H06 installed package"],
  "SR-022": ["SR-022 invalid input"],
  "SR-027": ["SR-027 help bypasses"],
  "SR-032": ["C05", "golden auth-status"],
  "SR-033": ["S03 installed host logins", "golden detection-list-member-cid"],
  "SR-052": ["C08 incomplete", "C06 no implicit", "C05 profile selection"],
  "SR-053": ["C14 unsafe config"],
  "SR-054": ["SR-054 cursor refuses", "SR-054 tampered"],
  "SR-062": [
    "SR-062 missing process",
    "SR-062 ancestor-only",
    "S03 installed detection process",
  ],
  "SR-063": [
    "golden detection-list-filtered",
    "golden detection-list-chunked",
    "golden detection-list-at-the-wall",
  ],
  "SR-064": ["SR-064 malformed", "SR-064 omitted", "golden detection-summary"],
  "SR-065": [
    "golden detection-summary-scope-denied",
    "golden unknown-severity",
  ],
  "SR-068": ["S03 installed host network"],
  "SR-071": ["S03 scope refusal names the actual grant: Hosts:read"],
  "SR-072": ["S03 installed host network"],
  "SR-079": [
    "SR-079 field validation",
    "golden detection-list-fields",
    "golden host-list-fields",
  ],
  "SR-081": ["SR-081 incomplete", "SR-081 FileVantage batches"],
  "SR-082": [
    "S03 installed file-change show",
    "S03 distinguishes malformed or missing file-change",
    "S03 scope refusal names the actual grant: Falcon FileVantage:read",
  ],
  "SR-083": [
    "golden detection-list-filtered",
    "golden host-list-filtered",
    "SR-191 retained shell matrix",
  ],
  "SR-085": ["golden error-fql-invalid", "golden host-logins"],
  "SR-094": [
    "H06 installed package",
    "S03 installed process tree",
    "S03 installed host list",
  ],
  "SR-100": [
    "S03 installed host list",
    "golden host-walk-budget-at-wall",
    "golden host-list-fields",
  ],
  "SR-101": ["S03 installed host logins", "SR-101 hostname"],
  "SR-109": [
    "golden detection-list-identity",
    "golden detection-show-identity",
    "golden detection-list-unknown-product",
  ],
  "SR-123": [
    "S03 installed ioc list",
    "S03 installed ioc show",
    "golden ioc-hosts",
    "golden ioc-processes",
  ],
  "SR-125": ["golden ioc-processes", "unknown flag fails before credentials"],
  "SR-134": ["SR-134 hydration loss"],
  "SR-135": [
    "H07 installed empty response",
    "golden detection-list-empty-unfiltered",
  ],
  "SR-140": [
    "S03 installed process show",
    "SR-140/SR-173 redaction",
    "S03 distinguishes malformed or missing process show",
  ],
  "SR-141": [
    "SR-141 tree cycle",
    "SR-141 tree stops",
    "S03 installed process tree",
  ],
  "SR-142": [
    "SR-142 full child continuation",
    "golden process-tree-empty-children",
  ],
  "SR-143": ["C01/C02", "C05 complete environment", "C05 profile selection"],
  "SR-144": ["C18 legacy", "C19 canonical identity", "C19 an explicit"],
  "SR-145": [
    "C05/C09",
    "C10/C11",
    "C06 no implicit",
    "C04 profile list selects",
  ],
  "SR-146": ["SR-146 credential owner", "C13 file secret", "C14 loose secret"],
  "SR-148": ["SR-148 invalid READ_ONLY"],
  "SR-149": ["H06 installed package"],
  "SR-173": [
    "S03 installed rtr session",
    "S03 installed rtr audit",
    "SR-140/SR-173 redaction",
  ],
  "SR-174": [
    "sealed registry rejects",
    "S03 scope refusal names the actual grant: Real time response:read",
  ],
  "SR-190": ["golden auth-status-member-cid"],
  "SR-191": ["SR-191 retained shell matrix"],
  "SR-197": ["golden detection-walk", "golden host-walk-budget-at-wall"],
  "SR-201": ["SR-201 deleted hydration"],
  "SR-206": [
    "SR-134 hydration loss",
    "golden detection-show-full",
    "golden detection-show-truncated",
  ],
};
if (
  JSON.stringify(Object.keys(bindings).sort()) !==
  JSON.stringify(ledger.groups.map((group) => group.id).sort())
)
  throw new Error("A safety group lacks an executable replacement binding");
const localOnly = new Set([
  "SR-052",
  "SR-053",
  "SR-143",
  "SR-144",
  "SR-145",
  "SR-146",
  "SR-148",
  "SR-149",
  "SR-190",
]);
const managedBindings: Readonly<Record<string, readonly string[]>> = {
  "SR-064": [
    "SR-064 malformed",
    "SR-064 omitted",
    "S03 installed detection summary",
  ],
  "SR-015": ["Managed connection override"],
  "SR-032": ["C22 managed auth status", "H06 installed package"],
  "SR-033": ["S03 installed host logins", "H06 installed package"],
  "SR-063": ["H06 installed package", "SR-201 deleted hydration"],
  "SR-065": ["S03 scope refusal names the actual grant: Alerts:read"],
  "SR-079": ["SR-079 field validation", "S03 installed host list"],
  "SR-083": ["SR-011/SR-191 continuation"],
  "SR-085": ["SR-068/SR-085 filter rejection"],
  "SR-094": [
    "H06 installed package",
    "S03 installed process tree",
    "S03 installed host list",
  ],
  "SR-100": ["S03 installed host list", "SR-201 deleted hydration"],
  "SR-109": ["S03 installed detection show", "S03 installed detection summary"],
  "SR-123": [
    "S03 installed ioc list",
    "S03 installed ioc show",
    "S03 installed ioc hosts",
    "S03 installed ioc processes",
  ],
  "SR-125": ["SR-125 IPv6 observations", "SR-068/SR-085 filter rejection"],
  "SR-135": ["H07 installed empty response"],
  "SR-142": ["SR-142 full child continuation", "S03 installed process tree"],
  "SR-191": ["SR-011/SR-191 continuation", "Managed connection override"],
  "SR-197": ["SR-197 all ignores", "SR-201 deleted hydration"],
  "SR-206": ["SR-134 hydration loss", "SR-140/SR-173 redaction"],
};

const args = process.argv.slice(2);
let evidence: string | undefined;
let path: string | undefined;
for (let index = 0; index < args.length; index++) {
  const flag = args[index]!;
  if (flag === "--strict") continue;
  if (flag === "--evidence" && args[index + 1]) evidence = args[++index];
  else if (
    flag === "--path" &&
    ["native", "artium"].includes(args[index + 1] ?? "")
  )
    path = args[++index];
  else {
    console.error(`Unknown coverage selector ${flag}`);
    process.exit(2);
  }
}
if (Boolean(evidence) !== Boolean(path)) {
  console.error("--evidence and --path must be supplied together");
  process.exit(2);
}
if (evidence && path) {
  const tap = readFileSync(join(evidence, `${path}.tap`), "utf8");
  const passed = [...tap.matchAll(/^ok \d+ - (.*)$/gm)].map(
    (match) => match[1]!,
  );
  if (!passed.length || /^not ok /m.test(tap))
    throw new Error(
      "Behavioral coverage requires a nonempty, passing test run",
    );
  const reports = ledger.groups.map((group) => {
    const selected = bindings[group.id]!;
    const nativeOnly = path === "artium" && localOnly.has(group.id);
    const managed =
      path !== "artium"
        ? selected
        : nativeOnly
          ? ["Managed connection override", "C22 managed auth status"]
          : (managedBindings[group.id] ?? selected);
    const missing = managed.filter(
      (prefix) => !passed.some((name) => name.startsWith(prefix)),
    );
    if (missing.length)
      throw new Error(
        `${group.id} has no passing observation for ${missing.join(", ")}`,
      );
    return {
      requirement: group.id,
      source: group.source,
      symbols: group.members.map((member) => member.symbol),
      mode: nativeOnly
        ? "native-owned configuration; managed override refusal and private-profile health"
        : managed.length
          ? "installed public observations"
          : "structural registration check",
      observations: passed.filter((name) =>
        managed.some((prefix) => name.startsWith(prefix)),
      ),
      nativeWindows: ["SR-143", "SR-146", "SR-149"].includes(group.id)
        ? "pending"
        : "not applicable",
    };
  });
  writeFileSync(
    join(evidence, `${path}-coverage.json`),
    JSON.stringify(
      { path, ledgerSha256: seal, reports, pending: ledger.reassignments },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
}
console.log(
  `coverage: ${ledger.groups.length} frozen groups, ${operations.length} operations, ${expectedCommands.length} commands; native Windows pending`,
);
