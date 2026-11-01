import {
  readFileSync,
  readdirSync,
  mkdirSync,
  writeFileSync,
  unlinkSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  commands,
  valueFlags,
  boolFlags,
  DESCRIPTION,
} from "../../src/metadata.js";
import { HOME_GUIDANCE } from "../../src/skill.js";
import help from "../../src/help.json" with { type: "json" };
import searchHelp from "../../src/search-help.json" with { type: "json" };

const root = fileURLToPath(new URL("../../../", import.meta.url));
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  description: string;
};
if (pkg.description !== DESCRIPTION)
  throw new Error("Package description differs from the CLI description");
const check = process.argv.slice(2);
if (check.length > 1 || (check.length === 1 && check[0] !== "--check"))
  throw new Error("Expected --check or no arguments");
const npmCommand = "npx -y @knowttl/falcon-axi";
const npmExamples = (text: string): string =>
  text.replaceAll("uvx falcon-axi", npmCommand);
const main = npmExamples(
  readFileSync(
    join(root, "scripts/typescript/skill-template.md"),
    "utf8",
  ).replace(
    "{{home_guidance}}",
    HOME_GUIDANCE.map(
      (line) => `- ${line.replaceAll("`falcon-axi", "`uvx falcon-axi")}`,
    ).join("\n"),
  ),
);
const expected = new Map<string, string>([
  ["skills/falcon-axi/SKILL.md", main],
  [
    "skills/falcon-axi/references/agent-guide.md",
    npmExamples(
      readFileSync(join(root, "scripts/typescript/agent-guide.md"), "utf8"),
    ),
  ],
]);
for (const command of commands) {
  const text = { ...help, ...searchHelp }[command.name as keyof typeof help];
  if (!text) throw new Error(`No command help for ${command.name}`);
  expected.set(
    `skills/falcon-axi/references/${command.name.replaceAll(" ", "-")}.md`,
    `# ${command.name}\n\n${command.summary.trim()}\n\n\`\`\`text\n${text.replaceAll("falcon-axi", npmCommand)}\n\`\`\`\n`,
  );
}
const hash = (text: string | Buffer): string =>
  createHash("sha256").update(text).digest("hex");
const catalog = {
  version: 1,
  executable: ".typescript-build/src/bin.js",
  hook: ".typescript-build/src/hook.js",
  schema: {
    path: ".typescript-build/src/axi-credential.schema.json",
    sha256: hash(
      readFileSync(join(root, ".typescript-build/src/axi-credential.schema.json")),
    ),
  },
  parser: {
    path: ".typescript-build/src/parser.js",
    sha256: hash(readFileSync(join(root, ".typescript-build/src/parser.js"))),
  },
  skill: { path: "skills/falcon-axi/SKILL.md", sha256: hash(main) },
  globalFlags: [...boolFlags, ...valueFlags].map((flag) => flag.slice(2)),
  commands: commands.map((command) => ({
    command: command.name,
    flags: Object.fromEntries([
      ...boolFlags.map((flag) => [flag.slice(2), "boolean"]),
      ...valueFlags.map((flag) => [flag.slice(2), "value"]),
      ...command.booleans.map((flag) => [flag, "boolean"]),
      ...command.values.map((flag) => [flag, "value"]),
    ]),
  })),
};
expected.set(
  "artium-invocations.json",
  JSON.stringify(catalog, null, 2) + "\n",
);
const references = readdirSync(join(root, "skills/falcon-axi/references"));
for (const name of references)
  if (!expected.has(`skills/falcon-axi/references/${name}`)) {
    if (check.length) throw new Error(`Extra skill reference: ${name}`);
    unlinkSync(join(root, "skills/falcon-axi/references", name));
  }
for (const [path, content] of expected) {
  const destination = join(root, path);
  if (check.length) {
    if (readFileSync(destination, "utf8") !== content)
      throw new Error(`Generated content is stale: ${path}`);
  } else {
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, content);
  }
}
console.log(
  `Generated skill and command catalog ${check.length ? "are current" : "updated"}`,
);
