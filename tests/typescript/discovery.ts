import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { VERSION } from "../../src/version.js";

interface Reference {
  name: string;
  order: number;
  summary: string;
  scopes: { scope: string; access: string; required?: string }[];
}

// Reconstruct the frozen Python documents independently of candidate metadata.
export async function expectedDocument(name: string): Promise<string> {
  const root = resolve("tests/golden");
  const references = await Promise.all(
    (await readdir(resolve(root, "commands"))).map(
      async (file) =>
        JSON.parse(
          await readFile(resolve(root, "commands", file), "utf8"),
        ) as Reference,
    ),
  );
  references.sort((a, b) => a.order - b.order);
  const groups = new Map<
    string,
    { access: string; names: string[]; required: Set<string> }
  >();
  for (const reference of references)
    for (const { scope, access, required = "yes" } of reference.scopes) {
      const group = groups.get(scope) ?? {
        access,
        names: [],
        required: new Set<string>(),
      };
      group.names.push(reference.name);
      group.required.add(required);
      groups.set(scope, group);
    }
  const table =
    `scopes[${groups.size}]{scope,access,commands,required}:\n` +
    [...groups]
      .map(
        ([scope, group]) =>
          `  ${JSON.stringify(scope)},${group.access},${group.names.length > 1 ? JSON.stringify(group.names.join(", ")) : group.names[0]},${group.required.size === 1 && group.required.has("selected --type") ? "selected --type" : "yes"}`,
      )
      .join("\n");
  let expected = await readFile(resolve(root, `${name}.txt`), "utf8");
  for (const [key, value] of Object.entries({
    command_summaries: references
      .map((reference) => reference.summary)
      .join("\n"),
    command_names: references.map((reference) => reference.name).join(", "),
    scope_table: table,
    description: (
      await readFile(resolve(root, "description.txt"), "utf8")
    ).trimEnd(),
  }))
    expected = expected.replaceAll(`{{${key}}}`, value);
  if (name === "help-top")
    expected = expected.replace(
      /^falcon-axi \S+ - /,
      `falcon-axi ${VERSION} - `,
    );
  if (name.startsWith("version-")) expected = `${VERSION}\n`;
  return expected;
}
