import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import s02 from "../fixtures/migration/S02/contracts.json" with { type: "json" };
import s03 from "../fixtures/migration/S03/contracts.json" with { type: "json" };
import s04 from "../fixtures/migration/S04/contracts.json" with { type: "json" };
import s05 from "../fixtures/migration/S05/contracts.json" with { type: "json" };
import s06 from "../fixtures/migration/S06/contracts.json" with { type: "json" };
import s07 from "../fixtures/migration/S07/contracts.json" with { type: "json" };
import { VERSION } from "../../src/version.js";

export interface DiscoveryDelta {
  omitSuggestions?: string[];
  scopeGuidance?: string;
  scopeMatrix?: string;
  topHelp?: string;
  commandNames?: string;
  unavailableGroup?: string;
  omitSubcommands?: { group: string; names: string[] };
  restore: string;
}
interface Reference {
  name: string;
  order: number;
  summary: string;
  scopes: { scope: string; access: string }[];
}
// Expectations come only from retained origin documents and the frozen slice ownership.
// S13 must call the original-document gate, without applying these temporary deltas.
export async function expectedDocument(
  name: string,
  delta?: DiscoveryDelta,
): Promise<string> {
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
  const owned = new Set([
    ...s02.commandNames,
    ...s03.commandNames,
    ...s04.commandNames,
    ...s05.commandNames,
    ...s06.commandNames,
    ...s07.commandNames,
  ]);
  const selected = references.filter((reference) => owned.has(reference.name));
  const names = selected.map((reference) => reference.name).join(", ");
  let expected = await readFile(resolve(root, `${name}.txt`), "utf8");
  expected = expected.replaceAll(
    "{{description}}",
    (await readFile(resolve(root, "description.txt"), "utf8")).trimEnd(),
  );
  if (delta?.commandNames)
    expected = expected.replaceAll("{{command_names}}", names);
  if (delta?.topHelp) {
    expected = expected.replaceAll(
      "{{command_summaries}}",
      selected.map((reference) => reference.summary).join("\n"),
    );
    expected = expected.slice(0, expected.indexOf("\nRTR execution"));
    expected = expected.replace(
      /^falcon-axi \S+ - /,
      `falcon-axi ${VERSION} - `,
    );
  }
  if (delta?.scopeMatrix) {
    const groups = new Map<string, string[]>();
    for (const reference of selected)
      for (const { scope } of reference.scopes) {
        const commands = groups.get(scope) ?? [];
        if (!commands.includes(reference.name)) commands.push(reference.name);
        groups.set(scope, commands);
      }
    expected =
      `posture: read-only\nscopes[${groups.size}]{scope,access,commands,required}:\n` +
      [...groups]
        .map(
          ([scope, commands]) =>
            `  ${JSON.stringify(scope)},read,${commands.length > 1 ? JSON.stringify(commands.join(", ")) : commands[0]},${commands.every((name) => /^(policy|exclusion) /.test(name)) ? "selected --type" : "yes"}\n`,
        )
        .join("") +
      'member_cid_token_scope: unresolved (Flight Control read may be required; see design section 17.7)\nhelp[2]: "Grant these scopes in the Falcon console under Support and resources > API clients and keys","Grant read access only; falcon-axi needs no write scope"\n';
  }
  if (delta?.unavailableGroup)
    expected = `error: unknown command ${delta.unavailableGroup}\ncode: VALIDATION_ERROR\nhelp[2]: ${JSON.stringify(`valid commands: ${names}`)},"Run \`falcon-axi --help\` for the command list"\n`;
  if (delta?.scopeGuidance)
    expected = expected.replace(
      /^scopes: .*$/m,
      `scopes: ${delta.scopeGuidance}`,
    );
  if (delta?.omitSubcommands) {
    const { group, names } = delta.omitSubcommands;
    expected = expected.replace(
      new RegExp(`valid ${group} subcommands: ([^"\\n]+)`),
      (_text, verbs: string) =>
        `valid ${group} subcommands: ${verbs
          .split(", ")
          .filter((verb) => !names.includes(verb))
          .join(", ")}`,
    );
  }
  if (delta?.omitSuggestions)
    expected = expected.replace(
      /^help\[\d+\]: (.*)\n/m,
      (_line, values: string) => {
        const hints = JSON.parse(`[${values}]`) as string[];
        const kept = hints.filter(
          (hint) => !delta.omitSuggestions!.includes(hint),
        );
        return kept.length
          ? `help[${kept.length}]: ${kept.map((hint) => JSON.stringify(hint)).join(",")}\n`
          : "";
      },
    );
  return expected;
}
