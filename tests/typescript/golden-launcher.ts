import { pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { realpathSync } from "node:fs";

const executable = realpathSync(process.argv[2]!);
const cli = (await import(
  pathToFileURL(join(dirname(executable), "cli.js")).href
)) as {
  main: (argv: string[], bin: string) => Promise<number>;
};
process.exitCode = await cli.main(process.argv.slice(3), "falcon-axi");
