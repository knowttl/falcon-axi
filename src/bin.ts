#!/usr/bin/env node
import { tryFastPath } from "axi-sdk-js/fast-path";
import { VERSION } from "./version.js";

if (!tryFastPath(process.argv.slice(2), { version: VERSION })) {
  const { main } = await import("./cli.js");
  const exitCode = await main(process.argv.slice(2));
  // Flush the safe result before terminating the one-shot CLI.
  process.stdout.write("", () => process.exit(exitCode));
}
