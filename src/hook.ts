#!/usr/bin/env node
import { CliError } from "./core.js";
import { resolveCredential, normalizeEnvironment } from "./credentials.js";
import { resolveOrigin } from "./origin.js";
import { redactText } from "./render.js";
import { VERSION } from "./version.js";

let context: string;
try {
  normalizeEnvironment();
  const credential = await resolveCredential();
  const region = resolveOrigin(credential.region, false);
  context = `profile resolved; region ${region}. Run \`falcon-axi\` for recent detections.`;
} catch (error) {
  const code =
    error instanceof CliError ? error.code : "LOCAL_STATUS_UNAVAILABLE";
  context = `profile unresolved (${code}). Run \`falcon-axi setup\` for guidance.`;
}
process.stdout.write(
  redactText(`falcon-axi ${VERSION}: ${context}`).replace(/[\n\r]/g, " ") +
    "\n",
);
