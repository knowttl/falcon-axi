import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * The local architecture boundary (docs/design/v1.md §3.3 property 6, §14.5, §15.4).
 * Run by `npm run lint` and asserted again by test/offline/architecture.test.ts.
 */
const NETWORK_SINK = "src/transport/network-sink.ts";
const SINK_FUNCTION = "sendPermittedRequest";
const NETWORK_IMPORT = /from\s+["']node:(?:http|https|net|tls|dgram)["']/;
const NETWORK_REFERENCE = /\bfetch\s*\(/;
const PROCESS_EXECUTION = /node:child_process/;
const AUTOMATION_PATHS = [".github/workflows", ".gitlab-ci.yml", ".circleci", "azure-pipelines.yml", "Jenkinsfile"];

async function sources(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...(await sources(path)));
    else if (path.endsWith(".ts")) found.push(path.replace(/\\/g, "/"));
  }
  return found;
}

/** The body of the one function allowed to touch a network API. */
function sinkFunctionBody(text) {
  const start = text.indexOf(`export async function ${SINK_FUNCTION}`);
  if (start < 0) throw new Error(`${NETWORK_SINK} no longer defines ${SINK_FUNCTION}`);
  let depth = 0;
  for (let index = text.indexOf("{", start); index < text.length; index++) {
    if (text[index] === "{") depth++;
    else if (text[index] === "}" && --depth === 0) return text.slice(start, index + 1);
  }
  throw new Error(`${SINK_FUNCTION} is unterminated`);
}

async function exists(path) {
  try {
    await readdir(path);
    return true;
  } catch (error) {
    if (error.code === "ENOTDIR") return true;
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

export async function check() {
  for (const file of await sources("src")) {
    const text = await readFile(file, "utf8");
    if (PROCESS_EXECUTION.test(text)) throw new Error(`process execution is forbidden: ${file}`);
    if (file === NETWORK_SINK) {
      const body = sinkFunctionBody(text);
      const outside = text.replace(body, "");
      if (NETWORK_REFERENCE.test(outside)) throw new Error(`network reference outside ${SINK_FUNCTION}: ${file}`);
      continue;
    }
    if (NETWORK_IMPORT.test(text)) throw new Error(`network import outside the sealed sink: ${file}`);
    if (NETWORK_REFERENCE.test(text)) throw new Error(`network reference outside the sealed sink: ${file}`);
  }

  // The captain's directive bans automation that could carry a credential at all, which is strictly
  // stronger than scanning those paths for FALCON_AXI_LIVE or the credential variable names (§15.4).
  for (const path of AUTOMATION_PATHS) {
    if (await exists(path)) throw new Error(`automation configuration is not authorized in this repository: ${path}`);
  }
  return true;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await check();
  process.stdout.write("architecture boundary ok\n");
}
