import { lstat, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { CliError } from "./core.js";

export type CredentialChannel = "environment" | "file";

export type Credential = Readonly<{
  clientId: string;
  clientSecret: string;
  channel: CredentialChannel;
  path?: string;
}>;

export const DEFAULT_CREDENTIALS_PATH = join(homedir(), ".config", "falcon-axi", "credentials");

export function credentialsPath(env: NodeJS.ProcessEnv = process.env): string {
  return env.FALCON_AXI_CREDENTIALS_FILE || DEFAULT_CREDENTIALS_PATH;
}

export function setupHelp(env: NodeJS.ProcessEnv = process.env): readonly string[] {
  return [
    "Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in the environment",
    `Or write them to ${credentialsPath(env)} with mode 0600`,
    "Provision a read-only API client; falcon-axi never needs a write scope",
  ];
}

function incomplete(missing: string, present: string): CliError {
  return new CliError("CREDENTIAL_INCOMPLETE", `${present} is set but ${missing} is missing`, [
    `Set ${missing} as well`,
    `Or unset ${present} to fall back to ${credentialsPath()}`,
  ]);
}

/**
 * Rejects a credentials file that any other account could have written or read (§5.2).
 * The file is not read when this fails, and no value from it is ever echoed.
 */
async function assertProtectedFile(path: string): Promise<boolean> {
  let stats;
  try {
    stats = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw new CliError("VALIDATION_ERROR", `the credentials file at ${path} could not be read`, [
      `Ensure ${path} is a regular file owned by the current user with mode 0600`,
    ]);
  }
  const owned = typeof process.getuid === "function" ? stats.uid === process.getuid() : true;
  if (stats.isSymbolicLink() || !stats.isFile() || !owned || (stats.mode & 0o077) !== 0) {
    throw new CliError("VALIDATION_ERROR", `the credentials file at ${path} is not protected`, [
      `${path} must be a regular file owned by the current user with mode 0600`,
      "Run `chmod 0600` on it and replace any symlink with the file itself",
    ]);
  }
  return true;
}

function parseKeyValues(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator <= 0) continue;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^["'](.*)["']$/, "$1");
    values[key] = value;
  }
  return values;
}

/**
 * Resolves a credential through the accepted input channels, in precedence order (§5.2).
 * A half-configured environment stops resolution rather than falling through to a file, because a
 * silent fallback could select the wrong identity.
 */
export async function resolveCredential(env: NodeJS.ProcessEnv = process.env): Promise<Credential | undefined> {
  const id = env.FALCON_CLIENT_ID;
  const secret = env.FALCON_CLIENT_SECRET;
  if (id && secret) return { clientId: id, clientSecret: secret, channel: "environment" };
  if (id) throw incomplete("FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID");
  if (secret) throw incomplete("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET");

  const path = credentialsPath(env);
  if (!(await assertProtectedFile(path))) return undefined;
  const values = parseKeyValues(await readFile(path, "utf8"));
  const fileId = values.FALCON_CLIENT_ID;
  const fileSecret = values.FALCON_CLIENT_SECRET;
  if (fileId && fileSecret) return { clientId: fileId, clientSecret: fileSecret, channel: "file", path };
  if (!fileId && !fileSecret) return undefined;
  throw new CliError(
    "CREDENTIAL_INCOMPLETE",
    `the credentials file at ${path} sets only one half of the credential`,
    [`Set both FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in ${path}`],
  );
}
