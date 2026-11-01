import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, win32 } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import schema from "./axi-credential.schema.json" with { type: "json" };
import { CliError, object } from "./core.js";
import { registerSecret, registerMemberCid } from "./render.js";
import { verifyWindowsFile } from "./windows-acl.js";
import { rtrPolicy, readOnly } from "./rtr-policy.js";
import type { RtrPolicy } from "./rtr-policy.js";

export interface Credential {
  clientId: string;
  clientSecret: string;
  region?: string;
  memberCid?: string;
  channel?: "environment" | "file";
  profile?: string;
  path?: string;
  secretSource?: string;
  rtr?: RtrPolicy;
}
const aliases: Readonly<Record<string, string>> = {
  FALCON_CLIENT_ID: "FALCON_AXI_CLIENT_ID",
  FALCON_CLIENT_SECRET: "FALCON_AXI_CLIENT_SECRET",
  FALCON_MEMBER_CID: "FALCON_AXI_MEMBER_CID",
  FALCON_BASE_URL: "FALCON_AXI_REGION",
  FALCON_PROXY_URL: "FALCON_AXI_PROXY_URL",
};
const sourceAliases = new Map<string, string>();
export function normalizeEnvironment(): void {
  for (const [old, current] of Object.entries(aliases)) {
    if (process.env[old] !== undefined) {
      process.stderr.write(`${old} is deprecated; use ${current}\n`);
      if (process.env[current] === undefined) {
        sourceAliases.set(current, old);
        process.env[current] = process.env[old];
      }
    }
  }
  readOnly();
}
export function directory(kind: "config" | "state"): string {
  const env = process.env;
  if (process.platform === "win32")
    return join(
      env[kind === "config" ? "APPDATA" : "LOCALAPPDATA"] ||
        join(homedir(), "AppData", kind === "config" ? "Roaming" : "Local"),
      "falcon-axi",
    );
  const root = env[`XDG_${kind.toUpperCase()}_HOME`];
  return join(
    root && isAbsolute(root)
      ? root
      : join(homedir(), kind === "config" ? ".config" : ".local/state"),
    "falcon-axi",
  );
}
export function configPath(flag?: string): string {
  return (
    flag ||
    process.env.FALCON_AXI_CONFIG ||
    join(directory("config"), "config.json")
  );
}
export function writeLogPath(): string {
  return (
    process.env.FALCON_AXI_WRITE_LOG || join(directory("state"), "writes.log")
  );
}
async function checkLegacy(path: string): Promise<void> {
  const exists = async (candidate: string): Promise<boolean> => {
    try {
      await lstat(candidate);
      return true;
    } catch (error) {
      if (object(error) && error.code === "ENOENT") return false;
      throw new CliError("CONFIG_INSECURE", `cannot inspect ${candidate}`);
    }
  };
  const legacy = join(homedir(), ".config/falcon-axi/credentials");
  if (!(await exists(path)) && (await exists(legacy)))
    throw new CliError(
      "CONFIG_MOVED",
      `legacy credentials at ${legacy} must be converted to ${path}`,
      [
        "Use version 1 config.json profiles with clientId and clientSecret: {env: NAME} or {file: /absolute/path}",
        "See https://github.com/knowttl/artium-axi/blob/main/docs/credential-standard.md",
      ],
    );
}
export interface Profiles {
  profiles: Record<string, Record<string, unknown>>;
  defaultProfile?: string;
}
export async function loadProfiles(
  config?: string,
  diagnostic = false,
): Promise<Profiles> {
  const path = configPath(config);
  await checkLegacy(path);
  const contents = await readPrivate(path, false, diagnostic);
  if (contents === undefined) return { profiles: {} };
  let document: unknown;
  try {
    document = JSON.parse(contents) as unknown;
  } catch {
    throw new CliError("CONFIG_INVALID", `invalid JSON in ${path}`);
  }
  if (
    !object(document) ||
    document.version !== 1 ||
    !object(document.profiles) ||
    Object.keys(document).some(
      (key) => !["version", "defaultProfile", "profiles"].includes(key),
    )
  )
    throw new CliError(
      "CONFIG_INVALID",
      "config.json requires version 1 and a profiles object",
    );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  for (const [name, entry] of Object.entries(document.profiles)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name))
      throw new CliError("CONFIG_INVALID", "invalid profile name");
    if (!validate(entry) || !object(entry))
      throw new CliError(
        "CONFIG_INVALID",
        `profile ${name} does not match the profile schema`,
      );
    rtrPolicy(entry.rtr);
    for (const field of ["clientId", "region", "memberCid"])
      if (typeof entry[field] === "string" && !entry[field].trim())
        throw new CliError(
          "CONFIG_INVALID",
          `profile ${name} requires a nonempty string for ${field}`,
        );
    if (
      object(entry.clientSecret) &&
      typeof entry.clientSecret.file === "string"
    ) {
      const file = entry.clientSecret.file;
      if (
        process.platform === "win32"
          ? !/^[A-Za-z]:$/.test(win32.parse(file).root.slice(0, 2)) ||
            !win32.isAbsolute(file)
          : !isAbsolute(file)
      )
        throw new CliError(
          "CONFIG_INVALID",
          "clientSecret must reference an absolute local file",
        );
    }
  }
  const defaultProfile = document.defaultProfile;
  if (
    defaultProfile !== undefined &&
    defaultProfile !== null &&
    (typeof defaultProfile !== "string" ||
      !Object.hasOwn(document.profiles, defaultProfile))
  )
    throw new CliError(
      "CONFIG_INVALID",
      "defaultProfile must name an existing profile",
    );
  return {
    profiles: document.profiles as Profiles["profiles"],
    ...(typeof defaultProfile === "string" ? { defaultProfile } : {}),
  };
}
export async function readPrivate(
  path: string,
  secret = false,
  diagnostic = false,
): Promise<string | undefined> {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if (object(error) && error.code === "ENOENT") return undefined;
    throw new CliError(
      "CONFIG_INSECURE",
      "cannot inspect the selected credential file",
    );
  }
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    (process.platform === "win32" &&
      !(await verifyWindowsFile(path, diagnostic))) ||
    (process.platform !== "win32" &&
      (info.uid !== process.getuid!() ||
        (info.mode & (secret ? 0o077 : 0o022)) !== 0))
  )
    throw new CliError(
      "CONFIG_INSECURE",
      "the selected credential file is not protected",
    );
  let file;
  try {
    file = await open(
      path,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW ?? 0) |
        (constants.O_NONBLOCK ?? 0),
    );
  } catch {
    throw new CliError("CONFIG_INVALID", `cannot read UTF-8 from ${path}`);
  }
  try {
    const opened = await file.stat();
    if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino)
      throw new CliError(
        "CONFIG_INSECURE",
        "the credential file changed during its read check",
      );
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(
        await file.readFile(),
      );
    } catch {
      throw new CliError("CONFIG_INVALID", `cannot read UTF-8 from ${path}`);
    }
  } finally {
    await file.close();
  }
}
export async function resolveCredential(
  config?: string,
  profile?: string,
  diagnostic = false,
): Promise<Credential> {
  const env = process.env;
  const selected = profile ?? env.FALCON_AXI_PROFILE;
  const path = configPath(config);
  await checkLegacy(path);
  let credential: Credential;
  if (
    selected === undefined &&
    (env.FALCON_AXI_CLIENT_ID || env.FALCON_AXI_CLIENT_SECRET)
  ) {
    if (!env.FALCON_AXI_CLIENT_ID || !env.FALCON_AXI_CLIENT_SECRET)
      throw new CliError(
        "CONFIG_INVALID",
        `env profile is incomplete; set ${env.FALCON_AXI_CLIENT_ID ? "FALCON_AXI_CLIENT_SECRET" : "FALCON_AXI_CLIENT_ID"}`,
      );
    credential = {
      clientId: env.FALCON_AXI_CLIENT_ID,
      clientSecret: env.FALCON_AXI_CLIENT_SECRET,
      channel: "environment",
      profile: "env",
      secretSource: `env:${sourceAliases.get("FALCON_AXI_CLIENT_SECRET") ?? "FALCON_AXI_CLIENT_SECRET"}`,
      ...(env.FALCON_AXI_REGION ? { region: env.FALCON_AXI_REGION } : {}),
      ...(env.FALCON_AXI_MEMBER_CID
        ? { memberCid: env.FALCON_AXI_MEMBER_CID }
        : {}),
    };
  } else {
    const document = await loadProfiles(config, diagnostic);
    const profiles = document.profiles;
    const names = Object.keys(profiles);
    const name =
      selected ??
      document.defaultProfile ??
      (names.length === 1 ? names[0] : undefined);
    if (typeof name !== "string")
      throw new CliError(
        names.length ? "PROFILE_AMBIGUOUS" : "PROFILE_REQUIRED",
        names.length
          ? "select a profile with --profile or FALCON_AXI_PROFILE"
          : "no Falcon profile configured",
        names.length
          ? []
          : [
              "Set FALCON_AXI_CLIENT_ID and FALCON_AXI_CLIENT_SECRET in the environment",
              `Or configure a profile with a clientSecret SecretRef in ${path}`,
              "Provision an API client with read scopes; only `search start`, `search stop`, and `identity activity` need NGSIEM:write",
            ],
      );
    if (!Object.hasOwn(profiles, name))
      throw new CliError(
        "PROFILE_NOT_FOUND",
        "selected profile does not exist",
        ["Run `falcon-axi profile list`"],
      );
    const settings = profiles[name] as Record<string, unknown>;
    const ref = settings.clientSecret ?? { env: "FALCON_AXI_CLIENT_SECRET" };
    if (!object(ref))
      throw new CliError("CONFIG_INVALID", "invalid clientSecret SecretRef");
    let secret: string | undefined;
    if (typeof ref.env === "string") secret = env[ref.env];
    else if (typeof ref.file === "string" && isAbsolute(ref.file))
      secret = (await readPrivate(ref.file, true, diagnostic))?.trimEnd();
    if (!secret)
      throw new CliError(
        "AUTH_REQUIRED",
        "clientSecret SecretRef resolved to no value",
      );
    credential = {
      clientId: settings.clientId as string,
      clientSecret: secret,
      channel: "file",
      rtr: rtrPolicy(settings.rtr),
      profile: name,
      secretSource:
        typeof ref.env === "string"
          ? `env:${sourceAliases.get(ref.env) ?? ref.env}`
          : `file:${String(ref.file)}`,
      ...(typeof ref.file === "string" ? { path: ref.file } : {}),
      ...(typeof settings.region === "string"
        ? { region: settings.region }
        : {}),
      ...(typeof settings.memberCid === "string"
        ? { memberCid: settings.memberCid }
        : {}),
    };
  }
  registerSecret(credential.clientId);
  registerSecret(credential.clientSecret);
  if (credential.memberCid) registerMemberCid(credential.memberCid);
  return credential;
}
