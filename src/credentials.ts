import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import schema from "./axi-credential.schema.json" with { type: "json" };
import { CliError, object } from "./core.js";
import { registerSecret, registerMemberCid } from "./render.js";

export interface Credential {
  clientId: string;
  clientSecret: string;
  region?: string;
  memberCid?: string;
}
export async function readPrivate(
  path: string,
  secret = false,
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
    (process.platform !== "win32" &&
      (info.uid !== process.getuid!() ||
        (info.mode & (secret ? 0o077 : 0o022)) !== 0))
  )
    throw new CliError(
      "CONFIG_INSECURE",
      "the selected credential file is not protected",
    );
  const file = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    const opened = await file.stat();
    if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino)
      throw new CliError(
        "CONFIG_INSECURE",
        "the credential file changed during its read check",
      );
    return (await file.readFile("utf8")).replace(/^\uFEFF/, "");
  } finally {
    await file.close();
  }
}
export async function resolveCredential(
  config?: string,
  profile?: string,
): Promise<Credential> {
  const env = process.env;
  const selected = profile ?? env.FALCON_AXI_PROFILE;
  const path =
    config ??
    env.FALCON_AXI_CONFIG ??
    join(
      env.XDG_CONFIG_HOME ?? join(homedir(), ".config"),
      "falcon-axi",
      "config.json",
    );
  let credential: Credential;
  if (!selected && (env.FALCON_AXI_CLIENT_ID || env.FALCON_AXI_CLIENT_SECRET)) {
    if (!env.FALCON_AXI_CLIENT_ID || !env.FALCON_AXI_CLIENT_SECRET)
      throw new CliError(
        "CONFIG_INVALID",
        "env profile is incomplete; set the client ID and client secret together",
      );
    credential = {
      clientId: env.FALCON_AXI_CLIENT_ID,
      clientSecret: env.FALCON_AXI_CLIENT_SECRET,
      ...(env.FALCON_AXI_REGION ? { region: env.FALCON_AXI_REGION } : {}),
      ...(env.FALCON_AXI_MEMBER_CID
        ? { memberCid: env.FALCON_AXI_MEMBER_CID }
        : {}),
    };
  } else {
    const contents = await readPrivate(path);
    if (!contents)
      throw new CliError("PROFILE_REQUIRED", "no Falcon profile configured");
    let document: unknown;
    try {
      document = JSON.parse(contents) as unknown;
    } catch {
      throw new CliError(
        "CONFIG_INVALID",
        "the selected config is not valid JSON",
      );
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
        "the selected config does not match the profile schema",
      );
    const profiles = document.profiles;
    const names = Object.keys(profiles);
    const name =
      selected ??
      document.defaultProfile ??
      (names.length === 1 ? names[0] : undefined);
    if (typeof name !== "string")
      throw new CliError(
        "PROFILE_AMBIGUOUS",
        "select a profile with --profile or FALCON_AXI_PROFILE",
      );
    if (!Object.hasOwn(profiles, name))
      throw new CliError(
        "PROFILE_NOT_FOUND",
        "selected profile does not exist",
      );
    const validate = new Ajv2020({ strict: false }).compile(schema);
    for (const entry of Object.values(profiles))
      if (!validate(entry))
        throw new CliError(
          "CONFIG_INVALID",
          "a credential profile does not match the schema",
        );
    const settings = profiles[name] as Record<string, unknown>;
    const ref = settings.clientSecret ?? { env: "FALCON_AXI_CLIENT_SECRET" };
    if (!object(ref))
      throw new CliError("CONFIG_INVALID", "invalid clientSecret SecretRef");
    let secret: string | undefined;
    if (typeof ref.env === "string") secret = env[ref.env];
    else if (typeof ref.file === "string" && isAbsolute(ref.file))
      secret = (await readPrivate(ref.file, true))?.trimEnd();
    if (!secret)
      throw new CliError(
        "AUTH_REQUIRED",
        "clientSecret SecretRef resolved to no value",
      );
    credential = {
      clientId: settings.clientId as string,
      clientSecret: secret,
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
