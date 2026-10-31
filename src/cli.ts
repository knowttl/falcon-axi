import { CliError } from "./core.js";
import { resolveCredential } from "./credentials.js";
import { authenticate } from "./auth.js";
import { resolveOrigin } from "./origin.js";
import { listDetections } from "./detection.js";
import { render, registerSecret } from "./render.js";
import { valueFlags, boolFlags, commandNames } from "./metadata.js";
export async function main(argv: string[]): Promise<number> {
  const controller = new AbortController();
  const cancel = (): void => controller.abort();
  process.once("SIGTERM", cancel);
  process.once("SIGINT", cancel);
  try {
    const searchSubset =
      argv[0] === "search" &&
      argv[1] === "status" &&
      argv[2] === "synthetic-job";
    const words = argv.slice(
      0,
      argv[0]?.startsWith("-") ? 0 : searchSubset ? 3 : 2,
    );
    const flags = new Map<string, string>();
    const allowed = searchSubset ? [...valueFlags, "--wait"] : valueFlags;
    for (let index = words.length; index < argv.length; index++) {
      const arg = argv[index]!;
      const [key, ...inline] = arg.split("=");
      if (boolFlags.includes(key!)) {
        if (inline.length)
          throw new CliError(
            "VALIDATION_ERROR",
            `${key} does not accept a value`,
          );
        flags.set(key!, "true");
      } else if (allowed.includes(key!)) {
        const value = inline.length ? inline.join("=") : argv[++index];
        if (value === undefined || value.startsWith("--"))
          throw new CliError("VALIDATION_ERROR", `${key} requires a value`);
        flags.set(key!, value);
      } else
        throw new CliError("VALIDATION_ERROR", `unknown flag ${key}`, [
          `valid flags for detection list: ${[...valueFlags, ...boolFlags].join(", ")}`,
        ]);
    }
    if (argv.includes("--help") || !argv.length) {
      process.stdout.write(
        render(
          {
            description: "Read Falcon detections (TypeScript S01 candidate)",
            command: "falcon-axi detection list",
            flags:
              "--limit 50 (1-10000), --cursor <token>, --filter <fql>, --config <path>, --profile <name>, --region <region>, --member-cid <cid>, --no-member-cid, --allow-unknown-origin, --help",
          },
          [
            "falcon-axi detection list --limit 2",
            "falcon-axi detection list --filter \"severity_name:'High'\"",
          ],
        ),
      );
      return 0;
    }
    if (!searchSubset && !commandNames.includes(words.join(" ")))
      throw new CliError("VALIDATION_ERROR", "unknown command", [
        "Run `falcon-axi detection list --help`",
      ]);
    const limit = Number(flags.get("--limit") ?? "50");
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000)
      throw new CliError(
        "VALIDATION_ERROR",
        "--limit must be an integer from 1 to 10000",
      );
    const wait = flags.get("--wait");
    if (searchSubset && wait !== "1")
      throw new CliError(
        "VALIDATION_ERROR",
        "the S01 token-budget subset requires --wait 1",
      );
    const signal = searchSubset
      ? AbortSignal.any([controller.signal, AbortSignal.timeout(1000)])
      : controller.signal;
    const credential = await resolveCredential(
      flags.get("--config"),
      flags.get("--profile"),
    );
    if (flags.has("--no-member-cid")) delete credential.memberCid;
    else if (flags.has("--member-cid")) {
      credential.memberCid = flags.get("--member-cid")!;
      registerSecret(credential.memberCid);
    }
    const allowUnknown = flags.has("--allow-unknown-origin");
    const base = resolveOrigin(
      flags.get("--region") ?? credential.region,
      allowUnknown,
    );
    const session = await authenticate(credential, base, allowUnknown, signal);
    if (searchSubset)
      throw new CliError(
        "VALIDATION_ERROR",
        "search status is not delivered in S01",
      );
    const result = await listDetections(
      credential,
      session,
      limit,
      flags.get("--filter"),
      flags.get("--cursor"),
      allowUnknown,
      signal,
    );
    process.stdout.write(render(result.value, result.help));
    return 0;
  } catch (error) {
    const safe =
      error instanceof CliError
        ? error
        : new CliError(
            "UNKNOWN",
            "falcon-axi could not complete this command",
            ["Retry shortly"],
          );
    process.stdout.write(
      render(
        { error: { code: safe.code, message: safe.message, ...safe.details } },
        safe.help,
      ),
    );
    return safe.exitCode;
  } finally {
    process.removeListener("SIGTERM", cancel);
    process.removeListener("SIGINT", cancel);
  }
}
