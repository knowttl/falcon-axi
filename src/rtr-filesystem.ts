import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { CliError } from "./core.js";
import checksums from "../native/checksums.json" with { type: "json" };

interface Adapter {
  open(path: string, locked: boolean): object;
  append(handle: object, data: Buffer): void;
  close(handle: object): void;
}

let adapter: Adapter | undefined;

function load(): Adapter {
  if (process.platform !== "linux" || process.arch !== "x64")
    throw new CliError(
      "CONFIG_INSECURE",
      "RTR execution requires a supported POSIX controller",
    );
  if (!adapter) {
    const binary = new URL(
      "../../native/prebuilds/linux-x64.node",
      import.meta.url,
    );
    try {
      const digest = createHash("sha256")
        .update(readFileSync(binary))
        .digest("hex");
      if (digest !== checksums["linux-x64.node"]) throw new Error("integrity");
      adapter = createRequire(import.meta.url)(
        fileURLToPath(binary),
      ) as Adapter;
    } catch {
      throw new CliError(
        "CONFIG_INSECURE",
        "RTR filesystem adapter is unavailable or failed integrity checks",
      );
    }
  }
  return adapter;
}

// Only the native handle retains authority; no caller-supplied descriptor crosses this seam.
export function openRetainedFile(
  path: string,
  locked = false,
): {
  append(data: Buffer): void;
  close(): void;
} {
  const native = load();
  let handle: object;
  try {
    handle = native.open(path, locked);
  } catch (error) {
    if ((error as { code?: unknown }).code === "READ_ONLY_VIOLATION")
      throw new CliError(
        "READ_ONLY_VIOLATION",
        "Another local RTR run is active for this host",
      );
    throw new CliError("CONFIG_INSECURE", "RTR filesystem operation refused");
  }
  return {
    append: (data) => {
      try {
        native.append(handle, data);
      } catch {
        throw new CliError(
          "CONFIG_INSECURE",
          "RTR journal could not be durably written",
        );
      }
    },
    close: () => native.close(handle),
  };
}
