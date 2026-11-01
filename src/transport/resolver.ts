import { spawn } from "node:child_process";
import { isIP } from "node:net";
import type { LookupFunction } from "node:net";
import type { LookupAddress } from "node:dns";
import { fileURLToPath } from "node:url";

const invocations = new WeakMap<AbortSignal, Map<string, LookupAddress[]>>();

// DNS alone runs out of process: Node joins pending getaddrinfo work at exit.
export function createLookup(invocation: AbortSignal, budget: AbortSignal) {
  let cache = invocations.get(invocation);
  if (!cache) invocations.set(invocation, (cache = new Map()));
  const controller = new AbortController();
  const signal = AbortSignal.any([budget, controller.signal]);
  const pending = new Set<Promise<LookupAddress[]>>();
  const lookup: LookupFunction = (hostname, options, callback) => {
    const key = JSON.stringify([
      hostname,
      options.family ?? 0,
      options.hints ?? 0,
    ]);
    const cached = cache.get(key);
    const result = cached
      ? Promise.resolve(cached)
      : new Promise<LookupAddress[]>((resolve, reject) => {
          signal.throwIfAborted();
          const child = spawn(
            process.execPath,
            [
              fileURLToPath(new URL("./dns-worker.js", import.meta.url)),
              hostname,
              String(options.family ?? 0),
              String(options.hints ?? 0),
            ],
            {
              // No credential, preload, or inherited Node options reach this child.
              env: process.env.SystemRoot
                ? { SystemRoot: process.env.SystemRoot }
                : {},
              stdio: ["ignore", "pipe", "ignore"],
            },
          );
          let output = "";
          const abort = (): void => {
            child.kill("SIGKILL");
          };
          signal.addEventListener("abort", abort, { once: true });
          child.stdout.on("data", (chunk: Buffer) => {
            output += chunk.toString();
            if (output.length > 65536) abort();
          });
          child.once("error", reject);
          child.once("close", (code) => {
            signal.removeEventListener("abort", abort);
            if (code !== 0 || signal.aborted || output.length > 65536) {
              reject(new Error("System name resolution failed"));
              return;
            }
            try {
              const addresses: unknown = JSON.parse(output);
              if (
                !Array.isArray(addresses) ||
                !addresses.length ||
                addresses.some(
                  (address: LookupAddress) =>
                    !address ||
                    ![4, 6].includes(address.family) ||
                    typeof address.address !== "string" ||
                    isIP(address.address) !== address.family,
                )
              )
                throw new Error("Invalid resolver result");
              cache.set(key, addresses as LookupAddress[]);
              resolve(addresses as LookupAddress[]);
            } catch (error) {
              reject(error);
            }
          });
        });
    pending.add(result);
    void result.then(
      (addresses) => {
        pending.delete(result);
        if (options.all) callback(null, addresses);
        else callback(null, addresses[0]!.address, addresses[0]!.family);
      },
      () => {
        pending.delete(result);
        callback(new Error("System name resolution failed"), "");
      },
    );
  };
  return {
    lookup,
    async close(): Promise<void> {
      controller.abort();
      await Promise.allSettled(pending);
    },
  };
}
