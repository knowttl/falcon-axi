import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import type { IncomingMessage } from "node:http";

// Test-owned connection injection, excluded from the package. The logical hostname,
// SNI, hostname verification, authority checks and TLS trust remain production-owned.
const original = https.request;
const timeout = AbortSignal.timeout;
if (process.env.S11_SIZE_TIMEOUT === "1")
  AbortSignal.timeout = (milliseconds: number): AbortSignal =>
    timeout(milliseconds === 30000 ? 200 : milliseconds);
if (process.env.S11_EXECUTION_TIMEOUT === "1")
  AbortSignal.timeout = (milliseconds: number): AbortSignal =>
    timeout(milliseconds === 50000 ? 1000 : milliseconds);
https.request = ((
  options: https.RequestOptions,
  callback: (response: IncomingMessage) => void,
) => {
  if (
    !options ||
    typeof options !== "object" ||
    typeof options.hostname !== "string" ||
    (!options.hostname.endsWith(".crowdstrike.com") &&
      !["synthetic-cloud.example", "synthetic.invalid"].includes(
        options.hostname,
      ))
  )
    throw new Error("Unmatched offline traffic");
  const result = original(
    {
      ...options,
      headers: { ...options.headers, host: options.hostname },
      port: Number(process.env.S01_DELIVERY_PORT),
      ...(process.env.S01_DELIVERY_SOCKET
        ? { socketPath: process.env.S01_DELIVERY_SOCKET }
        : {}),
      servername: options.hostname,
      lookup: (_host, lookupOptions, done) =>
        options.lookup!("localhost", lookupOptions, done),
    },
    (response) => {
      if (
        process.env.S11_READ_ONLY_AFTER_INIT === "1" &&
        options.method === "POST" &&
        options.path === "/real-time-response/entities/sessions/v1"
      )
        response.once("end", () => {
          process.env.FALCON_AXI_READ_ONLY = "true";
        });
      callback(response);
    },
  );
  return result;
}) as typeof https.request;
syncBuiltinESMExports();
