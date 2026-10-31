import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import type { IncomingMessage } from "node:http";

// Test-owned connection injection, excluded from the package. The logical hostname,
// SNI, hostname verification, authority checks and TLS trust remain production-owned.
const original = https.request;
https.request = ((
  options: https.RequestOptions,
  callback: (response: IncomingMessage) => void,
) => {
  if (
    !options ||
    typeof options !== "object" ||
    typeof options.hostname !== "string" ||
    !options.hostname.endsWith(".crowdstrike.com")
  )
    throw new Error("Unmatched offline traffic");
  return original(
    {
      ...options,
      headers: { ...options.headers, host: options.hostname },
      port: Number(process.env.S01_DELIVERY_PORT),
      servername: options.hostname,
      lookup: (_host, _options, done) =>
        done(null, [{ address: "127.0.0.1", family: 4 }]),
    },
    callback,
  );
}) as typeof https.request;
syncBuiltinESMExports();
