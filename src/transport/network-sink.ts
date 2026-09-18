import { CliError } from "../core.js";
import type { FalconResponse } from "./types.js";

/**
 * The sole network sink (docs/design/v1.md §3.3 property 6).
 * This file is the only place allowed to reference a network API, and `sendPermittedRequest` is the
 * only function in it allowed to do so. Both sealed entry points mint a permit after their registry
 * or OAuth checks pass; a prepared request without a valid permit is refused before network access.
 */
const PERMIT = Symbol("falcon-axi transport permit");

export type Permit = Readonly<{ [PERMIT]: true }>;

export type PreparedRequest = Readonly<{
  url: string;
  method: "GET" | "POST";
  headers: Readonly<Record<string, string>>;
  body?: string;
}>;

export function mintPermit(): Permit {
  return Object.freeze({ [PERMIT]: true } as const);
}

const TLS_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

function causeCode(error: unknown): string {
  const cause = (error as { cause?: { code?: unknown } } | undefined)?.cause;
  return typeof cause?.code === "string" ? cause.code : "";
}

export async function sendPermittedRequest(request: PreparedRequest, permit: Permit): Promise<FalconResponse> {
  if (!permit || (permit as Record<symbol, unknown>)[PERMIT] !== true) {
    throw new CliError("READ_ONLY_VIOLATION", "a request reached the network sink without a transport permit", [
      "falcon-axi sends only requests originated by its sealed transport; report this as a bug",
    ]);
  }
  let response: Response;
  try {
    response = await fetch(request.url, {
      method: request.method,
      headers: { ...request.headers },
      body: request.body,
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    const code = causeCode(error);
    if (TLS_CODES.has(code)) {
      throw new CliError("TLS_UNTRUSTED", "the Falcon endpoint presented a certificate that could not be verified", [
        "Check the system trust store and any TLS-intercepting proxy on this host",
      ]);
    }
    throw new CliError("NETWORK_UNREACHABLE", "the Falcon endpoint could not be reached", [
      "Check network connectivity and any proxy settings for this host",
      "Run `falcon-axi auth status` once connectivity is restored",
    ]);
  }
  if (response.status >= 300 && response.status < 400) {
    throw new CliError("ORIGIN_NOT_ALLOWED", "the Falcon endpoint answered with a redirect and no credential was replayed", [
      "Supply a verified Falcon base URL with `--region <url>`",
    ], { invalid_component: "redirect" });
  }
  const text = await response.text();
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  let body: unknown = undefined;
  if (text.length) {
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
  }
  return Object.freeze({ status: response.status, headers: Object.freeze(headers), body });
}
