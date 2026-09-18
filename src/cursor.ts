import { createHmac, timingSafeEqual } from "node:crypto";
import { CliError } from "./core.js";
import type { OperationId } from "./transport/operations.js";

/**
 * An opaque continuation token (docs/design/v1.md §7.2).
 * It carries the operation, pagination model, and position, plus a non-reversible HMAC over the
 * invocation context. It never carries a credential value or the tenant CID, and a cursor whose
 * context changed is rejected before any request is made.
 */
export type CursorContext = Readonly<{
  operation: OperationId;
  clientId: string;
  query?: string;
  sort?: string;
  origin: string;
  memberCid?: string;
}>;

type CursorPayload = Readonly<{ operation: string; model: "offset"; position: number; fingerprint: string }>;

function fingerprint(position: number, context: CursorContext, clientSecret: string): string {
  const canonical = JSON.stringify({
    client_id: context.clientId,
    member_cid: context.memberCid ?? null,
    model: "offset",
    operation: context.operation,
    origin: context.origin,
    position,
    query: context.query ?? null,
    sort: context.sort ?? null,
  });
  return createHmac("sha256", clientSecret).update(canonical).digest("hex");
}

export function encodeCursor(position: number, context: CursorContext, clientSecret: string): string {
  const payload: CursorPayload = {
    operation: context.operation,
    model: "offset",
    position,
    fingerprint: fingerprint(position, context, clientSecret),
  };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function reject(): CliError {
  return new CliError("VALIDATION_ERROR", "this cursor does not continue the current query", [
    "A cursor is bound to its operation, filter, sort, region, tenant selection, and credential",
    "Re-run the command without `--cursor` to start a fresh read",
  ]);
}

/** Recomputes the fingerprint from the current invocation and returns the position it continues. */
export function decodeCursor(token: string, context: CursorContext, clientSecret: string): number {
  let payload: CursorPayload;
  try {
    payload = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as CursorPayload;
  } catch {
    throw reject();
  }
  if (
    !payload ||
    payload.operation !== context.operation ||
    payload.model !== "offset" ||
    !Number.isInteger(payload.position) ||
    payload.position < 0 ||
    typeof payload.fingerprint !== "string"
  ) {
    throw reject();
  }
  const expected = Buffer.from(fingerprint(payload.position, context, clientSecret), "utf8");
  const supplied = Buffer.from(payload.fingerprint, "utf8");
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw reject();
  return payload.position;
}
