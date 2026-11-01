import { createHmac, timingSafeEqual } from "node:crypto";
import { CliError, object } from "./core.js";
import type { Credential } from "./credentials.js";

export class Cursor {
  constructor(
    private readonly credential: Credential,
    private readonly origin: string,
    private readonly operation: string,
    private readonly query: string | undefined,
    private readonly model: "offset" | "token" = "offset",
    private readonly sort: string | null = null,
  ) {}
  private fingerprint(position: string | number): string {
    return createHmac("sha256", this.credential.clientSecret)
      .update(
        JSON.stringify({
          client_id: this.credential.clientId,
          member_cid: this.credential.memberCid ?? null,
          model: this.model,
          operation: this.operation,
          origin: this.origin,
          position,
          query: this.query ?? null,
          sort: this.sort,
        }),
      )
      .digest("hex");
  }
  encode(position: string | number): string {
    return Buffer.from(
      JSON.stringify({
        operation: this.operation,
        model: this.model,
        position,
        fingerprint: this.fingerprint(position),
      }),
    ).toString("base64url");
  }
  decode(token: string): string | number {
    try {
      const payload: unknown = JSON.parse(
        Buffer.from(token, "base64url").toString("utf8"),
      );
      if (
        !object(payload) ||
        payload.operation !== this.operation ||
        payload.model !== this.model ||
        (this.model === "offset"
          ? !Number.isSafeInteger(payload.position) ||
            (payload.position as number) < 0
          : typeof payload.position !== "string" || !payload.position) ||
        typeof payload.fingerprint !== "string" ||
        !/^[a-f0-9]{64}$/.test(payload.fingerprint) ||
        !timingSafeEqual(
          Buffer.from(payload.fingerprint),
          Buffer.from(this.fingerprint(payload.position as string | number)),
        )
      )
        throw new Error("cursor");
      return payload.position as string | number;
    } catch {
      throw new CliError(
        "VALIDATION_ERROR",
        "this cursor does not continue the current query",
        [
          "A cursor is bound to its operation, filter, sort, region, tenant selection, and credential",
          "Re-run the command without `--cursor` to start a fresh read",
        ],
      );
    }
  }
}
