import { readFileSync } from "node:fs";
import type { OperationId } from "../../src/transport/operations.js";
import type { FalconResponse, OAuthTokenArgs, RequestArgs, Transport } from "../../src/transport/types.js";

export const FIXTURES = new URL("../../../test/fixtures/", import.meta.url);

/** Loads a wholly synthetic fixture (docs/design/v1.md §14.4). */
export function fixture(relativePath: string): FalconResponse {
  const parsed = JSON.parse(readFileSync(new URL(relativePath, FIXTURES), "utf8")) as { response: FalconResponse };
  return parsed.response;
}

export function response(status: number, body: unknown, headers: Record<string, string> = {}): FalconResponse {
  return { status, headers, body };
}

export type RecordedRequest =
  | Readonly<{ kind: "operation"; id: OperationId; args: RequestArgs }>
  | Readonly<{ kind: "oauth"; args: OAuthTokenArgs }>;

export type OperationResponder = (id: OperationId, args: RequestArgs) => FalconResponse | undefined;

/**
 * The offline transport (§14.2).
 * It preserves the sealed entry-point shape and serves fixtures without any network access.
 * It is never reachable from the shipped binary: no flag, environment variable, or config key
 * selects it, and it lives only in the test tree.
 */
export class RecordedTransport implements Transport {
  readonly requests: RecordedRequest[] = [];

  constructor(
    private readonly responders: readonly OperationResponder[],
    private readonly oauth: FalconResponse[] = [fixture("oauth2/token-success.json")],
  ) {}

  async request(id: OperationId, args: RequestArgs): Promise<FalconResponse> {
    this.requests.push({ kind: "operation", id, args });
    for (const responder of this.responders) {
      const answer = responder(id, args);
      if (answer) return answer;
    }
    throw new Error(`no recorded response for ${id}`);
  }

  async requestOAuthToken(args: OAuthTokenArgs): Promise<FalconResponse> {
    this.requests.push({ kind: "oauth", args });
    const next = this.oauth.length > 1 ? this.oauth.shift() : this.oauth[0];
    if (!next) throw new Error("no recorded token response");
    return next;
  }

  operationRequests(id: OperationId): RequestArgs[] {
    return this.requests.filter(entry => entry.kind === "operation" && entry.id === id).map(entry => (entry as { args: RequestArgs }).args);
  }
}

export function serve(id: OperationId, answer: FalconResponse | ((args: RequestArgs) => FalconResponse)): OperationResponder {
  return (requested, args) => (requested === id ? (typeof answer === "function" ? answer(args) : answer) : undefined);
}

export const CREDENTIAL_ENV = Object.freeze({
  FALCON_CLIENT_ID: "synthetic-client-id",
  FALCON_CLIENT_SECRET: "synthetic-client-secret",
  FALCON_AXI_CREDENTIALS_FILE: "/nonexistent/falcon-axi/credentials",
});
