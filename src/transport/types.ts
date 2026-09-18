import type { OperationId } from "./operations.js";

export type FalconResponse = Readonly<{
  status: number;
  headers: Readonly<Record<string, string>>;
  body: unknown;
}>;

export type RequestArgs = Readonly<{
  baseUrl: string;
  token: string;
  query?: Readonly<Record<string, string | number>>;
  body?: unknown;
  allowUnknownOrigin?: boolean;
}>;

export type OAuthTokenArgs = Readonly<{
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  memberCid?: string;
  allowUnknownOrigin?: boolean;
}>;

/**
 * The sealed transport surface (docs/design/v1.md §3.3).
 * It exposes no raw URL, method, path, prepared request, or network primitive, and the tenancy
 * selection lives on the token mint alone because Falcon binds a member CID at that point (§6.5).
 */
export interface Transport {
  request(id: OperationId, args: RequestArgs): Promise<FalconResponse>;
  requestOAuthToken(args: OAuthTokenArgs): Promise<FalconResponse>;
}
