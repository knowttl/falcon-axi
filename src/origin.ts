import { CliError } from "./core.js";

export const REGIONS: Readonly<Record<string, string>> = Object.freeze({
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
});
export function origin(value: string, allowUnknown = false): string {
  const refuse = (component: string): never => {
    throw new CliError(
      "ORIGIN_NOT_ALLOWED",
      "the resolved Falcon base URL is not a trusted destination",
      [
        "Use a documented region with `--region` (us-1 us-2 eu-1 us-gov-1)",
        "Allowed hosts are the documented Falcon clouds and subdomains of crowdstrike.com or gcw.crowdstrike.com",
        "Pass `--allow-unknown-origin` in the same invocation to reach a deliberately selected unknown Falcon cloud",
      ],
      { invalid_component: component },
    );
  };
  // Check lexical input before WHATWG normalization erases ports, dot segments or controls.
  const match = /^https:\/\/([^/?#]+)(\/[^?#]*)?(\?[^#]*)?(#.*)?$/.exec(value);
  if (!match || /[\s\\\u0000-\u001f\u007f]/u.test(value)) refuse("scheme");
  const authority = match![1]!;
  if (authority.includes("@")) refuse("userinfo");
  if (authority.includes(":")) refuse("port");
  if (match![2] && match![2] !== "/") refuse("path");
  if (match![3]) refuse("query");
  if (match![4]) refuse("fragment");
  const host = authority.toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) || host.includes(".."))
    refuse("host");
  if (
    !allowUnknown &&
    host !== "crowdstrike.com" &&
    !host.endsWith(".crowdstrike.com")
  )
    refuse("host");
  return `https://${host}`;
}
export function resolveOrigin(region = "us-1", allowUnknown = false): string {
  if (!Object.hasOwn(REGIONS, region) && !region.includes("://"))
    throw new CliError("VALIDATION_ERROR", `unknown region ${region}`, [
      `valid regions: ${Object.keys(REGIONS).join(", ")}`,
      "Or pass a verified full Falcon base URL with `--region <url> --allow-unknown-origin`",
    ]);
  return origin(
    Object.hasOwn(REGIONS, region) ? REGIONS[region]! : region,
    allowUnknown,
  );
}
