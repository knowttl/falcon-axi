export const RAW_RESPONSE_LIMIT = 4 * 1024 * 1024;

export function routeProblem(method: string, path: string): string | undefined {
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method))
    return "the method must be GET, POST, PUT, PATCH or DELETE";
  if (
    !/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9a-fA-F]{2})*$/.test(path) ||
    /(?:^|\/)\.{1,2}(?:\/|$)|\/\//.test(path.replace(/%2e/gi, "."))
  )
    return "the path must be an absolute URI path without dot segments or repeated slashes";
  return undefined;
}
