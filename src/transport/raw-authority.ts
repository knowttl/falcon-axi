export const RAW_RESPONSE_LIMIT = 4 * 1024 * 1024;

export function routeProblem(method: string, path: string): string | undefined {
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method))
    return "the method must be GET, POST, PUT, PATCH or DELETE";
  if (
    path.length > 256 ||
    !/^\/[A-Za-z0-9._~/-]+$/.test(path) ||
    /(?:^|\/)\.{1,2}(?:\/|$)|\/\//.test(path)
  )
    return "the path must be an absolute Falcon API path of letters, digits, dots, dashes, underscores, tildes and slashes, without dot segments";
  return undefined;
}
