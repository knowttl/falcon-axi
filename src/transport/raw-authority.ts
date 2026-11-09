export const RAW_RESPONSE_LIMIT = 4 * 1024 * 1024;

const credentialAndAccessRoute =
  /(?:^|\/)(?:oauth2|user-management|users?|user-roles|roles?|permissions?|installation-tokens|api-clients?|(?:[a-z0-9._~]+-)*(?:keys?|tokens?|secrets?|credentials?|passwords?))(?:\/|$)/i;
const writeOnlyRoute =
  /(?:^|\/)(?:mssp|real-time-response(?:-admin)?)(?:\/|$)/i;

export function routeProblem(method: string, path: string): string | undefined {
  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method))
    return "the method must be GET, POST, PUT, PATCH or DELETE";
  if (
    path.length > 256 ||
    !/^\/[A-Za-z0-9._~/-]+$/.test(path) ||
    /(?:^|\/)\.{1,2}(?:\/|$)|\/\//.test(path)
  )
    return "the path must be an absolute Falcon API path of letters, digits, dots, dashes, underscores, tildes and slashes, without dot segments";
  if (credentialAndAccessRoute.test(path))
    return "credential, token, user, role and permission routes are blocked";
  if (method !== "GET" && writeOnlyRoute.test(path))
    return "Flight Control and Real Time Response routes are blocked for writes; use `falcon-axi rtr run` for guarded RTR";
  return undefined;
}
