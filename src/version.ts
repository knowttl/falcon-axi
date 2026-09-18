/** Kept in step with package.json by an offline test. */
export const VERSION = "0.1.0";

export function userAgent(): string {
  return `falcon-axi/${VERSION} (Node/${process.versions.node}; ${process.platform})`;
}
