import { CliError, object } from "./core.js";
import { redactText } from "./render.js";
import type { Response } from "./transport/https.js";

// Describe successful malformed envelopes without retaining upstream values.
export function malformed(
  response: Response,
  message: string,
  help: readonly string[] = [],
): never {
  const shape: { path: string; type: string; count?: number }[] = [];
  let truncated = false;
  let characters = 0;
  const visit = (value: unknown, path: string, depth: number): void => {
    if (
      shape.length >= 64 ||
      path.length > 256 ||
      characters + path.length > 4096
    ) {
      truncated = true;
      return;
    }
    characters += path.length;
    const type =
      value === null
        ? "null"
        : Array.isArray(value)
          ? "array"
          : typeof value === "bigint"
            ? "number"
            : typeof value;
    shape.push({
      path,
      type,
      ...(Array.isArray(value) ? { count: value.length } : {}),
    });
    if (Array.isArray(value) && value.length) {
      if (depth >= 4) truncated = true;
      else visit(value[0], `${path}[*]`, depth + 1);
    } else if (object(value))
      for (const [key, child] of Object.entries(value)) {
        if (depth >= 4 || shape.length >= 64) {
          truncated = true;
          break;
        }
        const segment =
          /^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(key) &&
          !/^(?:[a-f0-9]{32}|[a-f0-9]{8}(?:[-_][a-f0-9]{4}){3}[-_][a-f0-9]{12})$/i.test(
            key,
          )
            ? redactText(key)
            : "<key>";
        visit(child, `${path}[${JSON.stringify(segment)}]`, depth + 1);
        if (truncated) break;
      }
  };
  visit(response.body, "$", 0);
  const media = response.headers["content-type"]?.split(";", 1)[0]?.trim();
  throw new CliError("UPSTREAM_ERROR", message, help, {
    status:
      Number.isInteger(response.status) &&
      response.status >= 100 &&
      response.status <= 599
        ? response.status
        : null,
    contentType:
      media &&
      media.length <= 128 &&
      /^[a-z0-9!#$&^_.+\-]+\/[a-z0-9!#$&^_.+\-]+$/i.test(media)
        ? redactText(media)
        : null,
    shape,
    shapeTruncated: truncated,
  });
}
