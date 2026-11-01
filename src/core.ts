export class CliError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly help: readonly string[] = [],
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
  get exitCode(): number {
    return ["VALIDATION_ERROR", "FQL_INVALID", "CONFIG_INVALID"].includes(
      this.code,
    )
      ? 2
      : 1;
  }
}

export function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Preserve numeric lexemes outside Number's exact integer domain before rounding.
export function parseResponse(text: string): unknown {
  return JSON.parse(
    text,
    (_key: string, value: unknown, context?: { source?: string }) => {
      if (
        typeof value !== "number" ||
        Math.abs(value) <= Number.MAX_SAFE_INTEGER ||
        !context?.source
      )
        return value;
      return /^-?\d+$/.test(context.source)
        ? BigInt(context.source)
        : context.source;
    },
  ) as unknown;
}
