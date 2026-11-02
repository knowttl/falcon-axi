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

// Preserve numeric lexemes outside Number's exact integer domain, judged from the
// original text because JSON.parse has already rounded the value it hands us.
export function parseResponse(text: string): unknown {
  return JSON.parse(
    text,
    (_key: string, value: unknown, context?: { source?: string }) => {
      if (typeof value !== "number" || !context?.source) return value;
      const { source } = context;
      if (/^-?\d+$/.test(source)) {
        const integer = BigInt(source);
        return (integer < 0n ? -integer : integer) >
          BigInt(Number.MAX_SAFE_INTEGER)
          ? integer
          : value;
      }
      return Math.abs(value) >= Number.MAX_SAFE_INTEGER ? source : value;
    },
  ) as unknown;
}
