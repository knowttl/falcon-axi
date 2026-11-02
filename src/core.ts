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
      const [mantissa, exponent = "0"] = source.replace(/^-/, "").split(/[eE]/);
      const [whole, fraction = ""] = mantissa!.split(".");
      const coefficient = whole! + fraction;
      const significant = coefficient.replace(/^0+/, "");
      if (!significant) return value;
      const position =
        BigInt(whole!.length - (coefficient.length - significant.length)) +
        BigInt(exponent);
      const digits = significant.replace(/0+$/, "");
      return position > 16n ||
        (position === 16n && digits.padEnd(16, "0") > "9007199254740991")
        ? source
        : value;
    },
  ) as unknown;
}
