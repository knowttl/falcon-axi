import { CliError } from "./core.js";

// Refuse certain structural errors; ambiguous CQL remains Falcon's decision.
export function validateQuery(query: string): void {
  const open: Readonly<Record<string, string>> = {
    "(": ")",
    "[": "]",
    "{": "}",
  };
  const classes: Readonly<Record<string, string>> = {
    "(": "parenthesis",
    ")": "parenthesis",
    "[": "square bracket",
    "]": "square bracket",
    "{": "brace",
    "}": "brace",
  };
  const fail = (
    offset: number,
    message: string,
    expected: string | null = null,
  ): never => {
    const before = Array.from(query.slice(0, offset));
    const line = before.filter((char) => char === "\n").length + 1;
    const column = before.length - before.lastIndexOf("\n");
    throw new CliError(
      "VALIDATION_ERROR",
      `CQL syntax error at line ${line}, column ${column}: ${message}`,
      [
        expected
          ? `Expected ${expected}; correct the CQL structure before retrying`
          : "Remove the unexpected closing delimiter",
      ],
      { diagnostics: [{ line, column, message, expected }] },
    );
  };
  if (!query.trim())
    fail(0, "missing query", "a non-empty CQL query in --query");
  const stack: { char: string; offset: number; pipe: number | undefined }[] =
    [];
  let content = false;
  let pipe: number | undefined;
  let assignment: number | undefined;
  let previous = "";
  let i = 0;
  while (i < query.length) {
    const char = query[i]!;
    if (/\s/.test(char)) {
      i++;
      continue;
    }
    if (query.startsWith("/*", i)) {
      const end = query.indexOf("*/", i + 2);
      if (end < 0) fail(i, "unterminated block comment", "*/");
      i = end + 2;
      continue;
    }
    if (query.startsWith("//", i)) {
      const end = query.indexOf("\n", i);
      i = end < 0 ? query.length : end;
      continue;
    }
    if (assignment !== undefined) {
      if ("|)]};,".includes(char))
        fail(assignment, "dangling assignment", "an expression after ':='");
      assignment = undefined;
    }
    const regex = char === "/";
    if (
      regex &&
      ![
        "",
        "=",
        "(",
        ",",
        "|",
        "[",
        "{",
        ";",
        "=>",
        "AND",
        "OR",
        "NOT",
      ].includes(previous)
    )
      return;
    if (char === '"' || regex) {
      let end = i + 1;
      while (end < query.length && query[end] !== char) {
        if (/[\r\n]/.test(query[end]!)) break;
        end +=
          query[end] === "\\" &&
          end + 1 < query.length &&
          !/[\r\n]/.test(query[end + 1]!)
            ? 2
            : 1;
      }
      if (end >= query.length || query[end] !== char)
        fail(
          i,
          regex ? "unterminated regex literal" : "unterminated string",
          char,
        );
      i = end + 1;
      while (regex && i < query.length && "dim".includes(query[i]!)) i++;
      content = true;
      previous = "value";
      continue;
    }
    if (Object.hasOwn(open, char)) {
      stack.push({ char, offset: i, pipe });
      content = false;
      pipe = undefined;
      previous = char;
      i++;
      continue;
    } else if (")]}".includes(char)) {
      if (!stack.length || open[stack.at(-1)!.char] !== char)
        fail(
          i,
          `unexpected closing ${classes[char]}`,
          stack.length ? open[stack.at(-1)!.char]! : null,
        );
      if (!content && pipe !== undefined)
        fail(
          pipe,
          "query ends with an empty pipeline stage",
          "a function after the last '|'",
        );
      pipe = stack.pop()!.pipe;
    } else if (char === "|") {
      if (!content)
        fail(i, "empty pipeline stage", "a filter or function before '|'");
      content = false;
      pipe = i;
      previous = char;
      i++;
      continue;
    } else if (";,".includes(char) || query.startsWith("=>", i)) {
      if (!content && pipe !== undefined)
        fail(
          pipe,
          "query ends with an empty pipeline stage",
          "a function after the last '|'",
        );
      content = false;
      pipe = undefined;
      previous = query.startsWith("=>", i) ? "=>" : char;
      i += previous.length;
      continue;
    } else if (query.startsWith(":=", i)) {
      assignment = i;
      previous = "=";
      i += 2;
      continue;
    } else if (!"=!<>/".includes(char)) {
      let end = i + 1;
      while (end < query.length && !/\s|[()[\]{}"=,!<>;|]/.test(query[end]!)) {
        if (query.startsWith(":=", end)) break;
        end++;
      }
      previous = query.slice(i, end);
      content = true;
      i = end;
      continue;
    }
    content = true;
    previous = char;
    i++;
  }
  if (assignment !== undefined)
    fail(assignment, "dangling assignment", "an expression after ':='");
  if (stack.length) {
    const last = stack.at(-1)!;
    fail(last.offset, `unclosed ${classes[last.char]}`, open[last.char]!);
  }
  if (!content && pipe !== undefined)
    fail(
      pipe,
      "query ends with an empty pipeline stage",
      "a function after the last '|'",
    );
}
