"""Conservative CQL structure validation, without function or schema checks."""

from falcon_axi.core import CliError

_OPEN = {"(": ")", "[": "]", "{": "}"}


def validate_query(query: str) -> None:
    """Reject certain structural errors before authentication; ambiguous syntax passes."""
    if not query.strip():
        raise CliError(
            "VALIDATION_ERROR",
            "search start requires a CQL query",
            [
                "CQL is pipe-based: a filter, then commands, for example `#event_simpleName=ProcessRollup2 | head(5)`",
                "Run `falcon-axi search start --help` for the query shape",
            ],
        )

    def fail(offset: int, message: str, expected: str | None = None) -> None:
        line_start = query.rfind("\n", 0, offset) + 1
        line = query.count("\n", 0, offset) + 1
        column = offset - line_start + 1
        excerpt = query[line_start:].split("\n", 1)[0]
        raise CliError(
            "VALIDATION_ERROR",
            f"CQL syntax error at line {line}, column {column}: {message}",
            [
                f"{excerpt}\n{' ' * (column - 1)}^",
                "CQL is pipe-based and is neither FQL nor SQL: `#event_simpleName=ProcessRollup2 | head(5)`",
            ],
            details={"diagnostics": [{"line": line, "column": column, "message": message, "expected": expected}]},
        )

    stack: list[tuple[str, int]] = []
    stage_has_content = False
    last_pipe: int | None = None
    assignment: int | None = None
    previous = ""
    i = 0
    while i < len(query):
        char = query[i]
        if char.isspace():
            i += 1
            continue
        if query.startswith("/*", i):
            end = query.find("*/", i + 2)
            if end < 0:
                fail(i, "unterminated block comment", "*/")
            i = end + 2
            continue
        if query.startswith("//", i) and (i == 0 or query[i - 1].isspace()):
            end = query.find("\n", i)
            i = len(query) if end < 0 else end
            continue
        if assignment is not None:
            if char in "|)]};":
                fail(assignment, "':=' has no right-hand side", "an expression after ':='")
            assignment = None
        # Slash also means division or free text. Only treat it as regex where a value is expected.
        regex = char == "/" and previous in ("", "=", "(", ",", "|", "[", "{")
        if char == '"' or regex:
            delimiter = char
            end = i + 1
            while end < len(query) and query[end] != delimiter:
                if regex and query[end] == "\n":
                    break
                end += 2 if query[end] == "\\" else 1
            if end >= len(query) or query[end] != delimiter:
                fail(i, "unterminated regex literal" if regex else "unterminated string", delimiter)
            i = end + 1
            stage_has_content = True
            previous = "value"
            continue
        if char in _OPEN:
            stack.append((char, i))
        elif char in ")]}":
            if not stack or _OPEN[stack[-1][0]] != char:
                fail(i, f"unexpected '{char}'", _OPEN[stack[-1][0]] if stack else None)
            stack.pop()
        elif char == "|" and not stack:
            if not stage_has_content:
                fail(i, "empty pipeline stage", "a filter or function before '|'")
            stage_has_content = False
            last_pipe = i
            previous = char
            i += 1
            continue
        elif query.startswith(":=", i):
            assignment = i
            previous = "="
            i += 2
            continue
        stage_has_content = True
        previous = char
        i += 1
    if assignment is not None:
        fail(assignment, "':=' has no right-hand side", "an expression after ':='")
    if stack:
        opener, offset = stack[-1]
        fail(offset, f"'{opener}' is never closed", _OPEN[opener])
    if not stage_has_content and last_pipe is not None:
        fail(last_pipe, "query ends with an empty pipeline stage", "a function after the last '|'")
