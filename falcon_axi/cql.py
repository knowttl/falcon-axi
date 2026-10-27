"""Conservative CQL structure validation, without function or schema checks."""

from falcon_axi.core import CliError
from falcon_axi.render import redact

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
        line_end = query.find("\n", offset)
        excerpt = str(redact(query[: len(query) if line_end < 0 else line_end])).rsplit("\n", 1)[-1]
        caret_column = len(str(redact(query[:offset])).rsplit("\n", 1)[-1])
        raise CliError(
            "VALIDATION_ERROR",
            f"CQL syntax error at line {line}, column {column}: {message}",
            [
                f"{excerpt}\n{' ' * caret_column}^",
                "CQL is pipe-based and is neither FQL nor SQL: `#event_simpleName=ProcessRollup2 | head(5)`",
            ],
            details={"diagnostics": [{"line": line, "column": column, "message": message, "expected": expected}]},
        )

    stack: list[tuple[str, int, int | None]] = []
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
        if query.startswith("//", i):
            end = query.find("\n", i)
            i = len(query) if end < 0 else end
            continue
        if assignment is not None:
            if char in "|)]};,":
                fail(assignment, "':=' has no right-hand side", "an expression after ':='")
            assignment = None
        regex = char == "/"
        if regex and previous not in ("", "=", "(", ",", "|", "[", "{", ";", "=>", "AND", "OR", "NOT"):
            return
        if char == '"' or regex:
            delimiter = char
            end = i + 1
            while end < len(query) and query[end] != delimiter:
                if query[end] in "\r\n":
                    break
                end += 2 if query[end] == "\\" and end + 1 < len(query) and query[end + 1] not in "\r\n" else 1
            if end >= len(query) or query[end] != delimiter:
                fail(i, "unterminated regex literal" if regex else "unterminated string", delimiter)
            i = end + 1
            while regex and i < len(query) and query[i] in "dim":
                i += 1
            stage_has_content = True
            previous = "value"
            continue
        if char in _OPEN:
            stack.append((char, i, last_pipe))
            stage_has_content = False
            last_pipe = None
            previous = char
            i += 1
            continue
        elif char in ")]}":
            if not stack or _OPEN[stack[-1][0]] != char:
                fail(i, f"unexpected '{char}'", _OPEN[stack[-1][0]] if stack else None)
            if not stage_has_content and last_pipe is not None:
                fail(last_pipe, "query ends with an empty pipeline stage", "a function after the last '|'")
            _, _, last_pipe = stack.pop()
        elif char == "|":
            if not stage_has_content:
                fail(i, "empty pipeline stage", "a filter or function before '|'")
            stage_has_content = False
            last_pipe = i
            previous = char
            i += 1
            continue
        elif char in ";," or query.startswith("=>", i):
            if not stage_has_content and last_pipe is not None:
                fail(last_pipe, "query ends with an empty pipeline stage", "a function after the last '|'")
            stage_has_content = False
            last_pipe = None
            previous = "=>" if query.startswith("=>", i) else char
            i += len(previous)
            continue
        elif query.startswith(":=", i):
            assignment = i
            previous = "="
            i += 2
            continue
        elif char not in "=!<>/":
            end = i + 1
            while end < len(query) and not query[end].isspace() and query[end] not in '()[]{}"=,!<>;|':
                if query.startswith(":=", end):
                    break
                end += 1
            previous = query[i:end]
            stage_has_content = True
            i = end
            continue
        stage_has_content = True
        previous = char
        i += 1
    if assignment is not None:
        fail(assignment, "':=' has no right-hand side", "an expression after ':='")
    if stack:
        opener, offset, _ = stack[-1]
        fail(offset, f"'{opener}' is never closed", _OPEN[opener])
    if not stage_has_content and last_pipe is not None:
        fail(last_pipe, "query ends with an empty pipeline stage", "a function after the last '|'")
