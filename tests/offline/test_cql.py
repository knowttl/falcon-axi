"""Pre-auth CQL checks reject only certain structural breakage."""

import pytest
from toon_format import decode

from falcon_axi.cli import run
from falcon_axi.core import CliError
from falcon_axi.cql import validate_query
from tests.support.recorded import CREDENTIAL_ENV, RecordedTransport, fixture, serve


@pytest.mark.parametrize(
    ("query", "message", "line", "column", "expected"),
    [
        ("*\n| groupBy([ComputerName], function=count()\n| head(5)", "'(' is never closed", 2, 10, ")"),
        ('ComputerName="host1 | head(5)', "unterminated string", 1, 14, '"'),
        ('message="first\nsecond" | head(5)', "unterminated string", 1, 9, '"'),
        ('message="first\\\nsecond" | head(5)', "unterminated string", 1, 9, '"'),
        ('message="first\rsecond" | head(5)', "unterminated string", 1, 9, '"'),
        ('* | f(message="first\nsecond")', "unterminated string", 1, 15, '"'),
        ("message=/first\nsecond/ | head(5)", "unterminated regex literal", 1, 9, "/"),
        ("message=/first\\\nsecond/ | head(5)", "unterminated regex literal", 1, 9, "/"),
        ("message=/first\rsecond/ | head(5)", "unterminated regex literal", 1, 9, "/"),
        ("* | head(5) |", "query ends with an empty pipeline stage", 1, 13, "a function after the last '|'"),
        ("* || head(5)", "empty pipeline stage", 1, 4, "a filter or function before '|'"),
        ("| head(5)", "empty pipeline stage", 1, 1, "a filter or function before '|'"),
        ("* | /* ignored */ | head(5)", "empty pipeline stage", 1, 19, "a filter or function before '|'"),
        ("* | x :=\n| head(5)", "':=' has no right-hand side", 1, 7, "an expression after ':='"),
        ("* | x := /* comment */", "':=' has no right-hand side", 1, 7, "an expression after ':='"),
        ("* | f(x:=)", "':=' has no right-hand side", 1, 8, "an expression after ':='"),
        ("CommandLine=/invoke-expression | head(5)", "unterminated regex literal", 1, 13, "/"),
        ('in(field=aid, values=["a","b"))', "unexpected ')'", 1, 30, "]"),
        ("* | /* comment", "unterminated block comment", 1, 5, "*/"),
        ("* | head(5)/* unfinished", "unterminated block comment", 1, 12, "*/"),
        ("* | [count()]/* unfinished", "unterminated block comment", 1, 14, "*/"),
        ("* | case { * }/* unfinished", "unterminated block comment", 1, 15, "*/"),
        ('message="x"/* unfinished', "unterminated block comment", 1, 12, "*/"),
        ("message=/x//* unfinished", "unterminated block comment", 1, 12, "*/"),
        ("message=/x/i/* unfinished", "unterminated block comment", 1, 13, "*/"),
        ("* )", "unexpected ')'", 1, 3, None),
        ('* | x:="escaped\\"', "unterminated string", 1, 8, '"'),
    ],
)
def test_structural_errors_have_actionable_diagnostics_before_authentication(
    query: str, message: str, line: int, column: int, expected: str | None
) -> None:
    with pytest.raises(CliError) as error:
        validate_query(query)
    assert error.value.details == {"diagnostics": [{"line": line, "column": column, "message": message, "expected": expected}]}
    assert error.value.help[0] == query.split("\n")[line - 1] + "\n" + " " * (column - 1) + "^"
    recorded = RecordedTransport([])
    stdout, exit_code = run(["search", "start", "--query", query], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 2
    assert "code: VALIDATION_ERROR" in stdout
    assert f"CQL syntax error at line {line}, column {column}" in stdout
    assert "CQL is pipe-based" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "query",
    [
        "#event_simpleName=ProcessRollup2 ImageFileName=/\\\\powershell\\.exe$/i\n"
        "| groupBy([ComputerName], function=count())\n| sort(_count, limit=10)",
        '// comment\n#repo=base_sensor @timestamp>0 url="https://example.com/a"\n'
        '| in(field=aid, values=["a","b"])\n| case { x=1 | y:="one"; * | y:="other" }\n'
        '| $"my saved"()\n| t:=now()/1000 /* inline */',
        "https://www.example.com/ | head(5)",
        "* | x:=a / b | head(5)",
        "* | x:=1/2 | head(5)",
        "* | x:=/a\\/b[()|]/i | head(5)",
        "field!=/a[()|]/ | head(5)",
        "repo.name=docker/* | head(5)",
        "repo=services/OR/logs | head(5)",
        "repo=services/AND/logs | head(5)",
        "repo=services/NOT/logs | head(5)",
        "NOT /[)]/ | head(5)",
        "foo /[)]/ | head(5)",
        "foo AND /[)]/ | head(5)",
        "foo OR /[)]/ | head(5)",
        "foo NOT /[)]/ | head(5)",
        "* | field match { /[)]/ => head(5); /[(]/ => head(2) }",
        "* | case { foo | head(5); bar | head(2) }",
        "* | join(query={foo | head(5)}, field=aid)",
        '* | case { message="||" | head(5); /[|]/ | head(2) }',
        "* | case { foo /* || */ | head(5); bar // ||\n| head(2) }",
        "* | x:=a / b / c | head(5)",
        "* | x:=a / b",
        "* | x := (a / b) | field=/x/",
        "* | f(value=a / b) | field=/x/",
        "* | case { * | x := (a / b); * | head(5) } | field=/x/",
        "* | join(query={ * | x := (a / b) }, field=aid) | field=/x/",
        "* | head(5)/* ) */",
        "* | [count()]/* ] */",
        "* | case { * }/* } */",
        'message="x"/* ) */ | head(5)',
        "message=/x//* ) */ | head(5)",
        "message=/x/i/* ) */ | head(5)",
        "* | head(5)// )",
        "* | [count()]// ]",
        "* | case { * }// }",
        'message="x"// )\n| head(5)',
        "message=/x/// )\n| head(5)",
        "message=/x/i// )\n| head(5)",
        '* | f(message="first\\nsecond")',
        "* | [total:=count(), max(value)]",
        "* | f(total:=count(), limit=5)",
        '* | regex("[()|]\\"") | head(5)',
        "* /* ([ | := */ | head(5) // ([ | :=",
        "* | unknownFunction(field=unknown)",
        "SELECT * FROM events",
        'a=b | case { x=1 | y:="a"; * | y:="b" } | in(field=z, values=[1,2]) | $"my saved"() /* c */ // d',
    ],
)
def test_valid_or_ambiguous_queries_reach_the_server_unchanged(query: str) -> None:
    recorded = RecordedTransport([serve("StartSearchV1", fixture("ngsiem/start-search.json"))])
    stdout, exit_code = run(["search", "start", "--query", query], recorded, dict(CREDENTIAL_ENV))
    assert exit_code == 0, stdout
    assert recorded.operation_requests("StartSearchV1")[0].body["queryString"] == query


@pytest.mark.parametrize(
    "query",
    [
        "* | case { x=1 || head(5); * | head(5) }",
        "* | case { x=1 | /* comment */ | head(5); * | head(5) }",
        "* | case { | head(5); * | head(5) }",
        "* | case { x=1 | head(5); | head(5) }",
        "* | case { x=1 | ; * | head(5) }",
        "* | case { x=1 | head(5); * | }",
        "* | field match { a => x=1 || head(5); * => head(5) }",
        "* | field match { a => | head(5); * => head(5) }",
        "* | field match { a => head(5); * => | head(5) }",
        "* | field match { a => x=1 | ; * => head(5) }",
        "* | field match { a => head(5); * => x=1 | }",
        "* | join(query={x=1 || head(5)}, field=aid)",
        "* | join(query={ | head(5)}, field=aid)",
        "* | join(query={x=1 | }, field=aid)",
        "* | join(query={x=1 | // comment\n | head(5)}, field=aid)",
        "* | case { x=1 | join(query={y=2 || head(5)}, field=aid) }",
    ],
)
def test_nested_empty_stages_fail_before_authentication(query: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["search", "start", "--query", query], recorded, {})
    assert exit_code == 2
    assert "code: VALIDATION_ERROR" in stdout
    assert "empty pipeline stage" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "query",
    [
        "* | [total:=, count()]",
        "* | stats([total:= /* comment */ , count()])",
        "* | f(total:=, limit=5)",
        "* | f(g(total:=, limit=5))",
    ],
)
def test_comma_cannot_end_an_assignment_without_an_expression(query: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["search", "start", "--query", query], recorded, {})
    assert exit_code == 2
    assert "':=' has no right-hand side" in stdout
    assert recorded.requests == []


@pytest.mark.parametrize(
    "query",
    [
        "#repo.cid=synthetic-tenant | head(",
        "#repo.cid!=synthetic-tenant | head(",
        'cid := "synthetic-tenant" | head(',
        'test(cid == "synthetic-tenant") | head(',
        'cid like "synthetic-tenant" | head(',
        'cid="synthetic-tenant" | head(',
        'member_cid="synthetic tenant" | head(',
        'message="Bearer eyJzeW50aGV0aWM.payload.signature" | head(',
    ],
)
def test_pre_auth_excerpts_redact_sensitive_values_and_keep_the_caret_aligned(query: str) -> None:
    recorded = RecordedTransport([])
    stdout, exit_code = run(["search", "start", "--query", query], recorded, {})
    assert exit_code == 2
    assert "synthetic-tenant" not in stdout
    assert "synthetic tenant" not in stdout
    assert "eyJzeW50aGV0aWM.payload.signature" not in stdout
    excerpt, caret = decode(stdout)["help"][0].split("\n")
    assert "[redacted]" in excerpt
    assert caret == " " * excerpt.rindex("(") + "^"
    assert recorded.requests == []
