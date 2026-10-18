"""The encoder swap is the one library change the port makes on the output path.

`toon_format.encode` must agree with `@toon-format/toon` on every shape falcon-axi prints
(docs/design/v1-python.md §9 P0.1). The golden documents prove it end to end; these cases pin the
shapes directly, including the stable 1.x empty-array rendering.
"""

from toon_format import decode, encode

from falcon_axi.render import raw, render


def test_a_uniform_row_array_encodes_as_a_tabular_block() -> None:
    document = encode(
        {
            "detections": [
                {"id": "ldt:synthetic-agent-01:1001", "severity": "High", "tactic": "Execution", "hostname": "WIN-WS-42"},
                {"id": "ldt:a,b:2", "severity": "Low", "tactic": "Discovery: stuff", "hostname": "host with space"},
            ]
        }
    )
    assert document.split("\n")[0] == "detections[2]{id,severity,tactic,hostname}:"
    assert '  "ldt:synthetic-agent-01:1001",High,Execution,WIN-WS-42' in document
    assert '  "ldt:a,b:2",Low,"Discovery: stuff",host with space' in document


def test_a_single_element_string_array_stays_inline() -> None:
    assert encode({"required_scopes": ["Alerts:read"]}).strip() == 'required_scopes[1]: "Alerts:read"'


def test_falcon_axi_never_emits_an_empty_array() -> None:
    """Stable TOON 1.x renders an empty array as `key: []`.

    `detection list` renders an empty result as a raw line and `required_scopes` is never empty, so
    no falcon-axi document reaches that shape.
    """
    assert encode({"empty": []}).strip() == "empty: []"
    empty_result = render({"detections": raw("0 detections in this tenant")})
    assert empty_result == "detections: 0 detections in this tenant\n"


def test_a_rendered_document_round_trips_through_the_decoder() -> None:
    document = render(
        {"count": raw("2 of 384 total"), "detections": [{"id": "ldt:a:1", "severity": "High"}]},
        [
            "Run `falcon-axi detection show <id>` for the full detection",
            "first, with a comma",
            'second with "quotes" and a colon: here',
        ],
    )
    decoded = decode(document)
    assert decoded["detections"] == [{"id": "ldt:a:1", "severity": "High"}]
    assert decoded["help"] == [
        "Run `falcon-axi detection show <id>` for the full detection",
        "first, with a comma",
        'second with "quotes" and a colon: here',
    ]
