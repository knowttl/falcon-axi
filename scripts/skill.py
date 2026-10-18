#!/usr/bin/env python3
"""Generate the packaged skill, or refuse drift without writing."""

import argparse
import sys
from pathlib import Path

from falcon_axi.skill import skill_markdown

REPO = Path(__file__).resolve().parent.parent
SKILL_FILE = REPO / "skills/falcon-axi/SKILL.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed skill is stale; write nothing")
    args = parser.parse_args(argv)
    expected = skill_markdown()
    if args.check:
        try:
            actual = SKILL_FILE.read_text(encoding="utf-8")
        except OSError:
            actual = None
        if actual != expected:
            sys.stderr.write("SKILL.md is stale; run `uv run scripts/skill.py` to regenerate\n")
            return 1
        sys.stdout.write("SKILL.md is current\n")
    else:
        SKILL_FILE.write_text(expected, encoding="utf-8")
        sys.stdout.write("wrote skills/falcon-axi/SKILL.md\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
