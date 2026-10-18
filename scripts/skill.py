#!/usr/bin/env python3
"""Generate the packaged skill, or refuse drift without writing."""

import argparse
import sys
from pathlib import Path

from falcon_axi.skill import skill_files

REPO = Path(__file__).resolve().parent.parent
SKILL_ROOT = REPO / "skills/falcon-axi"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed skill is stale; write nothing")
    args = parser.parse_args(argv)
    expected = skill_files()
    actual = {path.relative_to(SKILL_ROOT).as_posix(): path.read_text(encoding="utf-8") for path in SKILL_ROOT.rglob("*.md")}
    if args.check:
        if actual != expected:
            sys.stderr.write("skill files are stale; run `uv run scripts/skill.py` to regenerate\n")
            return 1
        sys.stdout.write("skill files are current\n")
    else:
        for name, content in expected.items():
            target = SKILL_ROOT / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        for name in actual.keys() - expected.keys():
            (SKILL_ROOT / name).unlink()
        sys.stdout.write("wrote skills/falcon-axi/\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
