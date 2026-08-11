#!/usr/bin/env python3
"""Keep the engine embedded in securid.bash in sync with securid-engine.py.

Usage:
    tools/embed.py            # write securid-engine.py into securid.bash
    tools/embed.py --check    # fail (exit 1) if securid.bash is out of sync
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASH = ROOT / "securid.bash"
ENGINE = ROOT / "securid-engine.py"
OPEN = "<<'__PASS_SECURID_ENGINE__'"
CLOSE = "__PASS_SECURID_ENGINE__"


def split(bash_text):
    lines = bash_text.splitlines(keepends=True)
    start = end = None
    in_block = False
    for i, ln in enumerate(lines):
        if not in_block and OPEN in ln:
            in_block = True
            start = i
            # the python body begins on the next line
            body_start = i + 1
            continue
        if in_block and ln.strip() == CLOSE:
            end = i
            break
    if start is None or end is None:
        raise SystemExit("securid.bash: engine block delimiters not found")
    return lines, body_start, end


def main():
    check = len(sys.argv) > 1 and sys.argv[1] == "--check"
    bash_text = BASH.read_text()
    lines, body_start, end = split(bash_text)
    engine = ENGINE.read_text().rstrip("\n") + "\n"

    extracted = "".join(lines[body_start:end]).rstrip("\n") + "\n"
    if extracted == engine:
        print("securid.bash engine is in sync")
        return 0
    if check:
        print("securid.bash engine is OUT OF SYNC with securid-engine.py",
              file=sys.stderr)
        print("run: tools/embed.py", file=sys.stderr)
        return 1
    new_bash = "".join(lines[:body_start]) + engine + "".join(lines[end:])
    BASH.write_text(new_bash)
    print("embedded securid-engine.py into securid.bash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
