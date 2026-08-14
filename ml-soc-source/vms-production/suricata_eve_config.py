#!/usr/bin/env python3
"""Disable only Suricata EVE stats events that exceed Wazuh's JSON field limit."""

from pathlib import Path
import sys


MARKER = "# stats output disabled: Wazuh JSON decoder field limit"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def disable_eve_stats_output(source: str) -> tuple[str, bool]:
    lines = source.splitlines(keepends=True)
    eve_indent = None
    types_indent = None

    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        indent = _indent(lines[index])

        if stripped == "- eve-log:":
            eve_indent = indent
            types_indent = None
            index += 1
            continue

        if eve_indent is not None and stripped and indent <= eve_indent:
            eve_indent = None
            types_indent = None

        if eve_indent is not None and types_indent is None:
            if stripped == "types:" and indent > eve_indent:
                types_indent = indent
        elif types_indent is not None and stripped == "- stats:" and indent > types_indent:
            block_indent = indent
            end = index + 1
            while end < len(lines):
                candidate = lines[end]
                if candidate.strip() and _indent(candidate) <= block_indent:
                    break
                end += 1

            newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
            lines[index:end] = [" " * block_indent + MARKER + newline]
            return "".join(lines), True

        index += 1

    return source, False


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} /etc/suricata/suricata.yaml", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    source = path.read_text(encoding="utf-8")
    updated, changed = disable_eve_stats_output(source)
    if changed:
        path.write_text(updated, encoding="utf-8")
        print(f"[OK] Disabled Suricata EVE stats output in {path}")
    else:
        print(f"[OK] Suricata EVE stats output already disabled in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
