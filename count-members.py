#!/usr/bin/env python3
"""Count the number of members per entry in an LDIF file.

Examples:
    ./ldif_member_count.py groups.ldif
    ./ldif_member_count.py groups.ldif --attr member uniqueMember memberUid
    ./ldif_member_count.py groups.ldif --sort --min 1 --csv > counts.csv
    cat groups.ldif | ./ldif_member_count.py -
"""
import argparse
import base64
import csv
import sys
from collections import Counter


def read_entries(handle):
    """Yield each LDIF entry as a list of unfolded (name, value) tuples."""
    lines = []
    for raw in handle:
        line = raw.rstrip("\r\n")
        if line.startswith(" ") and lines:
            # Folded line: continuation of the previous line
            lines[-1] += line[1:]
        elif line == "":
            if lines:
                yield parse_lines(lines)
                lines = []
        elif line.startswith("#"):
            continue
        else:
            lines.append(line)
    if lines:
        yield parse_lines(lines)


def parse_lines(lines):
    attrs = []
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        if value.startswith(":"):  # base64-encoded value ("attr:: ...")
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", "replace")
            except Exception:
                value = value[1:].strip()
        elif value.startswith("<"):  # URL reference, keep as-is
            value = value[1:].strip()
        else:
            value = value.strip()
        # Drop attribute options, e.g. "member;range=0-1499"
        name = name.split(";", 1)[0].strip().lower()
        attrs.append((name, value))
    return attrs


def count_members(entry, wanted):
    dn = ""
    counts = Counter()
    for name, value in entry:
        if name == "dn":
            dn = value
        elif name in wanted:
            counts[name] += 1
    return dn, counts


def main():
    parser = argparse.ArgumentParser(description="Count members per entry in an LDIF file.")
    parser.add_argument("file", help="LDIF file path, or '-' for stdin")
    parser.add_argument("--attr", nargs="+", default=["member"],
                        help="membership attribute(s) to count (default: member)")
    parser.add_argument("--sort", action="store_true", help="sort by count, descending")
    parser.add_argument("--min", type=int, default=0, dest="min_count",
                        help="only show entries with at least this many members")
    parser.add_argument("--csv", action="store_true", help="output as CSV")
    args = parser.parse_args()

    wanted = {a.lower() for a in args.attr}
    handle = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")

    results = []
    with handle:
        for entry in read_entries(handle):
            dn, counts = count_members(entry, wanted)
            total = sum(counts.values())
            if dn and total >= args.min_count and (total > 0 or args.min_count == 0):
                results.append((dn, total, counts))

    if args.sort:
        results.sort(key=lambda r: r[1], reverse=True)

    if args.csv:
        writer = csv.writer(sys.stdout)
        writer.writerow(["dn", "members"])
        for dn, total, _ in results:
            writer.writerow([dn, total])
    else:
        for dn, total, counts in results:
            detail = ""
            if len(wanted) > 1:
                detail = "  (" + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) + ")"
            print(f"{total:>6}  {dn}{detail}")
        print(f"\n{len(results)} entries, {sum(r[1] for r in results)} members in total",
              file=sys.stderr)


if __name__ == "__main__":
    main()
