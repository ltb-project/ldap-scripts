#!/usr/bin/env python3
"""Print the DN of each LDIF entry that has both a userPassword and a
pwdPolicySubentry attribute.
 
Examples:
    ./ldif_pwd_policy_entries.py users.ldif
    ./ldif_pwd_policy_entries.py users.ldif --show-policy
    cat users.ldif | ./ldif_pwd_policy_entries.py -
"""
import argparse
import base64
import sys
 
 
def read_entries(handle):
    """Yield each LDIF entry as a list of unfolded raw lines."""
    lines = []
    for raw in handle:
        line = raw.rstrip("\r\n")
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]  # folded continuation line
        elif line == "":
            if lines:
                yield lines
                lines = []
        elif line.startswith("#"):
            continue
        else:
            lines.append(line)
    if lines:
        yield lines
 
 
def parse_entry(lines):
    """Return (dn, {attr_name: [values]}) with lower-cased attribute names."""
    dn = ""
    attrs = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        if value.startswith(":"):  # base64-encoded value
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", "replace")
            except Exception:
                value = value[1:].strip()
        else:
            value = value.strip()
        name = name.split(";", 1)[0].strip().lower()  # drop attribute options
        if name == "dn":
            dn = value
        else:
            attrs.setdefault(name, []).append(value)
    return dn, attrs
 
 
def main():
    parser = argparse.ArgumentParser(
        description="Print DNs of entries having both userPassword and pwdPolicySubentry.")
    parser.add_argument("file", help="LDIF file path, or '-' for stdin")
    parser.add_argument("--show-policy", action="store_true",
                        help="also print the pwdPolicySubentry value (tab-separated)")
    args = parser.parse_args()
 
    handle = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="replace")
 
    with handle:
        for lines in read_entries(handle):
            dn, attrs = parse_entry(lines)
            if dn and "userpassword" in attrs and "pwdpolicysubentry" in attrs:
                if args.show_policy:
                    print(f"{dn}\t{attrs['pwdpolicysubentry'][0]}")
                else:
                    print(dn)
 
 
if __name__ == "__main__":
    main()
 

