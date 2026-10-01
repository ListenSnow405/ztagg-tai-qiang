#!/usr/bin/env python3
"""Compare two APK (zip) archives entry-by-entry so a repack list can be validated.

Usage: python tools/compare_apk_entries.py <base.apk> <other.apk> [--hash]
Exits 0 always; prints only the entries that differ (size, or content when --hash).
"""
from __future__ import annotations

import hashlib
import sys
import zipfile


def inventory(path: str, do_hash: bool) -> dict[str, tuple[int, str | None]]:
    out: dict[str, tuple[int, str | None]] = {}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            digest = None
            if do_hash:
                digest = hashlib.sha256(zf.read(info.filename)).hexdigest()
            out[info.filename] = (info.file_size, digest)
    return out


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    do_hash = "--hash" in sys.argv
    if len(args) != 2:
        print(__doc__)
        return 2
    base, other = (inventory(a, do_hash) for a in args)
    print(f"{args[0]}: {len(base)} entries")
    print(f"{args[1]}: {len(other)} entries")

    only_base = sorted(set(base) - set(other))
    only_other = sorted(set(other) - set(base))
    changed = sorted(
        name for name in set(base) & set(other)
        if base[name][0] != other[name][0] or (do_hash and base[name][1] != other[name][1])
    )

    print(f"\n=== only in {args[0]} ({len(only_base)}) ===")
    for name in only_base:
        print("  " + name)
    print(f"\n=== only in {args[1]} ({len(only_other)}) ===")
    for name in only_other:
        print("  " + name)
    print(f"\n=== differing content ({len(changed)}) ===")
    for name in changed:
        print(f"  {name}\n      {base[name][0]} -> {other[name][0]} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
