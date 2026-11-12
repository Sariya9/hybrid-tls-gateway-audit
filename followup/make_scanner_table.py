#!/usr/bin/env python3
"""Print the rows of the paper's scanner-baseline table from summary.json.

    python3 make_scanner_table.py results/2026-11-12-followup-01

Run summarise_followup.py first. This script only reads summary.json.
"""
import json
from pathlib import Path
import sys

H = "X25519MLKEM768"


def short(groups):
    """X25519MLKEM768:X25519 -> HC, X25519 -> C, X25519MLKEM768 -> H."""
    return "".join("H" if g == H else "C" for g in groups.split(":"))


def reported(finding):
    """What testssl.sh said about hybrid key exchange for one target."""
    return "H" if finding and H in finding[1] else "none"


def main(folder):
    summary = json.loads((Path(folder) / "summary.json").read_text())
    print(" & Offer & Origin & Used & Conf. & Front & Origin \\\\ \\midrule")
    for name, row in summary["scanner_baseline"].items():
        used = "/".join(short(g) for g in row["restricted_backend_groups"])
        print(f"{name} & {short(row['gateway_backend_offer'])} & {short(row['origin_accepts'])} & {used} & "
              f"{row['restricted_requests_conforming']} & {reported(row['testssl_frontend_kems'])} & "
              f"{reported(row['testssl_origin_kems'])} \\\\")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
