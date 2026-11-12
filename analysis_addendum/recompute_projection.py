"""Recompute the Section 8 grouping from the retained HTTP audit records.

Run it on the request_outcomes.csv files in the reproducibility package:

    python3 recompute_projection.py \
        reports/http-primary/request_outcomes.csv \
        reports/http-reproduction/request_outcomes.csv

It only reads the CSV files. It does not run any experiment.
"""
import csv
import sys
from collections import defaultdict

# What a frontend observer can see for one request. TLS version, the
# verification result and the frontend certificate are the same for every
# admitted request in one execution, so they cannot split a group and are
# left out here.
FRONTEND = ["path", "required_mask", "front_group", "http_status"]


def minimum_errors(rows, keys):
    """Group admitted requests by `keys` and count the unavoidable errors.

    A rule that only sees `keys` has to give one answer per group, so in a
    group with both labels it is wrong at least min(conforming, violating)
    times.
    """
    groups = defaultdict(lambda: {"conforming": 0, "violating": 0, "cases": set()})
    for row in rows:
        group = groups[tuple(row[k] for k in keys)]
        if row["classification"] == "admitted_conforming":
            group["conforming"] += 1
        else:
            group["violating"] += 1
        group["cases"].add(row["case_id"])
    mixed = {k: g for k, g in groups.items() if g["conforming"] and g["violating"]}
    total = sum(min(g["conforming"], g["violating"]) for g in mixed.values())
    return total, mixed


def main(paths):
    for path in paths:
        with open(path, newline="") as handle:
            rows = list(csv.DictReader(handle))
        admitted = [r for r in rows if r["classification"].startswith("admitted")]
        print(f"{path}: {len(rows)} requests, {len(admitted)} admitted")

        for label, keys in [
            ("frontend summary", FRONTEND),
            ("frontend summary + gateway policy", FRONTEND + ["policy"]),
            ("frontend summary + backend group", FRONTEND + ["backend_group"]),
        ]:
            total, mixed = minimum_errors(admitted, keys)
            print(f"  {label}: minimum errors = {total}")
            for key, group in mixed.items():
                print(
                    f"    mixed group {key}: {group['conforming']} conforming, "
                    f"{group['violating']} violating, scenarios {sorted(group['cases'])}"
                )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
