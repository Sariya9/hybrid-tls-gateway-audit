#!/usr/bin/env python3
"""Create the paper's CSV and LaTeX table from a retained run, without rerunning it."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("run", type=Path)
p.add_argument("--out", type=Path, required=True)
a = p.parse_args()
a.out.mkdir(parents=True, exist_ok=False)
r = json.loads((a.run / "results.json").read_text())
m_bytes = (a.run / "declared_matrix.json").read_bytes()
m = json.loads(m_bytes)
assert r["status"] == "passed"
assert hashlib.sha256(m_bytes).hexdigest() == r["matrix_sha256"]
specs = {c["id"]: c for c in m["cases"]}
assert len(r["cases"]) == len(specs) == 16
short = {"X25519MLKEM768": "H", "X25519": "C",
         "X25519MLKEM768:X25519": "HC"}
mask = {0: "--", 1: "F", 2: "B", 3: "FB"}
def group(v):
    return "--" if v is None else {"x25519mlkem768":"H","x25519":"C"}[v.casefold()]
def code(x):
    if x["stage"] == "delivered":
        return "DV" if x["conformance"] == "violated" else "DC"
    return {"front_group_rejected": "RF", "backend_group_rejected": "RB",
            "release_blocked": "RG", "front_ca_rejected": "CF",
            "backend_name_rejected": "CB"}[x["stage"]]

rows = []
for c in r["cases"]:
    s = specs[c["name"]]
    o = c["observed"]
    assert c["status"] == "expected_observation_matched"
    assert code(s["expected"]) == code(o)
    rows.append(dict(id=c["name"], client=short[s["client_groups"]],
                     front=short[s["front_groups"]], backend=short[s["backend_groups"]],
                     origin=short[s["origin_groups"]], required=mask[s["required_mask"]],
                     guard="on" if s["release_guard"] else "off",
                     negotiated_f=group(o["front_group"]),
                     negotiated_b=group(o["backend_group"]),
                     predicted=code(s["expected"]), observed=code(o),
                     delivered=o["delivered"], conformance=o["conformance"],
                     payload_write_attempts=o["payload_write_attempts"],
                     payload_bytes_accepted=o["payload_bytes_accepted"],
                     framing_bytes_accepted=o["framing_bytes_accepted"]))
with (a.out / "policy_outcomes.csv").open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0])
    writer.writeheader()
    writer.writerows(rows)
tex = [
    r"\begin{table*}[t]\centering\small",
    r"\caption{Declared matrix and observed outcomes. H is X25519MLKEM768; C is X25519; HC is the ordered support list H,C. Required identifies policy legs; Auth.\ F/B reports authenticated negotiations, with a dash for an absent authenticated connection. DC: conforming delivery; DV: delivery violating the declaration; RF/RB: front/backend group rejection; RG: release-guard refusal; CF/CB: front/backend certificate rejection.}",
    r"\label{tab:matrix}",
    r"\begin{tabular}{@{}lccccccccc@{}}\toprule",
    r"ID & Client & Front & Backend & Origin & Required & Guard & Auth.\ F/B & Predicted & Observed \\ \midrule",
]
for row in rows:
    values=[str(row[k]) for k in ("id","client","front","backend","origin","required","guard")]
    values += [row["negotiated_f"]+"/"+row["negotiated_b"],row["predicted"],row["observed"]]
    tex.append(" & ".join(values) + r" \\")
tex += [r"\bottomrule\end{tabular}", r"\end{table*}"]
(a.out / "policy_results.tex").write_text("\n".join(tex) + "\n")
by_id = {c["name"]: c for c in r["cases"]}
paired = [by_id["M05"], by_id["M06"]]
for case in paired:
    ev = case["processes"]["origin"]["events"]
    assert [e["iana_ids"] for e in ev if e["event"] == "offered_groups"] == [[4588, 29], [4588, 29]]
    assert [e["iana_ids"] for e in ev if e["event"] == "offered_key_shares"] == [[4588], [29]]
    assert len([e for e in ev if e["event"] == "hello_retry_request"]) == 1
    assert case["observed"]["backend_group"].lower() == "x25519"
    gate = next(e for e in case["processes"]["proxy"]["events"] if e["event"] == "release_policy")
    assert gate["allowed"] == (case["name"] == "M05")
paired_tex = r"""
\begin{table}[t]\centering\small
\caption{Observed backend trace for the paired support/enforcement cases. The TLS exchanges select the same group; only release differs.}
\label{tab:paired}
\begin{tabular}{@{}p{0.44\columnwidth}cc@{}}\toprule
Observation & M05 & M06 \\ \midrule
Supported groups & H,C & H,C \\
Initial key share & H & H \\
HelloRetryRequest & yes & yes \\
Replacement key share & C & C \\
Authenticated backend group & C & C \\
Release guard enabled & no & yes \\
READY sent & yes & no \\
Request bytes at origin & 303 & 0 \\
Response bytes at client & 319 & 0 \\
\bottomrule\end{tabular}
\end{table}
"""
(a.out / "paired_trace.tex").write_text(paired_tex.strip() + "\n")
summary = {"cases": len(rows),
           "violations": sum(x["conformance"] == "violated" for x in rows),
           "conforming_delivery": sum(x["conformance"] == "satisfied_with_delivery" for x in rows),
           "rejected": sum(not x["delivered"] for x in rows)}
assert summary == {"cases": 16, "violations": 3, "conforming_delivery": 6, "rejected": 7}
(a.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(summary)
