#!/usr/bin/env python3
"""Derive library comparisons and gateway tables from retained observations."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from check_release_order import validate_gateway, validate_reference


def load(path, count):
    data = path.read_bytes()
    record = json.loads(data)
    assert record["status"] == "passed" and len(record["cases"]) == count
    for case in record["cases"]:
        assert case["status"] == "expected_observation_matched"
        for role, process in case["processes"].items():
            assert process["reaped"] and not process["timed_out"]
            assert process["cleanup_signal"] is None
            if role != "haproxy" and "stdout" in process:
                assert [json.loads(line) for line in process["stdout"].splitlines()] == process["events"]
    return record, hashlib.sha256(data).hexdigest()


def group(name):
    return "--" if name is None else {"x25519mlkem768": "H", "x25519": "C"}[name.casefold()]


def pair(observed):
    return group(observed["front_group"]) + "/" + group(observed["backend_group"])


def outcome(observed):
    if observed["delivered"]:
        return "DV" if observed["conformance"] == "violated" else "DC"
    return {"front_group_rejected": "RF", "backend_group_rejected": "RB",
            "release_blocked": "RG", "front_ca_rejected": "CF",
            "backend_name_rejected": "CB"}[observed["stage"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", type=Path, required=True)
    parser.add_argument("--gnutls", type=Path, required=True)
    parser.add_argument("--gnutls-fixed", type=Path, required=True)
    parser.add_argument("--haproxy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert __debug__, "Do not use Python -O"
    baseline, openssl_hash = load(args.openssl, 16)
    library, gnutls_hash = load(args.gnutls, 16)
    gateway, gateway_hash = load(args.haproxy, 9)
    fixed, fixed_hash = load(args.gnutls_fixed, 16)
    causal = {"openssl": validate_reference(baseline), "gnutls": validate_reference(library),
              "gnutls_fixed": validate_reference(fixed), "haproxy": validate_gateway(gateway)}
    for name, record in (("openssl", baseline), ("gnutls", library), ("gnutls_fixed", fixed)):
        for observed, derived in zip(record["cases"], causal[name]["cases"]):
            assert observed["name"] == derived["id"]
            assert observed["observed"]["conformance"] == derived["verdict"]
            assert pair(observed["observed"]) == pair(derived)
    gateway_causal = {c["id"]: c for c in causal["haproxy"]["cases"]}
    fixed_by_id = {c["name"]: c for c in fixed["cases"]}
    args.out.mkdir(parents=True, exist_ok=False)
    by_id = {c["name"]: c for c in baseline["cases"]}
    masks = {0: "--", 1: "F", 2: "B", 3: "FB"}
    configured = {"X25519MLKEM768": "H", "X25519": "C",
                  "X25519MLKEM768:X25519": "HC"}
    library_tex = [r"\begin{table*}[t]\centering\small",
        r"\caption{Shared relay matrix and outcomes for OpenSSL (O), unmodified GnuTLS (G), and the upstream-fix control (G+). H is X25519MLKEM768; C is X25519; HC is configured H,C support. F/B lists authenticated groups, with a dash for an absent authenticated connection. DC: conforming delivery; DV: violating delivery; RF/RB: front/backend group rejection; RG: guard refusal; CF/CB: front/backend certificate rejection. G+ group and outcome pairs equal O in this execution.}",
        r"\label{tab:matrix}", r"\begin{tabular}{@{}lccccccccccc@{}}\toprule",
        r"ID & Client & Front & Backend & Origin & $D$ & Guard & O F/B & G F/B & O & G & G+ \\ \midrule"]
    rows = []
    for case in library["cases"]:
        ident = case["name"]
        original = by_id[ident]
        assert case["configuration"] == original["configuration"]
        assert case["declared_policy"] == original["declared_policy"]
        assert case["guard_enabled"] == original["guard_enabled"]
        observed = case["observed"]
        events = [e for p in case["processes"].values() for e in p["events"]]
        progress = [e for e in events if e["event"] == "write_progress" and e["kind"] in ("request", "response")]
        assert observed["payload_bytes_accepted"] == sum(e["bytes"] for e in progress if e["part"] == "payload")
        assert observed["framing_bytes_accepted"] == sum(e["bytes"] for e in progress if e["part"] == "header")
        if not observed["delivered"]:
            assert not progress and not [e for e in events if e["event"] in ("frame", "payload_write_attempt")]
        else:
            for kind, data in (("request", library["payload"]["request_hex"]), ("response", library["payload"]["response_hex"])):
                frames = [e for e in events if e["event"] == "frame" and e["kind"] == kind]
                assert len(frames) == 4 and all(e["hex"] == data for e in frames)
        old = original["observed"]
        patched = fixed_by_id[ident]
        assert patched["configuration"] == case["configuration"]
        assert patched["declared_policy"] == case["declared_policy"]
        assert patched["guard_enabled"] == case["guard_enabled"]
        assert (pair(patched["observed"]), outcome(patched["observed"])) == (pair(old), outcome(old))
        rows.append(dict(id=ident, openssl_groups=pair(old), gnutls_groups=pair(observed),
                         openssl_verdict=old["conformance"], gnutls_verdict=observed["conformance"],
                         gnutls_fixed_groups=pair(patched["observed"]),
                         gnutls_fixed_verdict=patched["observed"]["conformance"],
                         same_outcome=(old["stage"], pair(old), old["conformance"]) ==
                                      (observed["stage"], pair(observed), observed["conformance"])))
        configuration = original["configuration"]
        values = [ident] + [configured[configuration[k]] for k in
                           ("client_groups", "proxy_front_groups", "proxy_backend_groups", "origin_groups")]
        values += [masks[case["declared_policy"]], "on" if case["guard_enabled"] else "off",
                   pair(old), pair(observed), outcome(old), outcome(observed),
                   outcome(patched["observed"])]
        library_tex.append(" & ".join(values) + r" \\")
    library_tex += [r"\bottomrule\end{tabular}", r"\end{table*}"]
    (args.out / "library_results.tex").write_text("\n".join(library_tex) + "\n")
    with (args.out / "library_comparison.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0]); writer.writeheader(); writer.writerows(rows)
    tex = [r"\begin{table*}[t]\centering\small",
           r"\caption{HAProxy observations. F/B lists completed authenticated groups. Client and origin columns count request payload bytes, excluding four-byte framing. $\mathcal Q_D$ checks completed delivered routes; the final column reports evidence against the stronger barrier $\mathcal P_D$. Uncertified means the observations do not establish satisfaction.}",
           r"\label{tab:gateway}", r"\begin{tabular}{@{}lcccccll@{}}\toprule",
           r"Case & F/B & $D$ & Client accepted & Origin received & Delivery & $\mathcal Q_D$ & $\mathcal P_D$ evidence \\ \midrule"]
    gateway_rows = []
    for case in gateway["cases"]:
        observed = case["observed"]
        barrier = gateway_causal[case["id"]]
        required = case["specification"]["required_mask"]
        assert observed["original_temporal_property"] == "not_certified"
        p = case["processes"]
        client = [e for e in p["client"]["events"] if e["event"] == "write_progress" and e["kind"] == "request" and e["part"] == "payload"]
        origin = [e for e in p["origin"]["events"] if e["event"] == "read_progress" and e["kind"] == "request" and e["part"] == "payload"]
        assert sum(e["bytes"] for e in client) == observed["frontend_request_payload_bytes_accepted"]
        assert sum(e["bytes"] for e in origin) == observed["origin_request_payload_bytes_received"]
        if observed["delivered"]:
            assert observed["front_group"] and observed["backend_group"]
            for role in ("client", "origin"):
                frames = [e for e in p[role]["events"] if e["event"] == "frame"]
                assert len(frames) == 2
                assert [e["hex"] for e in frames] == [gateway["payload"]["request_hex"], gateway["payload"]["response_hex"]]
            met = not ((required & 1 and group(observed["front_group"]) != "H") or
                       (required & 2 and group(observed["backend_group"]) != "H"))
            assert observed["delivered_route_classification"] == ("requirements_met" if met else "group_requirement_violated")
            verdict = "met" if met else "violated"
        else:
            assert observed["origin_request_payload_bytes_received"] == 0
            verdict = "no delivery"
        row = dict(id=case["id"], groups=pair(observed), required={0: "--", 1: "F", 2: "B", 3: "FB"}[required],
                   client_bytes=observed["frontend_request_payload_bytes_accepted"],
                   origin_bytes=observed["origin_request_payload_bytes_received"],
                   delivery="yes" if observed["delivered"] else "no", route_check=verdict,
                   temporal_check=("violation_witness" if barrier["temporal_verdict"] == "violated"
                                   else "not_certified"),
                   temporal_reasons=";".join(w["reason"] for w in barrier["witnesses"]),
                   stage=observed["stage"])
        gateway_rows.append(row)
        values = [str(row[k]) for k in ("id", "groups", "required", "client_bytes", "origin_bytes", "delivery", "route_check")]
        values.append("violation" if row["temporal_check"] == "violation_witness" else "uncertified")
        tex.append(" & ".join(values) + r" \\")
    tex += [r"\bottomrule\end{tabular}", r"\end{table*}"]
    (args.out / "gateway_results.tex").write_text("\n".join(tex) + "\n")
    with (args.out / "gateway_outcomes.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=gateway_rows[0]); writer.writeheader(); writer.writerows(gateway_rows)
    summary = {"input_sha256": {"openssl": openssl_hash, "gnutls": gnutls_hash, "haproxy": gateway_hash},
               "gnutls_verdicts": dict(Counter(c["observed"]["conformance"] for c in library["cases"])),
               "library_differences": [r for r in rows if not r["same_outcome"]],
               "gateway_delivered_route_checks": dict(Counter(r["route_check"] for r in gateway_rows)),
               "gateway_client_write_without_origin_delivery": [r["id"] for r in gateway_rows if r["client_bytes"] and not r["origin_bytes"]],
               "original_property_violation_witnesses": [r["id"] for r in gateway_rows if r["temporal_check"] == "violation_witness"]}
    summary["input_sha256"]["gnutls_fixed"] = fixed_hash
    summary["causal_checker_sha256"] = hashlib.sha256(
        Path(__file__).with_name("check_release_order.py").read_bytes()).hexdigest()
    summary["gnutls_fixed_verdicts"] = causal["gnutls_fixed"]["verdicts"]
    summary["fix_control_changed_cases"] = [r["id"] for r in rows
        if (r["gnutls_groups"], r["gnutls_verdict"]) != (r["gnutls_fixed_groups"], r["gnutls_fixed_verdict"])]
    (args.out / "extension_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.out / "causal_evidence.json").write_text(json.dumps(causal, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
