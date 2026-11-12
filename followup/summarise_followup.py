#!/usr/bin/env python3
"""Summarise one run of run_followup.py.

    python3 summarise_followup.py results/2026-11-12-followup-01

It reads results.json and the scanner JSON files in that folder and writes
summary.json next to them. It does not run any experiment.
"""
import json
from pathlib import Path
import re
import sys

H = "X25519MLKEM768"


def testssl_findings(path):
    """id -> (severity, finding), with port numbers and scan time removed."""
    findings = {}
    for entry in json.loads(path.read_text()):
        if entry["id"] in ("scanTime", "engine_problem"):
            continue
        findings[entry["id"]] = (entry.get("severity"), re.sub(r"\b\d{5}\b", "PORT", entry.get("finding", "")))
    return findings


def sslyze_findings(path):
    scan = json.loads(path.read_text())["server_scan_results"][0]
    result = scan.get("scan_result") or {}
    suites = (result.get("tls_1_3_cipher_suites") or {}).get("result") or {}
    curves = (result.get("elliptic_curves") or {}).get("result") or {}
    return dict(status=scan.get("scan_status"),
                tls13_suites=sorted(s["cipher_suite"]["name"] for s in suites.get("accepted_cipher_suites", [])),
                supported_curves=sorted(c["name"] for c in curves.get("supported_curves") or []))


def main(folder):
    folder = Path(folder)
    results = json.loads((folder / "results.json").read_text())
    summary = dict(run=folder.name, runtime=results["runtime"], verification_controls={}, scanner_baseline={})

    # Part A: did the origin ever accept a request when verification failed?
    for name in ("V1", "V2", "V3"):
        entry = results["scenarios"][name]
        requests = entry["requests"]
        summary["verification_controls"][name] = dict(
            note=entry["specification"]["note"],
            http_status=[r["http_status"] for r in requests],
            gateway_error=sorted({r["gateway_backend_error_name"] for r in requests}),
            origin_tls_completed=sum(c["tls_completed"] for c in entry["origin_counts"].values()),
            origin_tls_failed=sum(c["tls_failed"] for c in entry["origin_counts"].values()),
            origin_requests_accepted=sum(c["application_accept"] for c in entry["origin_counts"].values()),
            # None when nothing was admitted, so that "true" is never vacuous
            every_accept_after_origin_tls=all(r.get("origin_tls_before_accept") for r in requests
                                              if r["admitted_by_origin"])
            if any(r["admitted_by_origin"] for r in requests) else None)

    # Part B: what is true per scenario, and what does each scanner report?
    scans = {}
    for name in ("S1", "S2", "S3"):
        entry = results["scenarios"][name]
        restricted = [r for r in entry["requests"] if r["path"] == "/restricted"]
        conforming = [r["gateway_front_group"] == H and r["gateway_backend_group"] == H
                      and r.get("origin_group") == H for r in restricted]
        raw = folder / "raw" / name
        scans[name] = {f"{tool}-{target}": reader(raw / f"{tool}-{target}.json")
                       for tool, reader in (("testssl", testssl_findings), ("sslyze", sslyze_findings))
                       for target in ("frontend", "origin")}
        summary["scanner_baseline"][name] = dict(
            note=entry["specification"]["note"],
            gateway_backend_offer=entry["specification"]["backend"],
            origin_accepts=entry["specification"]["origin"],
            restricted_requests=len(restricted),
            restricted_backend_groups=sorted({r["gateway_backend_group"] for r in restricted}),
            restricted_requests_conforming=sum(conforming),
            testssl_frontend_kems=scans[name]["testssl-frontend"].get("FS_KEMs"),
            testssl_origin_kems=scans[name]["testssl-origin"].get("FS_KEMs"),
            sslyze_frontend_curves=scans[name]["sslyze-frontend"]["supported_curves"],
            sslyze_origin_curves=scans[name]["sslyze-origin"]["supported_curves"])

    # Which pairs of scenarios does each scan fail to tell apart?
    summary["identical_scanner_output"] = {
        key: {f"{a}={b}": scans[a][key] == scans[b][key] for a, b in (("S1", "S2"), ("S1", "S3"), ("S2", "S3"))}
        for key in ("testssl-frontend", "testssl-origin", "sslyze-frontend", "sslyze-origin")}

    (folder / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
