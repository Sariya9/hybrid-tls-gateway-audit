#!/usr/bin/env python3
"""Synthetic evidence mutations and an optional live-record regression.

Run with python3 -B -m unittest discover -s <http_policy> -p test_audit_http.py.
Set AUDIT_HTTP_RUN_DIRECTORY to also audit retained live records and source bytes.
The synthetic fixture is evidence for auditor behaviour, not a TLS experiment.
"""
import contextlib
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

import audit_http as audit


SOURCE_BYTES = {"run_http.py": b"# synthetic collector source\n",
                "origin_http.c": b"/* synthetic native source */\n",
                "frozen_gateway_helper.py": b"# synthetic credential helper source\n"}
PROXY_CERT, ORIGIN_CERT = "a" * 64, "b" * 64
BODY = b"\x00\xff\x01\x80"
CONFIG = """global
    log stdout format raw local0 info
defaults
    mode http
    retries 0
    option http-keep-alive
frontend front
    bind 127.0.0.1:14000 ssl crt proxy.pem
    default_backend legacy
backend legacy
    http-reuse always
    server origin 127.0.0.1:14001 ssl verify required ca-file ca.crt verifyhost origin.test ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse no-sni-auto
backend restricted
    http-reuse always
    server origin 127.0.0.1:14002 ssl verify required ca-file ca.crt verifyhost origin.test ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse no-sni-auto
"""


def declaration_bytes(record):
    return (json.dumps(record["declaration"], indent=2) + "\n").encode()


def refresh_declaration(record):
    record["declaration_sha256"] = audit.digest(declaration_bytes(record))
    record["source_sha256"]["declaration.json"] = record["declaration_sha256"]
    for scenario, spec in zip(record["scenarios"], record["declaration"]["cases"]):
        scenario["specification"] = copy.deepcopy(spec)


def sync_events(record, origin):
    process = record["scenarios"][0]["processes"][origin]
    process["stdout"] = "".join(json.dumps(event) + "\n" for event in process["events"])


def mutate_row(record, index=0, **fields):
    process = record["scenarios"][0]["processes"]["gateway"]
    rows = process["stdout"].splitlines()
    row = dict(item.split("=", 1) for item in rows[index].split()[1:])
    row.update({key: str(value) for key, value in fields.items()})
    rows[index] = "AUDIT " + " ".join(f"{key}={value}" for key, value in row.items())
    process["stdout"] = "\n".join(rows) + "\n"


def make_record(paths=None, statuses=None, front=audit.H, restricted="H", policy="route_aware"):
    """Small coherent record with reused backend connections and two front ports."""
    paths = paths or ("/compat", "/restricted", "/compat", "/restricted")
    statuses = statuses or [200] * len(paths)
    requests, requirements, logs = [], [], []
    processes = {role: dict(stdout="", stderr="", reaped=True, timed_out=False,
                            cleanup_signal=None, exit=0) for role in ("legacy", "restricted", "gateway")}
    for role in ("legacy", "restricted"):
        processes[role]["events"] = [dict(event="listening", origin=role, monotonic_ns=1)]
    for index, (path, status) in enumerate(zip(paths, statuses)):
        rid = f"synthetic_{index}"
        batch, port = (0, 20000) if index < 2 else (1, 20001)
        origin = "legacy" if path == "/compat" else "restricted"
        backend = audit.C if origin == "legacy" or restricted == "C" else audit.H
        requirements.append(dict(path=path, batch=batch, required_mask=0 if path == "/compat" else 3,
                                 allowed_under_declared_requirement=path == "/compat" or (front == audit.H and restricted == "H"),
                                 expected_http_status=200))
        client = dict(local_port=port, tls_version="TLSv1.3", peer_certificate_sha256=PROXY_CERT,
                      session_reused=False, certificate_verified=True, expected_dns_name="proxy.test",
                      http_status=status, response_hex=BODY.hex() if status == 200 else b"denied".hex(),
                      response_request_id=rid if status == 200 else None,
                      response_origin_connection="1" if status == 200 else None, exception=None)
        requests.append(dict(request_id=rid, path=path, batch=batch, body_hex=BODY.hex(), client=client))
        if status == 200:
            events = processes[origin]["events"]
            if not any(e["event"] == "tls" and e["ok"] for e in events):
                events.append(dict(event="tls", origin=origin, monotonic_ns=10 + index * 2, connection_id=1, ok=True,
                                   group=backend, version="TLSv1.3", session_reused=False,
                                   certificate_sha256=ORIGIN_CERT, psk_offered=False))
            events.append(dict(event="application_accept", origin=origin, monotonic_ns=10 + index * 2,
                               connection_id=1, request_id=rid, path=path, body_hex=BODY.hex(), body_bytes=len(BODY)))
            events.append(dict(event="response", origin=origin, monotonic_ns=11 + index * 2,
                               connection_id=1, request_id=rid, status=200))
        elif status == 503:
            events = processes[origin]["events"]
            events.append(dict(event="tls", origin=origin, monotonic_ns=10 + index * 2,
                               connection_id=index + 2, ok=False, group=None, version=None,
                               session_reused=False, certificate_sha256=ORIGIN_CERT, psk_offered=False,
                               reason="handshake_failed", no_shared_group=True, reason_code=101))
            events.append(dict(event="connection_closed", origin=origin, monotonic_ns=11 + index * 2,
                               connection_id=index + 2))
        row = dict(id=rid, path=path, cp=port, fc=front, bc=backend if status == 200 else "-",
                   fp="TLSv1.3", bp="TLSv1.3" if status == 200 else "-", fr=0,
                   br=0 if status == 200 else "-", cert=ORIGIN_CERT if status == 200 else "-",
                   backend=origin if status != 403 else "front", status=status, term="----")
        logs.append("AUDIT " + " ".join(f"{key}={value}" for key, value in row.items()))
    processes["gateway"]["stdout"] = "\n".join(logs) + "\n"
    for role in ("legacy", "restricted"):
        events = processes[role]["events"]
        if any(e["event"] == "tls" and e["ok"] for e in events):
            events.append(dict(event="connection_closed", origin=role, monotonic_ns=100, connection_id=1))
        events.append(dict(event="stopped", origin=role, monotonic_ns=101))
        processes[role]["stdout"] = "".join(json.dumps(event) + "\n" for event in events)
    spec = dict(id="synthetic", policy=policy, restricted_origin=restricted,
                client_mode="H" if front == audit.H else "C", requests=requirements)
    record = dict(schema_version=1, status="collected", declaration=dict(schema_version=1, phase="predeclared",
                  payload_bytes=len(BODY), cases=[spec]), declaration_sha256="", runtime={},
                  credentials={"proxy": {"sha256": PROXY_CERT}, "origin": {"sha256": ORIGIN_CERT}},
                  source_sha256={name: audit.digest(data) for name, data in SOURCE_BYTES.items()},
                  scenarios=[dict(id=spec["id"], specification=copy.deepcopy(spec), config=CONFIG,
                                  config_sha256=audit.digest(CONFIG.encode()), processes=processes, requests=requests)])
    refresh_declaration(record)
    return record


def write_run(directory, record):
    (directory / "results.json").write_text(json.dumps(record))
    raw = declaration_bytes(record)
    (directory / "declaration.json").write_bytes(raw)
    (directory / "source").mkdir()
    for name, data in {**SOURCE_BYTES, "declaration.json": raw}.items():
        (directory / "source" / name).write_bytes(data)


class AuditorTests(unittest.TestCase):
    def test_minimal_coherent_record(self):
        result = audit.audit(make_record(paths=["/compat"]))
        self.assertEqual(result["totals"], dict(requests=1, admitted=1, violations=0, overblocked=0,
                                                rejected_unavailable=0, expectation_mismatches=0))
        self.assertEqual(result["cases"][0]["requests"][0]["classification"], "admitted_conforming")
        self.assertEqual(result["pooled_sessions"], 0)
        self.assertFalse(result["retained_file_hashes_verified"])
        self.assertNotIn("auditor_sha256", result)

    def test_pooling_is_observed_and_origin_ids_are_local(self):
        result = audit.audit(make_record())
        self.assertEqual(result["pooled_sessions"], 2)
        self.assertEqual(result["cross_frontend_reuse"], 2)
        self.assertEqual({s["origin"] for s in result["sessions"]}, {"legacy", "restricted"})
        for session in result["sessions"]:
            self.assertEqual(session["connection_id"], 1)
            self.assertEqual(session["local_ports"], [20000, 20001])

    def test_policy_failure_is_valid_evidence_and_expectations_are_separate(self):
        record = make_record(front=audit.C, policy="support_only")
        result = audit.audit(record)
        self.assertEqual(result["by_policy"]["support_only"]["violations"], 2)
        self.assertEqual(result["totals"]["expectation_mismatches"], 0)
        original = [r["classification"] for r in result["cases"][0]["requests"]]
        record["declaration"]["cases"][0]["requests"][1]["expected_http_status"] = 403
        refresh_declaration(record)
        revised = audit.audit(record)
        self.assertEqual(revised["totals"]["expectation_mismatches"], 1)
        self.assertEqual(original, [r["classification"] for r in revised["cases"][0]["requests"]])

    def test_backend_classical_violation_comes_from_observed_group(self):
        result = audit.audit(make_record(paths=["/restricted"], restricted="C", policy="support_only"))
        req = result["cases"][0]["requests"][0]
        self.assertEqual(req["observed_mask"], 1)
        self.assertEqual(req["classification"], "admitted_violation")

    def test_availability_is_declared_and_not_inferred_from_status(self):
        record = make_record(paths=["/compat", "/restricted"], statuses=[503, 403], front=audit.C)
        result = audit.audit(record)
        self.assertEqual([r["classification"] for r in result["cases"][0]["requests"]],
                         ["rejected_available", "rejected_unavailable"])
        self.assertEqual(result["totals"]["overblocked"], 1)
        self.assertEqual(result["totals"]["rejected_unavailable"], 1)
        self.assertEqual(result["totals"]["expectation_mismatches"], 2)

    def test_declared_client_mode_must_match_observed_front_group(self):
        for observed, declared in ((audit.H, "C"), (audit.C, "H")):
            for status in (200, 503):
                with self.subTest(observed=observed, declared=declared, status=status):
                    record = make_record(paths=["/restricted"], statuses=[status], front=observed)
                    spec = record["declaration"]["cases"][0]
                    spec["client_mode"] = declared
                    spec["requests"][0]["allowed_under_declared_requirement"] = declared == "H"
                    spec["requests"][0]["expected_http_status"] = status
                    refresh_declaration(record)
                    with self.assertRaisesRegex(audit.ValidationError, "declared client mode"):
                        audit.audit(record)

    def test_declared_availability_cannot_be_rewritten_to_hide_overblocking(self):
        record = make_record(paths=["/compat"], statuses=[503])
        record["declaration"]["cases"][0]["requests"][0]["allowed_under_declared_requirement"] = False
        refresh_declaration(record)
        with self.assertRaisesRegex(audit.ValidationError, "availability"):
            audit.audit(record)

    def test_payload_corruption_at_each_observation(self):
        for layer in ("request", "origin", "response", "length", "hex"):
            with self.subTest(layer=layer):
                record = make_record(paths=["/compat"])
                req = record["scenarios"][0]["requests"][0]
                if layer == "request":
                    req["body_hex"] = "11" * len(BODY)
                elif layer == "response":
                    req["client"]["response_hex"] = "11" * len(BODY)
                elif layer == "hex":
                    req["body_hex"] = "0g"
                else:
                    event = record["scenarios"][0]["processes"]["legacy"]["events"][2]
                    event["body_hex" if layer == "origin" else "body_bytes"] = "11" * len(BODY) if layer == "origin" else 99
                    sync_events(record, "legacy")
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_missing_group_and_certificate_never_pass_on_200(self):
        for field in ("fc", "bc", "cert", "bp", "br"):
            with self.subTest(field=field):
                record = make_record(paths=["/compat"])
                mutate_row(record, **{field: "-"})
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)
        for field in ("group", "certificate_sha256"):
            with self.subTest(origin_field=field):
                record = make_record(paths=["/compat"])
                del record["scenarios"][0]["processes"]["legacy"]["events"][1][field]
                sync_events(record, "legacy")
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_raw_and_structured_evidence_must_agree(self):
        record = make_record()
        record["scenarios"][0]["processes"]["legacy"]["events"][2]["body_hex"] = "00" * len(BODY)
        with self.assertRaisesRegex(audit.ValidationError, "raw/structured"):
            audit.audit(record)

    def test_duplicate_and_missing_ids_in_each_layer(self):
        for layer in ("gateway_duplicate", "gateway_missing", "request_duplicate", "request_missing",
                      "origin_duplicate", "origin_missing", "unknown_gateway", "unknown_origin"):
            with self.subTest(layer=layer):
                record = make_record()
                scenario = record["scenarios"][0]
                gateway = scenario["processes"]["gateway"]
                origin = scenario["processes"]["legacy"]
                if layer == "gateway_duplicate":
                    gateway["stdout"] += gateway["stdout"].splitlines()[0] + "\n"
                elif layer == "gateway_missing":
                    gateway["stdout"] = "\n".join(gateway["stdout"].splitlines()[1:]) + "\n"
                elif layer == "request_duplicate":
                    scenario["requests"][2]["request_id"] = scenario["requests"][0]["request_id"]
                elif layer == "request_missing":
                    del scenario["requests"][0]["request_id"]
                elif layer == "origin_duplicate":
                    origin["events"].insert(3, copy.deepcopy(origin["events"][2]))
                    sync_events(record, "legacy")
                elif layer == "origin_missing":
                    origin["events"] = [e for e in origin["events"] if e.get("request_id") != "synthetic_0"]
                    sync_events(record, "legacy")
                elif layer == "unknown_gateway":
                    gateway["stdout"] += gateway["stdout"].splitlines()[0].replace("synthetic_0", "unrequested") + "\n"
                else:
                    for event in origin["events"]:
                        if event.get("request_id") == "synthetic_0":
                            event["request_id"] = "unrequested"
                    sync_events(record, "legacy")
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_bad_session_mapping_and_identity(self):
        mutations = [("client", "local_port", 29999), ("client", "response_origin_connection", 2),
                     ("client", "response_request_id", "wrong"), ("client", "certificate_verified", False),
                     ("client", "expected_dns_name", "wrong.test"), ("client", "peer_certificate_sha256", "c" * 64),
                     ("client", "session_reused", True), ("gateway", "bc", audit.H),
                     ("gateway", "fr", 1), ("gateway", "br", 1), ("gateway", "backend", "restricted"),
                     ("gateway", "cert", "c" * 64), ("gateway", "fp", "TLSv1.2")]
        for layer, field, value in mutations:
            with self.subTest(layer=layer, field=field):
                record = make_record(paths=["/compat"])
                if layer == "client":
                    record["scenarios"][0]["requests"][0]["client"][field] = value
                else:
                    mutate_row(record, **{field: value})
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_same_front_port_cannot_change_group(self):
        record = make_record()
        mutate_row(record, index=1, fc=audit.C)
        with self.assertRaisesRegex(audit.ValidationError, "declared client mode"):
            audit.audit(record)

    def test_origin_lifecycle_and_tls_fail_closed(self):
        for mutation in ("no_tls", "no_close", "no_response", "bad_order", "psk", "resumed", "wrong_origin"):
            with self.subTest(mutation=mutation):
                record = make_record(paths=["/compat"])
                events = record["scenarios"][0]["processes"]["legacy"]["events"]
                if mutation in ("no_tls", "no_close", "no_response"):
                    kind = {"no_tls": "tls", "no_close": "connection_closed", "no_response": "response"}[mutation]
                    events[:] = [e for e in events if e["event"] != kind]
                elif mutation == "bad_order":
                    events[2]["monotonic_ns"] = 0
                elif mutation == "wrong_origin":
                    events[2]["origin"] = "restricted"
                else:
                    events[1]["psk_offered" if mutation == "psk" else "session_reused"] = True
                sync_events(record, "legacy")
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_failed_backend_handshake_is_valid_rejection_evidence(self):
        record = make_record(paths=["/compat", "/restricted"], statuses=[200, 503], restricted="C")
        result = audit.audit(record)
        self.assertEqual(result["totals"]["rejected_unavailable"], 1)
        self.assertEqual(result["totals"]["admitted"], 1)

    def test_503_requires_selected_origin_group_refusal_evidence(self):
        for mutation in ("cleared", "missing", "no_tls", "wrong_origin", "successful_tls", "wrong_backend"):
            with self.subTest(mutation=mutation):
                record = make_record(paths=["/restricted"], statuses=[503], restricted="C")
                processes = record["scenarios"][0]["processes"]
                events = processes["restricted"]["events"]
                if mutation == "cleared":
                    events[1]["no_shared_group"] = False
                elif mutation == "missing":
                    del events[1]["no_shared_group"]
                elif mutation == "no_tls":
                    del events[1:-1]
                elif mutation == "wrong_origin":
                    moved = events[1:-1]
                    for event in moved:
                        event["origin"] = "legacy"
                    processes["legacy"]["events"][1:1] = moved
                    del events[1:-1]
                    sync_events(record, "legacy")
                elif mutation == "successful_tls":
                    events[-1:-1] = [dict(event="tls", origin="restricted", monotonic_ns=50,
                                          connection_id=99, ok=True, group=audit.C, version="TLSv1.3",
                                          session_reused=False, certificate_sha256=ORIGIN_CERT, psk_offered=False),
                                     dict(event="connection_closed", origin="restricted", monotonic_ns=60,
                                          connection_id=99)]
                else:
                    mutate_row(record, backend="legacy")
                sync_events(record, "restricted")
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_rejected_status_cannot_hide_application_acceptance(self):
        record = make_record(paths=["/compat"])
        client = record["scenarios"][0]["requests"][0]["client"]
        client.update(http_status=403, response_request_id=None, response_origin_connection=None)
        mutate_row(record, status=403)
        with self.assertRaisesRegex(audit.ValidationError, "rejected request"):
            audit.audit(record)

    def test_no_acceptance_cannot_be_replaced_by_client_response(self):
        record = make_record(paths=["/compat"])
        events = record["scenarios"][0]["processes"]["legacy"]["events"]
        events[:] = [e for e in events if e["event"] not in ("application_accept", "response")]
        sync_events(record, "legacy")
        with self.assertRaisesRegex(audit.ValidationError, "acceptance"):
            audit.audit(record)

    def test_process_cleanup_failures_are_errors(self):
        for role in ("legacy", "restricted", "gateway"):
            for field, value in (("timed_out", True), ("reaped", False), ("cleanup_signal", "SIGKILL"), ("exit", 1)):
                with self.subTest(role=role, field=field):
                    record = make_record()
                    record["scenarios"][0]["processes"][role][field] = value
                    with self.assertRaises(audit.ValidationError):
                        audit.audit(record)

    def test_missing_requests_scenarios_and_specification_drift(self):
        for mutation in ("request", "scenario", "duplicate_scenario", "specification"):
            with self.subTest(mutation=mutation):
                record = make_record()
                if mutation == "request":
                    record["scenarios"][0]["requests"].pop()
                elif mutation == "scenario":
                    record["scenarios"].clear()
                elif mutation == "duplicate_scenario":
                    record["scenarios"].append(copy.deepcopy(record["scenarios"][0]))
                else:
                    record["scenarios"][0]["specification"]["policy"] = "support_only"
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_config_hash_and_backend_identity_checks(self):
        for mutation in ("hash", "verify", "verifyhost", "reuse", "sni", "sni_auto"):
            with self.subTest(mutation=mutation):
                record = make_record()
                scenario = record["scenarios"][0]
                before, after = {"hash": ("mode http", "mode tcp"), "verify": ("verify required", "verify none"),
                                 "verifyhost": ("origin.test", "other.test"), "reuse": ("no-ssl-reuse", ""),
                                 "sni": ("no-ssl-reuse", "no-ssl-reuse sni str(origin.test)"),
                                 "sni_auto": ("no-sni-auto", "no-sni-auto sni-auto")}[mutation]
                scenario["config"] = scenario["config"].replace(before, after)
                if mutation != "hash":
                    scenario["config_sha256"] = audit.digest(scenario["config"].encode())
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_no_sni_auto_required_on_each_backend(self):
        for backend in ("legacy", "restricted"):
            with self.subTest(backend=backend):
                record = make_record()
                scenario = record["scenarios"][0]
                lines = scenario["config"].splitlines()
                server_index = lines.index(f"backend {backend}") + 2
                lines[server_index] = lines[server_index].replace(" no-sni-auto", "")
                scenario["config"] = "\n".join(lines) + "\n"
                scenario["config_sha256"] = audit.digest(scenario["config"].encode())
                with self.assertRaisesRegex(audit.ValidationError, f"{backend}: explicit no-sni-auto"):
                    audit.audit(record)

    def test_duplicate_json_keys_and_gateway_fields(self):
        with self.assertRaisesRegex(audit.ValidationError, "duplicate JSON"):
            audit.parse_json('{"id": 1, "id": 2}')
        with self.assertRaises(audit.ValidationError):
            audit.parse_json('{"value": NaN}')
        record = make_record(paths=["/compat"])
        record["scenarios"][0]["processes"]["gateway"]["stdout"] = record["scenarios"][0]["processes"]["gateway"]["stdout"].rstrip() + " status=200\n"
        with self.assertRaises(audit.ValidationError):
            audit.audit(record)

    def test_in_memory_audit_does_not_mutate_input(self):
        record = make_record()
        original = copy.deepcopy(record)
        audit.audit(record)
        self.assertEqual(record, original)

    def test_cli_outputs_and_refuses_existing_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root / "run"
            run.mkdir()
            record = make_record()
            write_run(run, record)
            before = {p.relative_to(run): p.read_bytes() for p in run.rglob("*") if p.is_file()}
            out = root / "audit"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main([str(run), "--out", str(out)]), 0)
                summary = json.loads((out / "summary.json").read_text())
                self.assertTrue(summary["retained_file_hashes_verified"])
                self.assertEqual(summary["auditor_sha256"],
                                 hashlib.sha256(Path(audit.__file__).read_bytes()).hexdigest())
                with (out / "request_outcomes.csv").open(newline="") as handle:
                    rows = list(csv.DictReader(handle))
                self.assertEqual(len(rows), len(record["scenarios"][0]["requests"]))
                self.assertIn(r"route\_aware", (out / "application_results.tex").read_text())
                outputs = {p.name: p.read_bytes() for p in out.iterdir()}
                self.assertEqual(audit.main([str(run), "--out", str(out)]), 1)
                self.assertEqual(outputs, {p.name: p.read_bytes() for p in out.iterdir()})
            self.assertEqual(before, {p.relative_to(run): p.read_bytes() for p in run.rglob("*") if p.is_file()})

    def test_retained_source_and_declaration_hashes(self):
        for path in ("source/run_http.py", "source/origin_http.c", "source/declaration.json",
                     "source/frozen_gateway_helper.py", "declaration.json"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                write_run(root, make_record())
                with (root / path).open("ab") as handle:
                    handle.write(b"\n")
                with self.assertRaisesRegex(audit.ValidationError, "hash"):
                    audit.load_record(root)

    def test_successful_connection_header_accepts_text_or_integer(self):
        for value in ("1", 1):
            with self.subTest(header=value):
                record = make_record(paths=["/compat"])
                record["scenarios"][0]["requests"][0]["client"]["response_origin_connection"] = value
                self.assertEqual(audit.audit(record)["totals"]["admitted"], 1)

    def test_missing_and_unsafe_source_entries(self):
        for mutation in ("missing", "traversal", "malformed_hash"):
            with self.subTest(mutation=mutation):
                record = make_record()
                if mutation == "missing":
                    del record["source_sha256"]["frozen_gateway_helper.py"]
                elif mutation == "traversal":
                    record["source_sha256"]["../unexpected.py"] = "a" * 64
                else:
                    record["source_sha256"]["run_http.py"] = "unknown"
                with self.assertRaises(audit.ValidationError):
                    audit.audit(record)

    def test_invalid_run_creates_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            record = make_record()
            record["scenarios"][0]["requests"][0]["client"]["response_hex"] = "0000"
            write_run(root, record)
            out = root / "new-audit"
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main([str(root), "--out", str(out)]), 1)
            self.assertFalse(out.exists())


@unittest.skipUnless(os.environ.get("AUDIT_HTTP_RUN_DIRECTORY"), "no live record directory supplied")
class LiveRecordTests(unittest.TestCase):
    def test_live_record_and_payload_mutation(self):
        record = audit.load_record(os.environ["AUDIT_HTTP_RUN_DIRECTORY"])
        summary = audit.audit(record)
        self.assertEqual(summary["totals"]["requests"], sum(len(s["requests"]) for s in record["scenarios"]))
        changed = copy.deepcopy(record)
        admitted = next((r for s in changed["scenarios"] for r in s["requests"] if r["client"]["http_status"] == 200), None)
        self.assertIsNotNone(admitted, "live fixture needs an admitted request for this mutation")
        admitted["client"]["response_hex"] += "00"
        with self.assertRaises(audit.ValidationError):
            audit.audit(changed)


if __name__ == "__main__":
    unittest.main()
