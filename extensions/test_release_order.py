#!/usr/bin/env python3
"""Replay retained evidence and reject causal mutations. Never starts TLS."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_release_order import ValidationError, validate_gateway, validate_reference

HERE = Path(__file__).resolve().parent
PACKAGED = HERE.name == "extensions"
RESULTS = HERE.parent / "results" if PACKAGED else HERE.parents[1] / "results" / "icete2027"
ALIASES = {
    "2026-10-24-primary-02": "primary",
    "2026-10-24-independent-02": "reproduction",
    "2026-10-24-gnutls-confirmatory-01": "gnutls",
    "2026-10-24-gnutls-parent-02": "gnutls-reproduction",
    "2026-10-24-gnutls-confirmatory-rebuilt-01": "gnutls-additional-rebuilt",
    "2026-10-24-haproxy-primary-01": "haproxy",
    "2026-10-24-haproxy-parent-01": "haproxy-reproduction",
}
REFERENCE_RUNS = (
    "2026-10-24-primary-01", "2026-10-24-independent-01",
    "2026-10-24-primary-02", "2026-10-24-independent-02",
    "2026-10-24-gnutls-confirmatory-01", "2026-10-24-gnutls-confirmatory-rebuilt-01",
    "2026-10-24-gnutls-parent-02",
)
GATEWAY_RUNS = ("2026-10-24-haproxy-primary-01", "2026-10-24-haproxy-parent-01")
if PACKAGED:
    # Only these two historical executions are intentionally absent from the ZIP.
    REFERENCE_RUNS = tuple(n for n in REFERENCE_RUNS if n not in
                          ("2026-10-24-primary-01", "2026-10-24-independent-01"))


def record_path(name):
    return RESULTS / (ALIASES[name] if PACKAGED else name) / "results.json"


def load(name):
    return json.loads(record_path(name).read_bytes())


def sync_stdout(record):
    # Mutations also change embedded raw text, so ordering assertions must catch them.
    for case in record["cases"]:
        for process in case["processes"].values():
            if "stdout" in process and "events" in process:
                process["stdout"] = "".join(json.dumps(e) + "\n" for e in process["events"])


def before(events, predicate, target):
    i = next(i for i, e in enumerate(events) if predicate(e))
    e = events.pop(i)
    at = next(i for i, e in enumerate(events) if target(e))
    events.insert(at, e)


def write_before(events, leg, kind, target):
    def selected(e):
        return e.get("leg") == leg and e.get("kind") == kind and (
            e["event"] in ("payload_write_attempt", "write_progress")
            or e["event"] == "frame" and e["direction"] == "sent")
    block = [e for e in events if selected(e)]
    events[:] = [e for e in events if not selected(e)]
    at = next(i for i, e in enumerate(events) if target(e))
    events[at:at] = block


class ReleaseOrderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = {name: load(name) for name in REFERENCE_RUNS + GATEWAY_RUNS}
        cls.hashes = {name: hashlib.sha256(record_path(name).read_bytes()).hexdigest()
                      for name in cls.records}

    @classmethod
    def tearDownClass(cls):
        for name, expected in cls.hashes.items():
            actual = hashlib.sha256(record_path(name).read_bytes()).hexdigest()
            if actual != expected:
                raise AssertionError("Retained record changed: " + name)

    def test_all_reference_executions(self):
        for name in REFERENCE_RUNS:
            with self.subTest(run=name):
                record = self.records[name]
                original = copy.deepcopy(record)
                summary = validate_reference(record)
                conforming, rejecting = (5, 8) if "gnutls" in name else (6, 7)
                self.assertEqual(summary["verdicts"], {"satisfied_with_delivery": conforming,
                                                     "violated": 3, "satisfied_by_rejection": rejecting})
                self.assertEqual([r["id"] for r in summary["cases"] if r["verdict"] == "violated"],
                                 ["M02", "M05", "M07"])
                self.assertGreater(summary["order_check_count"], 500)
                self.assertEqual(record, original)

    def test_all_gateway_executions(self):
        for name in GATEWAY_RUNS:
            with self.subTest(run=name):
                record = self.records[name]
                original = copy.deepcopy(record)
                summary = validate_gateway(record)
                self.assertEqual(summary["temporal_witness_cases"],
                                 ["H01", "H02", "H03", "H04", "H07", "H08", "H09"])
                self.assertEqual(summary["temporal_verdicts"], {"violated": 7, "not_certified": 2})
                self.assertEqual(summary["reason_counts"], {"required_group_not_hybrid": 2,
                    "accepted_write_without_ever_authenticated_backend": 2,
                    "client_write_before_origin_tls_start": 7})
                self.assertEqual(record, original)

    def negative(self, mutate, message):
        for name in ("2026-10-24-primary-02", "2026-10-24-gnutls-confirmatory-01"):
            with self.subTest(run=name):
                record = copy.deepcopy(self.records[name])
                case = next(c for c in record["cases"] if c["name"] == "M01")
                mutate(case)
                sync_stdout(record)
                with self.assertRaisesRegex(ValidationError, message):
                    validate_reference(record)

    def test_accepted_progress_before_matching_attempt(self):
        self.negative(lambda c: before(c["processes"]["client"]["events"],
            lambda e: e["event"] == "write_progress" and e["kind"] == "request",
            lambda e: e["event"] == "payload_write_attempt"), "attempt_before_accepted_bytes")

    def test_accepted_progress_before_own_handshake(self):
        for role, leg, kind in (("client", "front", "request"), ("proxy", "backend", "request"),
                                ("proxy", "front", "response"), ("origin", "backend", "response")):
            with self.subTest(role=role, leg=leg, kind=kind):
                self.negative(lambda c: before(c["processes"][role]["events"],
                    lambda e: e["event"] == "write_progress" and e["kind"] == kind and e["leg"] == leg,
                    lambda e: e["event"] == "handshake" and e["leg"] == leg),
                    "handshake_before_accepted_bytes")

    def test_client_release_before_ready(self):
        self.negative(lambda c: write_before(c["processes"]["client"]["events"], "front", "request",
            lambda e: e["event"] == "frame" and e["kind"] == "ready"),
            "causal_prerequisite_before_attempt")

    def test_ready_before_backend_authentication(self):
        def mutate(c):
            ev = c["processes"]["proxy"]["events"]
            before(ev, lambda e: e["event"] == "release_policy",
                   lambda e: e["event"] == "handshake" and e["leg"] == "backend")
        self.negative(mutate, "authenticated_backend_before_gate")

    def test_backend_request_before_front_request_read(self):
        self.negative(lambda c: write_before(c["processes"]["proxy"]["events"], "backend", "request",
            lambda e: e["event"] == "frame" and e["kind"] == "request" and e["direction"] == "received"),
            "causal_prerequisite_before_attempt")

    def test_origin_response_before_request_read(self):
        self.negative(lambda c: write_before(c["processes"]["origin"]["events"], "backend", "response",
            lambda e: e["event"] == "frame" and e["kind"] == "request"),
            "causal_prerequisite_before_attempt")

    def test_front_reply_before_backend_response_read(self):
        self.negative(lambda c: write_before(c["processes"]["proxy"]["events"], "front", "response",
            lambda e: e["event"] == "frame" and e["kind"] == "response" and e["direction"] == "received"),
            "causal_prerequisite_before_attempt")

    def test_mismatched_ready(self):
        def mutate(c):
            next(e for e in c["processes"]["client"]["events"] if e["event"] == "frame"
                 and e["kind"] == "ready")["hex"] = "0000000000"
        self.negative(mutate, "ready frame does not match")

    def test_mismatched_origin_payload(self):
        def mutate(c):
            next(e for e in c["processes"]["origin"]["events"] if e["event"] == "frame"
                 and e["kind"] == "request")["hex"] = "00"
        self.negative(mutate, "request frame does not match")

    def test_failed_initiator_verification(self):
        def mutate(c):
            next(e for e in c["processes"]["client"]["events"] if e["event"] == "handshake")["verify_code"] = 62
        self.negative(mutate, "missing initiator authentication")

    def test_nonpositive_accepted_byte_count(self):
        def mutate(c):
            next(e for e in c["processes"]["client"]["events"] if e["event"] == "write_progress")["bytes"] = 0
        self.negative(mutate, "invalid API accepted-byte event")

    def test_expected_and_observed_are_not_oracle_inputs(self):
        for name in ("2026-10-24-primary-02", "2026-10-24-gnutls-confirmatory-01", GATEWAY_RUNS[0]):
            check = validate_gateway if "haproxy" in name else validate_reference
            record = copy.deepcopy(self.records[name])
            expected = check(record)
            for c in record["cases"]:
                c["observed"] = {"conformance": "false historical value"}
                c["expected"] = None
                if "specification" in c:
                    c["specification"]["expected"] = None
            self.assertEqual(check(record), expected)

    def test_gateway_clock_and_source_assumptions(self):
        original = self.records[GATEWAY_RUNS[0]]
        bad_source = copy.deepcopy(original)
        bad_source["source_sha256"]["endpoints.c"] = "0" * 64
        with self.assertRaisesRegex(ValidationError, "reviewed frozen endpoint source"):
            validate_gateway(bad_source)
        # No clock witness may be inferred from eventual handshake completion alone.
        later = copy.deepcopy(original)
        c = next(c for c in later["cases"] if c["id"] == "H01")
        client = c["processes"]["client"]["events"]
        origin = c["processes"]["origin"]["events"]
        delta = max(e["monotonic_ns"] for e in origin) - min(e["monotonic_ns"] for e in client) + 1
        for e in client:
            e["monotonic_ns"] += delta
        sync_stdout(later)
        row = validate_gateway(later)["cases"][0]
        self.assertEqual(row["temporal_verdict"], "not_certified")
        self.assertEqual(row["witnesses"], [])

    def test_cli_fresh_output_and_input_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "review"
            args = [sys.executable, "-B", str(HERE / "check_release_order.py"),
                    "--openssl", str(record_path("2026-10-24-primary-02")),
                    "--gnutls", str(record_path("2026-10-24-gnutls-confirmatory-01")),
                    "--haproxy", str(record_path(GATEWAY_RUNS[0])), "--out", str(out)]
            first = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            output = (out / "summary.json").read_bytes()
            result = json.loads(output)
            self.assertEqual(result["input_hashes"]["openssl"]["sha256"], self.hashes["2026-10-24-primary-02"])
            second = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual((out / "summary.json").read_bytes(), output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
