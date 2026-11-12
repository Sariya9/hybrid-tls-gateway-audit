#!/usr/bin/env python3
"""Supplemental causal checks for the retained single-exchange TLS fixtures.

Public API: validate_reference(record) and validate_gateway(record) return new
JSON-compatible summaries, or raise ValidationError. Neither API writes files,
imports a runner, or consults expected/observed verdicts. Anchors use zero-based
indices into the input JSON. Local event order and matched frame dependencies
are kept separate; frame-completion logs are never merged into a global order.
Certificate fingerprint logs bind the peer to its fixture identity; they do not
replace the initiator's successful verification/handshake evidence. Matched
frames establish control-flow dependencies, not ordered completion timestamps.

The reference proof assumes the frozen cooperative fixture's control flow.
Gateway clock witnesses assume one host/CLOCK_MONOTONIC namespace and one fresh
non-PSK origin connection. They establish failure of the explicit release
contract, not a TLS obligation or a claim about internal gateway forwarding.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

H = "X25519MLKEM768"
C = "X25519"
READY = b"READY"
PREFIX = b"origin-response\0"
GATEWAY_ENDPOINT_SHA256 = "2c0ca58c493443cc9c8d07349ea3c26c3dbf69ad2c5d910da0666bcae1c7a39d"


class ValidationError(ValueError):
    """Missing, inconsistent or causally invalid native evidence."""


def _need(condition, message):
    if not condition:
        raise ValidationError(message)


def _find(events, event, **fields):
    return [i for i, e in enumerate(events) if e.get("event") == event
            and all(e.get(k) == v for k, v in fields.items())]


def _one(events, event, **fields):
    indices = _find(events, event, **fields)
    _need(len(indices) == 1, f"Expected one {event} {fields}; found {len(indices)}")
    return indices[0]


def _group(value):
    groups = {H.casefold(): H, "x25519-mlkem768": H, C.casefold(): C}
    _need(isinstance(value, str) and value.casefold() in groups,
          f"Unknown successful negotiated group {value!r}")
    return groups[value.casefold()]


def _anchor(ci, role, ei):
    return f"cases[{ci}].processes.{role}.events[{ei}]"


def _payload(record):
    p = record["payload"]
    request, response = bytes.fromhex(p["request_hex"]), bytes.fromhex(p["response_hex"])
    _need(0 < len(request) <= 4096 and response == PREFIX + request,
          "Invalid request/response fixture")
    _need(p["request_bytes"] == len(request) and p["response_bytes"] == len(response),
          "Payload length metadata mismatch")
    return request, response


def _events(case, roles):
    result = {}
    for role in roles:
        p = case["processes"][role]
        _need(p["reaped"] and not p["timed_out"] and p["cleanup_signal"] is None,
              f"{role}: incomplete process evidence")
        ev = p["events"]
        _need(isinstance(ev, list) and all(isinstance(e, dict) and "event" in e for e in ev),
              f"{role}: invalid event list")
        if "stdout" in p:
            _need([json.loads(s) for s in p["stdout"].splitlines()] == ev,
                  f"{role}: embedded stdout differs from events")
        result[role] = ev
    return result


def _handshake(ev, leg):
    i = _one(ev, "handshake", leg=leg)
    h = ev[i]
    _need(type(h["ok"]) is bool and h["session_reused"] is False,
          f"{leg}: invalid handshake status or resumed connection")
    if h["ok"]:
        _need(h["protocol"] in ("TLSv1.3", "TLS1.3"), f"{leg}: not TLS 1.3")
        _group(h["group"])
    return i


def _authenticate(record, ev, leg, peer, edge):
    hi = _handshake(ev, leg)
    h = ev[hi]
    if not h["ok"]:
        return hi, None
    _need(h["verify_code"] == 0 and h["certificate_status"] == "verified"
          and h["verified_hostname"] == peer + ".test", f"{leg}: missing initiator authentication")
    cert = _one(ev, "certificate", leg=leg, kind="peer")
    _need(ev[cert]["sha256"] == record["credentials"][peer]["sha256"],
          f"{leg}: authenticated certificate fingerprint mismatch")
    for kind in (11, 15, 20):
        messages = _find(ev, "handshake_message", leg=leg, direction="received", type=kind)
        _need(messages, f"{leg}: missing authenticated handshake message {kind}")
        for i in messages:
            edge(i, hi, "handshake_message_before_completion")
    if "verify_called" in h:
        _need(h["verify_called"] is True, f"{leg}: verification callback not called")
        vi = _one(ev, "verification", leg=leg)
        v = ev[vi]
        _need(v["rc"] == v["status"] == 0 and v["san_exact"] is True
              and v["server_purpose"] is True and v["hostname"] == peer + ".test",
              f"{leg}: failed chain/SAN/purpose verification")
        edge(vi, hi, "verification_before_completion")
    return hi, _group(h["group"])


def _frame(ev, leg, kind, direction, data):
    i = _one(ev, "frame", leg=leg, kind=kind, direction=direction)
    e = ev[i]
    _need(e["bytes"] == len(data) and e["hex"] == data.hex(),
          f"{leg}: {kind} frame does not match fixture")
    return i


def _write(ev, leg, kind, data, handshake, edge, prerequisite=None):
    fi = _frame(ev, leg, kind, "sent", data)
    ai = None if kind == "ready" else _one(ev, "payload_write_attempt", leg=leg, kind=kind)
    if ai is not None:
        _need(ev[ai]["bytes"] == len(data), f"{kind}: attempted length mismatch")
        edge(handshake, ai, "handshake_before_attempt")
        if prerequisite is not None:
            edge(prerequisite, ai, "causal_prerequisite_before_attempt")
    progress = _find(ev, "write_progress", leg=leg, kind=kind)
    _need(progress, f"{kind}: no accepted-byte events")
    totals = Counter()
    for i in progress:
        e = ev[i]
        _need(type(e["bytes"]) is int and e["bytes"] > 0 and e["part"] in ("header", "payload"),
              f"{kind}: invalid API accepted-byte event")
        totals[e["part"]] += e["bytes"]
        edge(handshake, i, "handshake_before_accepted_bytes")
        if ai is not None:
            edge(ai, i, "attempt_before_accepted_bytes")
        if prerequisite is not None:
            edge(prerequisite, i, "causal_prerequisite_before_accepted_bytes")
        edge(i, fi, "accepted_bytes_before_completed_frame")
    _need(totals == {"header": 4, "payload": len(data)}, f"{kind}: accepted-byte totals mismatch")
    header = [i for i in progress if ev[i]["part"] == "header"]
    payload = [i for i in progress if ev[i]["part"] == "payload"]
    edge(max(header), min(payload), "framing_before_payload")
    return fi


def _start(record, count):
    _need(record["status"] == "passed" and len(record["cases"]) == count,
          "Expected a complete successful retained execution")
    ids = [c.get("name", c.get("id")) for c in record["cases"]]
    _need(len(set(ids)) == count and all(isinstance(i, str) for i in ids), "Duplicate/missing case IDs")


def validate_reference(record):
    """Return derived P_D verdicts and local-order/frame-match evidence for 16 cases.

    Invalid/incomplete evidence raises ValidationError; a valid trace that violates
    the declared group requirement returns verdict='violated'. Input is unchanged.
    """
    _start(record, 16)
    request, response = _payload(record)
    rows = []
    for ci, case in enumerate(record["cases"]):
        ev = _events(case, ("client", "proxy", "origin"))
        checks, links = [], []

        def edge(role, before, after, rule):
            _need(before < after, f"{case['name']} {role}: {rule} ({before} !< {after})")
            checks.append(dict(rule=rule, before=_anchor(ci, role, before), after=_anchor(ci, role, after)))

        def local(role):
            return lambda before, after, rule: edge(role, before, after, rule)

        fh, F = _authenticate(record, ev["client"], "front", "proxy", local("client"))
        pf = _handshake(ev["proxy"], "front")
        back = _find(ev["proxy"], "handshake", leg="backend")
        bh, B = (_authenticate(record, ev["proxy"], "backend", "origin", local("proxy"))
                 if back else (None, None))
        for role, events in ev.items():
            _need(all(not e["psk_offered"] for e in events if e["event"] == "client_hello"),
                  f"{role}: PSK offered")
            _need(not any(e["event"] == "handshake_message" and e["type"] == 4 for e in events),
                  f"{role}: session ticket outside reference scope")
        mask = case["declared_policy"]
        _need(type(mask) is int and mask in (0, 1, 2, 3), "Invalid declaration mask")
        progress = [(r, i) for r, events in ev.items() for i, e in enumerate(events)
                    if e["event"] == "write_progress"]
        frames = [(r, i) for r, events in ev.items() for i, e in enumerate(events) if e["event"] == "frame"]
        attempts = [(r, i) for r, events in ev.items() for i, e in enumerate(events)
                    if e["event"] == "payload_write_attempt"]
        if not progress:
            _need(not frames and not attempts, f"{case['name']}: incomplete/attempted release")
            verdict, delivered = "satisfied_by_rejection", False
        else:
            _need(F is not None and B is not None, f"{case['name']}: accepted bytes without authentication")
            _need(ev["proxy"][pf]["ok"] and _group(ev["proxy"][pf]["group"]) == F,
                  "Frontend peer group disagreement")
            oh = _handshake(ev["origin"], "backend")
            _need(ev["origin"][oh]["ok"] and _group(ev["origin"][oh]["group"]) == B,
                  "Backend peer group disagreement")
            gate = _one(ev["proxy"], "release_policy")
            edge("proxy", pf, gate, "front_completion_before_gate")
            edge("proxy", bh, gate, "authenticated_backend_before_gate")
            rs = _write(ev["proxy"], "front", "ready", READY, pf, local("proxy"), gate)
            rr = _frame(ev["client"], "front", "ready", "received", READY)
            edge("client", fh, rr, "client_authentication_before_ready_receipt")
            cq = _write(ev["client"], "front", "request", request, fh, local("client"), rr)
            pq = _frame(ev["proxy"], "front", "request", "received", request)
            edge("proxy", rs, pq, "ready_before_request_read")
            bq = _write(ev["proxy"], "backend", "request", request, bh, local("proxy"), pq)
            sq = _frame(ev["origin"], "backend", "request", "received", request)
            edge("origin", oh, sq, "origin_completion_before_request_read")
            sa = _write(ev["origin"], "backend", "response", response, oh, local("origin"), sq)
            ba = _frame(ev["proxy"], "backend", "response", "received", response)
            edge("proxy", bq, ba, "backend_request_before_response_read")
            pa = _write(ev["proxy"], "front", "response", response, pf, local("proxy"), ba)
            ca = _frame(ev["client"], "front", "response", "received", response)
            edge("client", cq, ca, "client_request_before_response_read")
            _need(len(frames) == 10 and len(attempts) == 4, "Unexpected extra/missing application frames")
            allowed_writes = {("client", "front", "request"), ("proxy", "front", "ready"),
                              ("proxy", "backend", "request"), ("origin", "backend", "response"),
                              ("proxy", "front", "response")}
            _need(all((r, ev[r][i].get("leg"), ev[r][i].get("kind")) in allowed_writes for r, i in progress),
                  "Unexpected accepted write")
            for kind, sr, si, dr, di in (("ready", "proxy", rs, "client", rr),
                                        ("request", "client", cq, "proxy", pq),
                                        ("request", "proxy", bq, "origin", sq),
                                        ("response", "origin", sa, "proxy", ba),
                                        ("response", "proxy", pa, "client", ca)):
                links.append(dict(kind=kind, sent_frame=_anchor(ci, sr, si), received_frame=_anchor(ci, dr, di),
                                  semantics="matched content and frozen control-flow dependency, not completion-log timestamp order"))
            violated = (mask & 1 and F != H) or (mask & 2 and B != H)
            verdict, delivered = ("violated" if violated else "satisfied_with_delivery"), True
        rows.append(dict(id=case["name"], required_mask=mask, front_group=F, backend_group=B,
                         verdict=verdict, delivered=delivered, order_check_count=len(checks),
                         order_checks=checks, matched_frames=links,
                         accepted_release_events=[_anchor(ci, r, i) for r, i in progress
                                                  if ev[r][i]["kind"] in ("request", "response")]))
    return dict(schema_version=1, kind="reference", case_count=len(rows),
                verdicts=dict(Counter(r["verdict"] for r in rows)),
                order_check_count=sum(r["order_check_count"] for r in rows), cases=rows,
                causal_scope="local program order and matched-frame dependencies under frozen cooperative fixture control flow; no merged stdout order")


def validate_gateway(record):
    """Return Q_D checks and P_D violation witnesses for nine eager HAProxy cases.

    temporal_verdict is 'violated' or 'not_certified', never a positive P_D
    certificate. Every witness includes its reason and exact input event anchors.
    """
    _start(record, 9)
    _need(record["source_sha256"]["endpoints.c"] == GATEWAY_ENDPOINT_SHA256,
          "Gateway source-order/clock witness requires the reviewed frozen endpoint source")
    request, response = _payload(record)
    rows = []
    for ci, case in enumerate(record["cases"]):
        ev = _events(case, ("client", "origin"))
        edges = []

        def edge(role, a, b, rule):
            _need(a < b, f"{case['id']} {role}: {rule}")
            edges.append(dict(rule=rule, before=_anchor(ci, role, a), after=_anchor(ci, role, b)))

        def client_edge(a, b, rule):
            edge("client", a, b, rule)

        fh, F = _authenticate(record, ev["client"], "front", "proxy", client_edge)
        for role, events in ev.items():
            times = [e["monotonic_ns"] for e in events]
            _need(all(type(t) is int and t > 0 for t in times) and times == sorted(times),
                  f"{role}: invalid local monotonic observations")
        config = case["config"]
        _need("retries 0" in config and "no-ssl-reuse" in config
              and "verify required" in config, "Gateway scope requires no retries and verified fresh backend")
        ohs = _find(ev["origin"], "handshake", leg="backend")
        accepted = _find(ev["origin"], "accepted")
        _need(len(accepted) <= 1 and len(ohs) <= 1, "Not a single origin connection")
        logs = [line for line in case["processes"]["haproxy"]["stdout"].splitlines() if line.startswith("case=")]
        _need(len(logs) == 1, "Missing/ambiguous gateway log")
        log = dict(item.split("=", 1) for item in logs[0].split())
        _need(log["case"] == case["id"], "Gateway log belongs to a different case")
        if F is not None:
            _need(_group(log["fc"]) == F and log["fp"] == "TLSv1.3" and log["fr"] == "0",
                  "Frontend gateway log disagrees with authenticated client")
        if ohs:
            _need(len(accepted) == 1, "Origin TLS without an accepted connection")
            for i, e in enumerate(ev["origin"]):
                if e["event"] in ("handshake", "handshake_message", "read_progress", "write_progress"):
                    edge("origin", accepted[0], i, "accepted_log_before_origin_tls_actions")
        B = None
        if ohs:
            oh = _handshake(ev["origin"], "backend")
            if ev["origin"][oh]["ok"] and log["be"] == "0":
                B = _group(ev["origin"][oh]["group"])
                _need(log["cert"].lower() == record["credentials"]["origin"]["sha256"]
                      and _group(log["bc"]) == B and log["br"] == "0", "Unbound backend authentication evidence")
                _need("verifyhost origin.test" in config, "Successful backend has unexpected reference identity")
        delivered = bool(_find(ev["client"], "exact_response_verified"))
        cp = _find(ev["client"], "write_progress", leg="front", kind="request")
        _need(all(e["event"] != "client_hello" or not e["psk_offered"] for e in ev["origin"]),
              "Gateway backend offered PSK")
        if cp:
            _need(F is not None, "Client write without authenticated frontend")
            _write(ev["client"], "front", "request", request, fh, client_edge)
        all_progress = [(role, e) for role, events in ev.items() for e in events if e["event"] == "write_progress"]
        _need(all((role, e.get("leg"), e.get("kind")) in
                  (("client", "front", "request"), ("origin", "backend", "response"))
                  for role, e in all_progress), "Unexpected gateway endpoint write")
        if delivered:
            _need(F is not None and B is not None, "Unverified delivered route")
            for role, leg in (("client", "front"), ("origin", "backend")):
                _frame(ev[role], leg, "request", "sent" if role == "client" else "received", request)
                _frame(ev[role], leg, "response", "received" if role == "client" else "sent", response)
            sq = _frame(ev["origin"], "backend", "request", "received", request)
            _write(ev["origin"], "backend", "response", response, ohs[0],
                   lambda a, b, rule: edge("origin", a, b, rule), sq)
        else:
            _need(not _find(ev["origin"], "write_progress"), "Undelivered case has origin response writes")
        mask = case["specification"]["required_mask"]
        _need(type(mask) is int and mask in (0, 1, 2, 3), "Invalid gateway declaration")
        bad = [leg for leg, group, bit in (("F", F, 1), ("B", B, 2)) if mask & bit and group != H]
        reasons = []
        if delivered and bad:
            reasons.append(dict(reason="required_group_not_hybrid", required_legs_failed=bad,
                                anchors=[_anchor(ci, "client", fh), _anchor(ci, "origin", ohs[0]),
                                         _anchor(ci, "client", cp[0])]))
        if cp and ohs and not ev["origin"][ohs[0]]["ok"] and log["bcname"] in ("SSL_HANDSHAKE", "SSL_MISMATCH"):
            reasons.append(dict(reason="accepted_write_without_ever_authenticated_backend",
                                anchors=[_anchor(ci, "client", cp[0]), _anchor(ci, "origin", ohs[0])],
                                gateway_error=log["bcname"], gateway_log_anchor=f"cases[{ci}].processes.haproxy.stdout"))
        if cp and accepted:
            wi, ai = cp[0], accepted[0]
            wt, at = ev["client"][wi]["monotonic_ns"], ev["origin"][ai]["monotonic_ns"]
            if wt < at:
                reasons.append(dict(reason="client_write_before_origin_tls_start",
                                    anchors=[_anchor(ci, "client", wi), _anchor(ci, "origin", ai)],
                                    client_write_monotonic_ns=wt, origin_accepted_monotonic_ns=at,
                                    source_order="endpoints.c:205 logs accepted before origin TLS creation/handshake at 365-368"))
        rows.append(dict(id=case["id"], required_mask=mask, front_group=F, backend_group=B,
                         delivered=delivered, delivered_route_verdict=("group_requirement_violated" if bad else "requirements_met") if delivered else "not_delivered",
                         temporal_verdict="violated" if reasons else "not_certified", witnesses=reasons,
                         order_checks=edges))
    return dict(schema_version=1, kind="gateway", case_count=len(rows), cases=rows,
                temporal_verdicts=dict(Counter(r["temporal_verdict"] for r in rows)),
                temporal_witness_cases=[r["id"] for r in rows if r["witnesses"]],
                reason_counts=dict(Counter(w["reason"] for r in rows for w in r["witnesses"])),
                witness_scope="same-host CLOCK_MONOTONIC namespace; reviewed frozen source order; one fresh non-PSK origin connection, no retries; no positive certification of internal gateway writes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("openssl", "gnutls", "haproxy"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    _need(not args.out.exists(), "Output directory already exists")
    inputs, summaries = {}, {}
    for name, check in (("openssl", validate_reference), ("gnutls", validate_reference), ("haproxy", validate_gateway)):
        path = getattr(args, name)
        data = path.read_bytes()
        inputs[name] = dict(sha256=hashlib.sha256(data).hexdigest(), input_file=path.name)
        summaries[name] = check(json.loads(data))
        _need(path.read_bytes() == data, "Input changed during validation")
    args.out.mkdir(parents=True, exist_ok=False)
    result = dict(schema_version=1, status="passed", input_hashes=inputs,
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), summaries=summaries)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v.get("verdicts", v.get("temporal_verdicts")) for k, v in summaries.items()}, indent=2))


if __name__ == "__main__":
    main()
