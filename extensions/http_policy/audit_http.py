#!/usr/bin/env python3
"""Independently correlate the bounded HTTP study's retained evidence.

Native collectors and their source authenticity are trusted. Hashes bind retained
bytes; they do not attest remote execution. No client write timing, latency or
population completeness is certified here. This module imports no collector code.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys


H, C = "X25519MLKEM768", "X25519"
POLICIES = ("support_only", "blanket_hybrid", "route_aware")
COUNTERS = ("requests", "admitted", "violations", "overblocked",
            "rejected_unavailable", "expectation_mismatches")
GATEWAY_KEYS = set("id path cp fc bc fp bp fr br cert backend status term".split())
CSV_FIELDS = ("case_id", "policy", "request_id", "path", "batch", "local_port",
              "origin", "connection_id", "front_group", "backend_group",
              "required_mask", "observed_mask", "allowed_under_declared_requirement",
              "http_status", "classification", "expected_http_status", "expectation_matched")


class ValidationError(ValueError):
    """Missing, malformed or contradictory evidence, distinct from a policy failure."""


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value),
            "missing or invalid SHA-256 fingerprint")
    return value.lower()


def integer(value, low, high, label):
    require(type(value) is int and low <= value <= high, f"invalid {label}: {value!r}")
    return value


def request_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value),
            "missing or unsafe request ID")
    return value


def payload(value):
    require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is not None,
            "invalid payload hex")
    return bytes.fromhex(value)


def group(value):
    require(isinstance(value, str) and value.lower() in (H.lower(), C.lower()),
            f"missing or unsupported TLS group: {value!r}")
    return H if value.lower() == H.lower() else C


def exact(left, right):
    # JSON equality must not silently equate true with 1 in retained evidence.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text):
    def bad_constant(value):
        raise ValidationError(f"invalid JSON constant: {value}")
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=bad_constant)


def process_check(process, role):
    require(process["reaped"] is True and process["timed_out"] is False
            and process["cleanup_signal"] is None, f"{role}: timeout or cleanup failure")
    require(isinstance(process["stdout"], str) and isinstance(process["stderr"], str),
            f"{role}: missing raw process output")
    if "exit" in process:
        require(type(process["exit"]) is int and process["exit"] == 0,
                f"{role}: unsuccessful process exit")


def origin_evidence(process, origin, certificate):
    """Reparse raw events and enforce each origin connection's event lifecycle."""
    events = [parse_json(line) for line in process["stdout"].splitlines() if line.strip()]
    require(exact(events, process["events"]), f"{origin}: raw/structured events differ")
    require(len(events) >= 2 and events[0]["event"] == "listening"
            and events[-1]["event"] == "stopped", f"{origin}: missing lifecycle evidence")
    tls, accepted, responses, closed = {}, {}, {}, set()
    previous = -1
    for index, event in enumerate(events):
        require(event["origin"] == origin, f"{origin}: event attributed to wrong origin")
        stamp = integer(event["monotonic_ns"], 0, 2**64 - 1, "event timestamp")
        require(stamp >= previous, f"{origin}: nonmonotonic events")
        previous = stamp
        kind = event["event"]
        if kind in ("listening", "stopped"):
            require(index == (0 if kind == "listening" else len(events) - 1),
                    f"{origin}: duplicate or misplaced {kind}")
            continue
        cid = integer(event["connection_id"], 1, 2**63 - 1, "origin connection ID")
        require(cid not in closed, f"{origin}: event after connection closed")
        if kind == "tls":
            require(cid not in tls and type(event["ok"]) is bool,
                    f"{origin}: duplicate or malformed TLS event")
            require(event["psk_offered"] is False, f"{origin}: PSK offered")
            if event["ok"]:
                group(event["group"])
                require(event["version"] == "TLSv1.3" and event["session_reused"] is False,
                        f"{origin}: wrong TLS version or resumed session")
                require(fingerprint(event["certificate_sha256"]) == certificate,
                        f"{origin}: certificate mismatch")
            else:
                require(type(event["no_shared_group"]) is bool,
                        f"{origin}: invalid group-refusal evidence")
                integer(event["reason_code"], 0, 2**31 - 1, "TLS failure reason code")
            tls[cid] = event
        elif kind == "application_accept":
            require(cid in tls and tls[cid]["ok"], f"{origin}: acceptance without successful TLS")
            rid = request_id(event["request_id"])
            require(rid not in accepted, f"{origin}: duplicate accepted request ID {rid}")
            require(event["path"] in ("/compat", "/restricted"), f"{origin}: invalid accepted path")
            body = payload(event["body_hex"])
            require(len(body) == integer(event["body_bytes"], 0, 4096, "accepted body length"),
                    f"{origin}: accepted body length mismatch")
            accepted[rid] = event
        elif kind == "response":
            rid = request_id(event["request_id"])
            require(rid in accepted and rid not in responses and event["status"] == 200
                    and type(event["status"]) is int and accepted[rid]["connection_id"] == cid,
                    f"{origin}: response/acceptance mapping mismatch")
            responses[rid] = event
        elif kind == "connection_closed":
            require(cid in tls, f"{origin}: close without TLS event")
            closed.add(cid)
        else:
            raise ValidationError(f"{origin}: unsupported event {kind!r}")
    require(closed == set(tls), f"{origin}: unclosed origin connections")
    require(set(accepted) == set(responses), f"{origin}: acceptance without response")
    return tls, accepted


def gateway_evidence(stdout):
    rows = {}
    for line in stdout.splitlines():
        if not line.startswith("AUDIT"):
            continue
        require(line.isascii() and line.startswith("AUDIT "), "malformed gateway AUDIT line")
        fields = line.split()[1:]
        require(all("=" in field for field in fields), "malformed gateway fields")
        row = _pairs(field.split("=", 1) for field in fields)
        require(set(row) == GATEWAY_KEYS and all(row.values()), "missing or extra gateway fields")
        rid = request_id(row["id"])
        require(rid not in rows, f"duplicate gateway request ID {rid}")
        rows[rid] = row
    return rows


def backend_authentication(config):
    """Check the configured initiating peer's identity checks on both origin routes."""
    backends = {}
    current = None
    for line in config.splitlines():
        words = line.split("#", 1)[0].split()
        if not words:
            continue
        if words[0] in ("global", "defaults", "frontend", "listen", "backend"):
            current = words[1] if words[0] == "backend" and len(words) == 2 else None
            if current is not None:
                require(current not in backends, "duplicate backend configuration")
                backends[current] = []
        elif current is not None and words[0] in ("server", "default-server"):
            backends[current].append(words)
    require(set(backends) == {"legacy", "restricted"}, "missing or unexpected origin backends")
    for name, servers in backends.items():
        require(len(servers) == 1 and servers[0][0] == "server", f"{name}: ambiguous server configuration")
        words = servers[0]
        require(len(words) > 3 and re.fullmatch(r"127\.0\.0\.1:[0-9]+", words[2]),
                f"{name}: origin is not IPv4 loopback")
        options = words[3:]
        for option, value in (("verify", "required"), ("verifyhost", "origin.test"),
                              ("ssl-min-ver", "TLSv1.3"), ("ssl-max-ver", "TLSv1.3")):
            require(options.count(option) == 1 and options.index(option) + 1 < len(options)
                    and options[options.index(option) + 1] == value, f"{name}: invalid {option}")
        require("no-sni-auto" in options and "sni-auto" not in options,
                f"{name}: explicit no-sni-auto required without sni-auto")
        require("ssl" in options and "ca-file" in options and "no-ssl-reuse" in options
                and not {"sni", "check", "check-ssl"}.intersection(options),
                f"{name}: missing authentication or unexpected SNI, reuse or health check")


def audit(record):
    """Audit a self-contained schema-1 record; never use predictions as verdicts.

    File hashes are checked against retained bytes by load_record for CLI use.
    An in-memory caller supplies those bytes' provenance separately.
    """
    try:
        return _audit(record)
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        raise ValidationError(f"malformed or missing evidence: {error}") from error


def _audit(record):
    require(type(record["schema_version"]) is int and record["schema_version"] == 1
            and record["status"] == "collected", "record is not a collected schema-1 run")
    declaration = record["declaration"]
    require(type(declaration["schema_version"]) is int and declaration["schema_version"] == 1,
            "unsupported declaration schema")
    size = integer(declaration["payload_bytes"], 0, 4096, "declared payload length")
    declaration_hash = fingerprint(record["declaration_sha256"])
    sources = record["source_sha256"]
    require(isinstance(sources, dict) and {"run_http.py", "origin_http.c", "declaration.json",
                                          "frozen_gateway_helper.py"} <= set(sources),
            "missing collector source hashes")
    for name, value in sources.items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                and name not in (".", ".."), "unsafe source filename")
        fingerprint(value)
    require(fingerprint(sources["declaration.json"]) == declaration_hash, "declaration hash disagreement")
    require(isinstance(record["runtime"], dict), "missing runtime record")
    certificates = {role: fingerprint(record["credentials"][role]["sha256"]) for role in ("proxy", "origin")}
    require(certificates["proxy"] != certificates["origin"], "proxy and origin certificates are identical")

    declared = {}
    require(isinstance(declaration["cases"], list) and declaration["cases"], "empty declaration")
    for spec in declaration["cases"]:
        sid = request_id(spec["id"])
        require(sid not in declared and spec["policy"] in POLICIES
                and spec["client_mode"] in ("H", "C") and spec["restricted_origin"] in ("H", "C"),
                "duplicate or invalid declared case")
        require(isinstance(spec["requests"], list) and spec["requests"], f"{sid}: empty request declaration")
        for req in spec["requests"]:
            path = req["path"]
            require(path in ("/compat", "/restricted"), f"{sid}: invalid declared path")
            integer(req["batch"], 0, 1, "declared batch")
            mask = integer(req["required_mask"], 0, 3, "required mask")
            require(mask == (0 if path == "/compat" else 3), f"{sid}: wrong route requirement")
            available = path == "/compat" or (spec["client_mode"] == "H" and spec["restricted_origin"] == "H")
            require(type(req["allowed_under_declared_requirement"]) is bool
                    and req["allowed_under_declared_requirement"] == available,
                    f"{sid}: inconsistent declared availability")
            integer(req["expected_http_status"], 100, 599, "expected HTTP status")
        declared[sid] = spec

    require(isinstance(record["scenarios"], list) and len(record["scenarios"]) == len(declared),
            "missing or extra scenarios")
    by_policy, cases, sessions = {}, [], []
    seen_cases, seen_ids = set(), set()
    for scenario in record["scenarios"]:
        sid = scenario["id"]
        require(sid in declared and sid not in seen_cases, "unknown or duplicate scenario ID")
        seen_cases.add(sid)
        spec = declared[sid]
        require(exact(scenario["specification"], spec), f"{sid}: scenario/declaration mismatch")
        config = scenario["config"]
        require(isinstance(config, str) and digest(config.encode()) == fingerprint(scenario["config_sha256"]),
                f"{sid}: configuration hash mismatch")
        backend_authentication(config)
        procs = scenario["processes"]
        require(set(procs) == {"legacy", "restricted", "gateway"}, f"{sid}: missing or extra processes")
        for role, process in procs.items():
            process_check(process, f"{sid}/{role}")
        origins = {name: origin_evidence(procs[name], name, certificates["origin"])
                   for name in ("legacy", "restricted")}
        for name, (tls, _) in origins.items():
            if name == "legacy" or spec["restricted_origin"] == "C":
                require(all(group(e["group"]) == C for e in tls.values() if e["ok"]),
                        f"{sid}/{name}: group contradicts C-only origin")
        accepted = {}
        for name, (_, requests) in origins.items():
            for rid, event in requests.items():
                require(rid not in accepted, f"{sid}: request accepted by multiple origins")
                accepted[rid] = (name, event)
        logs = gateway_evidence(procs["gateway"]["stdout"])
        requests = scenario["requests"]
        require(isinstance(requests, list) and len(requests) == len(spec["requests"]),
                f"{sid}: missing or extra requests")
        policy = spec["policy"]
        counters = by_policy.setdefault(policy, dict.fromkeys(COUNTERS, 0))
        outcomes, used_logs, admissions, frontends, used_sessions = [], set(), set(), {}, {}
        for req, expected in zip(requests, spec["requests"]):
            rid = request_id(req["request_id"])
            require(rid not in seen_ids, f"duplicate request ID {rid}")
            seen_ids.add(rid)
            require(req["path"] == expected["path"] and type(req["batch"]) is int
                    and req["batch"] == expected["batch"], f"{rid}: request/declaration mapping mismatch")
            body = payload(req["body_hex"])
            require(len(body) == size, f"{rid}: request payload length mismatch")
            require(rid in logs, f"{rid}: missing gateway request ID")
            row = logs[rid]
            used_logs.add(rid)
            client = req["client"]
            port = integer(client["local_port"], 1, 65535, "client source port")
            require(row["cp"] == str(port) and row["path"] == req["path"],
                    f"{rid}: gateway source port/path mismatch")
            require(client["tls_version"] == row["fp"] == "TLSv1.3"
                    and client["session_reused"] is False and row["fr"] == "0",
                    f"{rid}: front TLS version/resumption mismatch")
            require(client["certificate_verified"] is True and client["expected_dns_name"] == "proxy.test"
                    and fingerprint(client["peer_certificate_sha256"]) == certificates["proxy"],
                    f"{rid}: unauthenticated client-to-gateway TLS")
            require(client["exception"] is None, f"{rid}: client exception leaves incomplete evidence")
            F = group(row["fc"])
            require(F == (H if spec["client_mode"] == "H" else C),
                    f"{rid}: observed front group disagrees with declared client mode")
            front = (F, client["tls_version"], client["peer_certificate_sha256"].lower())
            require(port not in frontends or frontends[port] == front, f"{rid}: inconsistent front session mapping")
            frontends[port] = front
            status = integer(client["http_status"], 100, 599, "HTTP status")
            require(status in (200, 403, 503) and row["status"] == str(status),
                    f"{rid}: gateway/client status mismatch or unsupported status")
            B = None if row["bc"] == "-" else group(row["bc"])
            require(row["bp"] in ("-", "TLSv1.3") and row["br"] in ("-", "0"),
                    f"{rid}: backend TLS version/resumption mismatch")
            if row["cert"] != "-":
                require(fingerprint(row["cert"]) == certificates["origin"], f"{rid}: gateway backend certificate mismatch")
            origin, cid = ("legacy" if req["path"] == "/compat" else "restricted"), None
            if status == 200:
                require(B is not None and row["bp"] == "TLSv1.3" and row["br"] == "0"
                        and row["cert"] != "-", f"{rid}: missing backend TLS evidence for admission")
                require(row["backend"] == origin and rid in accepted and accepted[rid][0] == origin,
                        f"{rid}: wrong origin or missing application acceptance")
                event = accepted[rid][1]
                cid = event["connection_id"]
                require(event["path"] == req["path"] and payload(event["body_hex"]) == body,
                        f"{rid}: origin payload/path mismatch")
                tls = origins[origin][0][cid]
                require(group(tls["group"]) == B, f"{rid}: gateway/origin TLS session mismatch")
                response_cid = client["response_origin_connection"]
                require((type(response_cid) is int and response_cid == cid)
                        or (isinstance(response_cid, str) and response_cid == str(cid)),
                        f"{rid}: client/origin connection mapping mismatch")
                require(client["response_request_id"] == rid and payload(client["response_hex"]) == body,
                        f"{rid}: client echo/request ID mismatch")
                admissions.add(rid)
                key = (origin, cid)
                session = used_sessions.setdefault(key, dict(case_id=sid, origin=origin, connection_id=cid,
                                                            group=B, request_ids=[], local_ports=set()))
                session["request_ids"].append(rid)
                session["local_ports"].add(port)
            else:
                require(rid not in accepted, f"{rid}: rejected request reached application acceptance")
                require(client["response_request_id"] is None and client["response_origin_connection"] is None,
                        f"{rid}: rejection has an origin echo identity")
                payload(client["response_hex"])
                if status == 503:
                    origin_tls = origins[origin][0].values()
                    require(row["backend"] == origin, f"{rid}: 503 selected origin mismatch")
                    require(not any(event["ok"] for event in origin_tls),
                            f"{rid}: 503 selected origin has successful TLS")
                    require(any(event["no_shared_group"] is True for event in origin_tls),
                            f"{rid}: 503 lacks selected-origin group-refusal evidence")
            mask = (1 if F == H else 0) | (2 if B == H else 0)
            available = expected["allowed_under_declared_requirement"]
            if status == 200:
                verdict = "admitted_conforming" if mask & expected["required_mask"] == expected["required_mask"] else "admitted_violation"
            else:
                verdict = "rejected_available" if available else "rejected_unavailable"
            matched = status == expected["expected_http_status"]
            outcomes.append(dict(case_id=sid, policy=policy, request_id=rid, path=req["path"], batch=req["batch"],
                                 local_port=port, origin=origin, connection_id=cid, front_group=F, backend_group=B,
                                 required_mask=expected["required_mask"], observed_mask=mask,
                                 allowed_under_declared_requirement=available, http_status=status,
                                 classification=verdict, expected_http_status=expected["expected_http_status"],
                                 expectation_matched=matched))
            counters["requests"] += 1
            counters["admitted"] += status == 200
            counters["violations"] += verdict == "admitted_violation"
            counters["overblocked"] += verdict == "rejected_available"
            counters["rejected_unavailable"] += verdict == "rejected_unavailable"
            counters["expectation_mismatches"] += not matched
        require(used_logs == set(logs), f"{sid}: unmatched gateway request IDs")
        require(admissions == set(accepted), f"{sid}: unmatched origin request IDs")
        for session in used_sessions.values():
            session["local_ports"] = sorted(session["local_ports"])
            sessions.append(session)
        cases.append(dict(id=sid, policy=policy, requests=outcomes))
    totals = {key: sum(counts[key] for counts in by_policy.values()) for key in COUNTERS}
    return dict(schema_version=1, status="audited", by_policy=by_policy, totals=totals, cases=cases,
                sessions=sessions, pooled_sessions=sum(len(s["request_ids"]) > 1 for s in sessions),
                cross_frontend_reuse=sum(len(s["local_ports"]) > 1 for s in sessions),
                declaration_sha256=declaration_hash, source_sha256=sources.copy(),
                retained_file_hashes_verified=False,
                assurance="Trusted native source authenticity; no remote attestation. Origin application acceptance is the boundary.",
                limitations="No gateway internal accepted-write timing, latency or population completeness claim.")


def load_record(run_directory):
    """Load results.json, declaration.json and source/<filename> without changing them."""
    root = Path(run_directory)
    try:
        raw = (root / "results.json").read_bytes()
        record = parse_json(raw)
        declared_bytes = (root / "declaration.json").read_bytes()
        require(exact(parse_json(declared_bytes), record["declaration"]), "retained declaration differs from record")
        require(digest(declared_bytes) == fingerprint(record["declaration_sha256"]), "retained declaration hash mismatch")
        # Validate filenames and schema before reading any collector-supplied path.
        audit(record)
        for name, value in record["source_sha256"].items():
            source = root / "source" / name
            require(not source.is_symlink() and source.is_file(), f"missing regular retained source: {name}")
            require(digest(source.read_bytes()) == fingerprint(value), f"retained source hash mismatch: {name}")
        return record
    except ValidationError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise ValidationError(f"cannot load run evidence: {error}") from error


def tex_table(summary):
    lines = [r"\begingroup\scriptsize", r"\setlength{\tabcolsep}{3pt}",
             r"\begin{tabular}{@{}lrrrrrr@{}}", r"\hline",
             r"Policy & $N$ & Adm. & Viol. & Over. & Unav. & $\Delta$ exp. \\", r"\hline"]
    for policy, counts in sorted(summary["by_policy"].items()):
        lines.append(policy.replace("_", r"\_") + " & " + " & ".join(str(counts[k]) for k in COUNTERS) + r" \\")
    return "\n".join(lines + [r"\hline", r"\end{tabular}", r"\endgroup", ""])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--out", required=True, type=Path, help="new directory; existing paths are refused")
    args = parser.parse_args(argv)
    try:
        record = load_record(args.run_directory)
        summary = audit(record)
        summary["retained_file_hashes_verified"] = True
        summary["record_sha256"] = digest((args.run_directory / "results.json").read_bytes())
        summary["auditor_sha256"] = digest(Path(__file__).resolve().read_bytes())
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        with (args.out / "request_outcomes.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for case in summary["cases"]:
                writer.writerows(case["requests"])
        (args.out / "application_results.tex").write_text(tex_table(summary), encoding="utf-8")
    except (ValidationError, OSError) as error:
        print(f"HTTP audit failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary["totals"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
