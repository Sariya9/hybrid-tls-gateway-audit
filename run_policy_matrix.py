#!/usr/bin/env python3
"""Run the predeclared local TLS policy matrix into a NEW output directory.
Usage: python3 run_policy_matrix.py --out /path/to/new-run
Requires Python stdlib, a C compiler and OpenSSL >=3.5 headers/library/CLI.
Set OPENSSL_PREFIX if autodiscovery fails. No installation or external endpoints.
"""
import argparse
import re
import shutil
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", type=Path, required=True)
ARGS = parser.parse_args()
OUT = ARGS.out.resolve()
OUT.mkdir(parents=True, exist_ok=False)
MATRIX_BYTES = (HERE / "policy_matrix.json").read_bytes()
MATRIX = json.loads(MATRIX_BYTES)
(OUT / "declared_matrix.json").write_bytes(MATRIX_BYTES)
REDACTIONS = [(str(HERE), "$SRC")]
def redact(text):
    for actual, label in REDACTIONS:
        text = text.replace(actual, label)
    return text
HYBRID = "X25519MLKEM768"
CLASSICAL = "X25519"
PREFIX = b"origin-response\0"
TRACE = []
RESULT = {"status": "failed", "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "platform": platform.platform(), "python": sys.version, "cases": []}


def command(args, cwd):
    args = list(map(str, args))
    TRACE.append("$ " + redact(shlex.join(args)))
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        TRACE.extend(["COMMAND TIMEOUT (failure)", str(exc.stdout), str(exc.stderr)])
        raise
    TRACE.extend([p.stdout, p.stderr, f"exit={p.returncode}"])
    if p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {shlex.join(args)}")
    return p.stdout


def credentials(work, openssl):
    result = {}
    for serial, name in enumerate(("proxy", "origin"), 1):
        ca = work / f"{name}-ca"
        leaf = work / name
        command([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-noenc", "-sha256", "-days", "1", "-subj", f"/CN=probe-{name}-CA",
                 "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", f"{ca}.key", "-out", f"{ca}.crt"], work)
        command([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-noenc", "-subj", f"/CN={name}.test", "-keyout", f"{leaf}.key",
                 "-out", f"{leaf}.csr"], work)
        ext = work / f"{name}.ext"
        ext.write_text(f"subjectAltName=DNS:{name}.test\n"
                       "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                       "authorityKeyIdentifier=keyid,issuer\n")
        command([openssl, "x509", "-req", "-in", f"{leaf}.csr", "-CA", f"{ca}.crt",
                 "-CAkey", f"{ca}.key", "-set_serial", serial, "-days", "1", "-sha256",
                 "-extfile", ext, "-out", f"{leaf}.crt"], work)
        command([openssl, "verify", "-CAfile", f"{ca}.crt", "-verify_hostname", f"{name}.test",
                 "-purpose", "sslserver", f"{leaf}.crt"], work)
        details = command([openssl, "x509", "-in", f"{leaf}.crt", "-noout", "-subject",
                           "-issuer", "-serial", "-dates", "-ext", "subjectAltName"], work)
        public_key = command([openssl, "x509", "-in", f"{leaf}.crt", "-noout", "-pubkey"], work)
        pem = Path(f"{leaf}.crt").read_text()
        result[name] = {"hostname": f"{name}.test", "details": details,
                        "sha256": hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest(),
                        "public_key_pem": public_key, "certificate_pem": pem,
                        "ca_pem": Path(f"{ca}.crt").read_text()}
    assert result["proxy"]["sha256"] != result["origin"]["sha256"]
    assert result["proxy"]["public_key_pem"] != result["origin"]["public_key_pem"]
    assert result["proxy"]["ca_pem"] != result["origin"]["ca_pem"]
    for item in result.values():
        item["public_key_sha256"] = hashlib.sha256(item.pop("public_key_pem").encode()).hexdigest()
        item.pop("certificate_pem")
        item.pop("ca_pem")
    return result


def run_case(work, binary, spec):
    name = spec["id"]
    backend, origin_groups = spec["backend_groups"], spec["origin_groups"]
    trusted, host = spec["trusted_proxy"], spec["origin_hostname"]
    guard_mask = spec["required_mask"] if spec["release_guard"] else 0
    case = {"name": name, "status": "failed", "configuration": {
        "client_groups": spec["client_groups"], "proxy_front_groups": spec["front_groups"],
        "proxy_backend_groups": backend, "origin_groups": origin_groups,
        "client_ca": "proxy-ca" if trusted else "origin-ca",
        "client_hostname": "proxy.test", "backend_ca": "origin-ca", "backend_hostname": host,
        "front_sni": "proxy.test", "backend_sni": "origin.test"},
        "processes": {}, "declared_policy": spec["required_mask"], "guard_enabled": spec["release_guard"], "expected": spec["expected"]}
    RESULT["cases"].append(case)
    processes = {}
    TRACE.append(f"\nCASE {name}\n{json.dumps(case['configuration'], sort_keys=True)}")
    with contextlib.ExitStack() as stack:
        listeners = []
        for _ in range(2):
            s = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            listeners.append(s)
        front, origin = listeners
        case["listeners"] = {"front": list(front.getsockname()), "origin": list(origin.getsockname())}
        read_cancel, write_cancel = os.pipe()
        stack.callback(os.close, read_cancel)
        cancel_open = True

        def start(role, args, fds=()):
            out = stack.enter_context((work / f"{name}.{role}.out").open("w+"))
            err = stack.enter_context((work / f"{name}.{role}.err").open("w+"))
            cmd = list(map(str, [binary, role, *args]))
            p = subprocess.Popen(cmd, cwd=work, stdout=out, stderr=err, pass_fds=fds)
            processes[role] = (p, out, err)
            case["processes"][role] = {"command": cmd, "pid": p.pid, "timed_out": False,
                                        "cleanup_signal": None}

        try:
            start("origin", [origin.fileno(), read_cancel, origin_groups, work / "origin.crt",
                             work / "origin.key"], (origin.fileno(), read_cancel))
            start("proxy", [front.fileno(), origin.getsockname()[1], spec["front_groups"], backend,
                            work / "proxy.crt", work / "proxy.key", work / "origin-ca.crt", host, guard_mask],
                  (front.fileno(),))
            start("client", [front.getsockname()[1], spec["client_groups"],
                             work / ("proxy-ca.crt" if trusted else "origin-ca.crt"),
                             "proxy.test", work / "request.bin"])
            front.close()
            origin.close()
            deadline = time.monotonic() + 18
            # Only cancel an idle origin after both other processes have exited.
            # This is explicit cancellation, not evidence of a TLS rejection.
            for role in ("client", "proxy"):
                try:
                    processes[role][0].wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    case["processes"][role]["timed_out"] = True
                    raise
            os.close(write_cancel)
            cancel_open = False
            try:
                processes["origin"][0].wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                case["processes"]["origin"]["timed_out"] = True
                raise
        finally:
            if cancel_open:
                os.close(write_cancel)
            # No child survives an assertion, exception or interrupted run.
            for role, (p, out, err) in processes.items():
                record = case["processes"][role]
                if p.poll() is None:
                    p.terminate()
                    record["cleanup_signal"] = "SIGTERM"
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        record["cleanup_signal"] = "SIGKILL"
                p.wait(timeout=2)
                out.seek(0)
                err.seek(0)
                stdout, stderr = out.read(), err.read()
                record.update(exit=p.returncode, reaped=p.poll() is not None, stderr=stderr)
                TRACE.extend([f"[{name}/{role}] $ {shlex.join(record['command'])}",
                              "stdout:\n" + stdout, "stderr:\n" + stderr,
                              f"exit={p.returncode} cleanup={record['cleanup_signal']}"])
                record["stdout"] = stdout
    # Parse after cleanup so malformed output cannot interrupt child reaping.
    for record in case["processes"].values():
        record["events"] = [json.loads(line) for line in record.pop("stdout").splitlines()]
        assert not record["timed_out"] and record["cleanup_signal"] is None and record["reaped"]
        assert record["exit"] in (0, 20, 21, 23), record
    return case


def events(case, role, event, leg=None):
    return [e for e in case["processes"][role]["events"]
            if e["event"] == event and (leg is None or e.get("leg") == leg)]


def one(case, role, event, leg):
    found = events(case, role, event, leg)
    assert len(found) == 1, (case["name"], role, event, leg, found)
    return found[0]


def check_handshake(case, role, leg, group, ok=True, verify=0):
    h = one(case, role, "handshake", leg)
    assert h["ok"] is ok and h["verify_code"] == verify, h
    assert not h["session_reused"], h
    if ok:
        assert h["protocol"] == "TLSv1.3" and h["group"].casefold() == group.casefold() and h["group_id"] > 0, h
        initiator = role == "client" or (role == "proxy" and leg == "backend")
        cert_role = "proxy" if leg == "front" else "origin"
        cert = one(case, role, "certificate", leg)
        assert cert["sha256"] == RESULT["credentials"][cert_role]["sha256"], cert
        if initiator:
            assert h["certificate_status"] == "verified", h
            assert h["verified_hostname"] == f"{cert_role}.test", h
            received = {e["type"] for e in events(case, role, "handshake_message", leg)
                        if e["direction"] == "received"}
            assert {11, 15, 20} <= received, received  # Certificate, CertificateVerify, Finished.
        else:
            hellos = events(case, role, "client_hello", leg)
            assert hellos and all(not e["psk_offered"] for e in hellos)
            assert any(e["type"] == 20 and e["direction"] == "received"
                       for e in events(case, role, "handshake_message", leg))
    return h


def alert(case, role, leg, direction, description):
    assert any(e["direction"] == direction and e["level"] == 2 and e["description"] == description
               for e in events(case, role, "alert", leg)), (role, leg, description)


def policy_ok(mask, front, backend):
    return (not mask & 1 or front.casefold() == HYBRID.casefold()) and (
            not mask & 2 or backend.casefold() == HYBRID.casefold())


def validate_matrix():
    assert MATRIX["schema_version"] == 1 and MATRIX["expected_outcomes_declared_before_runs"]
    ids = [r["id"] for r in MATRIX["cases"]]
    assert len(ids) == len(set(ids)) == 16
    for r in MATRIX["cases"]:
        assert re.fullmatch(r"[MT][0-9]{2}", r["id"])
        assert r["required_mask"] in (0, 1, 2, 3)
        assert type(r["release_guard"]) is bool and type(r["trusted_proxy"]) is bool
        assert r["origin_hostname"] in ("origin.test", "wrong-origin.test")
        for key in ("client_groups", "front_groups", "backend_groups", "origin_groups"):
            assert r[key] in (HYBRID, CLASSICAL, HYBRID + ":" + CLASSICAL)
    # Explicit boundaries of the independent release predicate.
    assert policy_ok(0, CLASSICAL, CLASSICAL)
    assert policy_ok(1, HYBRID, CLASSICAL) and not policy_ok(1, CLASSICAL, HYBRID)
    assert policy_ok(2, CLASSICAL, HYBRID) and not policy_ok(2, HYBRID, CLASSICAL)
    assert policy_ok(3, HYBRID, HYBRID)
    assert not policy_ok(3, HYBRID, CLASSICAL) and not policy_ok(3, CLASSICAL, HYBRID)
    assert not policy_ok(3, CLASSICAL, CLASSICAL)


def check_offers(case):
    ids = {HYBRID:4588, CLASSICAL:29}
    for role, leg, field in (("proxy","front","client_groups"),
                             ("origin","backend","proxy_backend_groups")):
        offered = events(case, role, "offered_groups", leg)
        if events(case, role, "accepted"):
            assert offered, (case["name"], role, "missing offered groups")
        for e in offered:
            wanted = [ids[g] for g in case["configuration"][field].split(":")]
            assert e["iana_ids"] == wanted, (case["name"], e, wanted)
        shares = events(case, role, "offered_key_shares", leg)
        assert len(shares) == len(offered)
        for share in shares:
            assert set(share["iana_ids"]) <= set(wanted)
    for role in case["processes"]:
        assert all(not e["psk_offered"] for e in events(case, role, "client_hello"))
        assert all(e["type"] != 4 for e in events(case, role, "handshake_message"))


def check_case(case, request):
    processes = case["processes"]
    check_offers(case)
    front = one(case, "client", "handshake", "front")
    proxy_front = one(case, "proxy", "handshake", "front")
    delivered = bool(events(case, "client", "exact_response_verified"))
    payload_attempts = [e for role in processes for e in events(case, role, "payload_write_attempt")]
    payload_frames = [e for role in processes for e in events(case, role, "frame")
                      if e["kind"] in ("request","response")]
    payload_progress = [e for role in processes for e in events(case, role, "write_progress")
                        if e["kind"] in ("request","response")]
    backend_events = events(case, "proxy", "handshake", "backend")
    backend = backend_events[0] if backend_events else None
    F = front["group"] if front["ok"] else None
    B = backend["group"] if backend and backend["ok"] else None

    # Classify observed failures from specific TLS or release evidence, not expectation.
    if not front["ok"]:
        assert not proxy_front["ok"] and not backend_events
        assert events(case, "origin", "origin_cancelled_before_accept")
        assert not events(case, "origin", "accepted")
        if front["verify_code"] == 20:
            stage = "front_ca_rejected"
            alert(case, "client", "front", "sent", 48)
            alert(case, "proxy", "front", "received", 48)
        else:
            stage = "front_group_rejected"
            err = one(case, "proxy", "tls_error", "front")
            assert err["no_shared_group"]
            alert(case, "proxy", "front", "sent", 40)
            alert(case, "client", "front", "received", 40)
        exits = {"client":20, "proxy":20, "origin":0}
    else:
        check_handshake(case, "client", "front", F)
        check_handshake(case, "proxy", "front", F)
        assert backend is not None and events(case, "origin", "accepted")
        if not backend["ok"]:
            if backend["verify_code"] == 62:
                stage = "backend_name_rejected"
                err = one(case, "proxy", "tls_error", "backend")
                assert err["reason"] == "certificate verify failed"
                alert(case, "proxy", "backend", "sent", 42)
                alert(case, "origin", "backend", "received", 42)
            else:
                stage = "backend_group_rejected"
                err = one(case, "origin", "tls_error", "backend")
                assert err["no_shared_group"]
                alert(case, "origin", "backend", "sent", 40)
                alert(case, "proxy", "backend", "received", 40)
            exits = {"client":21,"proxy":20,"origin":20}
        else:
            check_handshake(case, "proxy", "backend", B)
            check_handshake(case, "origin", "backend", B)
            gate = events(case, "proxy", "release_policy")
            assert len(gate) == 1
            gate = gate[0]
            mask = case["declared_policy"] if case["guard_enabled"] else 0
            assert gate["guard_mask"] == mask and gate["allowed"] == policy_ok(mask,F,B)
            if not gate["allowed"]:
                stage = "release_blocked"
                exits = {"client":21,"proxy":23,"origin":21}
                for role, leg in (("client","front"),("origin","backend")):
                    err = one(case, role, "tls_error", leg)
                    assert err["ssl_error"] == 6 and err["errno"] == 0 and err["reason"] == "none"
                assert all(not any(e["level"] == 2 for e in events(case,r,"alert")) for r in processes)
            else:
                stage = "delivered"
                exits = dict.fromkeys(processes,0)
                response = PREFIX + request
                for kind, expected, route in (
                    ("request",request,(("client","front","sent"),("proxy","front","received"),
                                        ("proxy","backend","sent"),("origin","backend","received"))),
                    ("response",response,(("origin","backend","sent"),("proxy","backend","received"),
                                          ("proxy","front","sent"),("client","front","received")))):
                    for role,leg,direction in route:
                        found=[e for e in events(case,role,"frame",leg)
                               if e["kind"]==kind and e["direction"]==direction]
                        assert len(found)==1 and found[0]["hex"]==expected.hex()
                        assert found[0]["bytes"]==len(expected)
                assert delivered and len(payload_attempts)==4 and len(payload_frames)==8
                assert sum(e["bytes"] for e in payload_progress if e["part"]=="payload") == 2*(len(request)+len(response))
                assert sum(e["bytes"] for e in payload_progress if e["part"]=="header") == 16
                for role in processes:
                    ev = processes[role]["events"]
                    first_release = next(i for i,e in enumerate(ev) if e["event"]=="payload_write_attempt")
                    assert all(i < first_release for i,e in enumerate(ev) if e["event"]=="handshake")
                ev = processes["proxy"]["events"]
                gate_index = next(i for i,e in enumerate(ev) if e["event"]=="release_policy")
                assert all(i > gate_index for i,e in enumerate(ev) if e["event"] in ("frame","write_progress","payload_write_attempt"))
                ev = processes["client"]["events"]
                ready_index = next(i for i,e in enumerate(ev) if e["event"]=="frame" and e["kind"]=="ready")
                assert all(i > ready_index for i,e in enumerate(ev) if e["event"]=="payload_write_attempt")
                assert events(case,"client","clean_eof","front")
                assert events(case,"proxy","clean_eof","backend")
                assert all(not events(case,r,"tls_error") for r in processes)
                assert all(not any(e["level"]==2 for e in events(case,r,"alert")) for r in processes)
        if stage in ("backend_name_rejected","backend_group_rejected"):
            err=one(case,"client","tls_error","front")
            assert err["ssl_error"]==6 and err["errno"]==0 and err["reason"]=="none"

    assert {r:p["exit"] for r,p in processes.items()}==exits
    if stage!="delivered":
        assert not delivered and not payload_attempts and not payload_frames and not payload_progress
        assert all(not events(case,r,"frame") for r in processes)
        assert all(not events(case,r,"write_progress") for r in processes)
    conforms = not payload_progress or (front["ok"] and backend and backend["ok"]
                                       and policy_ok(case["declared_policy"],F,B))
    verdict = ("satisfied_with_delivery" if delivered else "satisfied_by_rejection") if conforms else "violated"
    observed=dict(stage=stage,front_group=F,backend_group=B,delivered=delivered,
                  conformance=verdict,payload_write_attempts=len(payload_attempts),
                  correlated_payload_frames=len(payload_frames),
                  payload_bytes_accepted=sum(e["bytes"] for e in payload_progress if e["part"]=="payload"),
                  framing_bytes_accepted=sum(e["bytes"] for e in payload_progress if e["part"]=="header"))
    case["observed"]=observed
    exp=case["expected"]
    assert exits == exp["process_exits"]
    for k in ("stage","delivered","conformance"):
        assert observed[k]==exp[k], (case["name"],k,observed,exp)
    for k in ("front_group","backend_group"):
        assert (observed[k] or "").casefold()==(exp[k] or "").casefold(), (case["name"],k,observed,exp)
    case["status"]="expected_observation_matched"
    TRACE.append("OBSERVED "+case["name"]+" "+json.dumps(observed,sort_keys=True))
    print(case["name"],stage,verdict,flush=True)


def main():
    if not __debug__:
        raise RuntimeError("Assertions are required; do not run Python with -O")
    validate_matrix()
    fallback = Path("/opt/homebrew/opt/openssl@3")
    discovered = fallback if fallback.is_dir() else Path(shutil.which("openssl") or "/missing/bin/openssl").resolve().parent.parent
    prefix = Path(os.environ.get("OPENSSL_PREFIX", str(discovered)))
    openssl = prefix / "bin/openssl"
    cc = shlex.split(os.environ.get("CC", "cc"))
    RESULT["source_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in (HERE / "proxy_probe.c", Path(__file__), HERE / "policy_matrix.json")}
    RESULT["scope"] = {
        "transport": "IPv4 loopback only; three native processes per case",
        "tls": "TLS 1.3 only; fresh contexts; session cache, tickets and early data disabled",
        "authentication": "separate local P-256 CAs and leaf keys; CA and DNS SAN checks on both legs",
        "psk": "no PSK callbacks or saved sessions; servers reject any pre_shared_key extension",
        "limits": "one bounded synthetic exchange per predeclared case; policy conformance is distinct from expected observation",
        "timeouts": "3 s socket I/O; 5 s accept; 12 s process alarm; 18 s supervisor per case"}
    with tempfile.TemporaryDirectory(prefix="tls-proxy-probe-") as temp:
        work = Path(temp)
        REDACTIONS.append((str(work), "$TMP"))
        RESULT["matrix_sha256"] = hashlib.sha256(MATRIX_BYTES).hexdigest()
        RESULT["openssl_version"] = command([openssl, "version", "-a"], work)
        RESULT["compiler_version"] = command([*cc, "--version"], work)
        binary = work / "proxy_probe"
        build = [*cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
                 f"-I{prefix / 'include'}", HERE / "proxy_probe.c", f"-L{prefix / 'lib'}",
                 f"-Wl,-rpath,{prefix / 'lib'}", "-lssl", "-lcrypto", "-o", binary]
        RESULT["build_command"] = list(map(str, build))
        command(build, work)
        RESULT["native_version"] = command([binary, "version"], work)
        RESULT["credentials"] = credentials(work, openssl)
        request = b"proxy-probe-v1\0" + secrets.token_bytes(32) + bytes(range(256))
        (work / "request.bin").write_bytes(request)
        RESULT["payload"] = {"request_bytes": len(request), "request_hex": request.hex(),
                             "response_bytes": len(PREFIX + request), "response_hex": (PREFIX + request).hex()}
        for spec in MATRIX["cases"]:
            check_case(run_case(work, binary, spec), request)
    RESULT["temporary_files_removed"] = not work.exists()
    assert RESULT["temporary_files_removed"] and len(RESULT["cases"]) == len(MATRIX["cases"])
    RESULT["status"] = "passed"


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        RESULT["error"] = traceback.format_exc()
        TRACE.append(RESULT["error"])
        raise
    finally:
        RESULT["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        TRACE.append(f"OVERALL {RESULT['status'].upper()}")
        (OUT / "trace.txt").write_text(redact("\n".join(TRACE) + "\n"))
        (OUT / "results.json").write_text(redact(json.dumps(RESULT, indent=2) + "\n"))
