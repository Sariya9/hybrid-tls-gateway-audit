#!/usr/bin/env python3
"""One fresh unmodified HAProxy process per predeclared loopback exchange."""
import argparse
import contextlib
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

HERE = Path(__file__).resolve().parent
H, C = "X25519MLKEM768", "X25519"
PREFIX = b"origin-response\0"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Run:
    def __init__(self, args):
        self.args = args
        self.out = args.out.resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.trace = []
        self.redactions = [(str(HERE), "$SRC"), (str(args.haproxy.resolve()), "$HAPROXY")]
        self.result = dict(status="failed", started_utc=self.now(), cases=[],
                           platform=platform.platform(), python=sys.version,
                           temporal_property="not_certified; no READY; gateway internal writes uninstrumented")

    @staticmethod
    def now():
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def redact(self, text):
        for old, new in sorted(self.redactions, key=lambda x: -len(x[0])):
            text = text.replace(old, new)
        return text

    def command(self, args, work):
        args = list(map(str, args))
        self.trace.append("$ " + shlex.join(args))
        p = subprocess.run(args, cwd=work, capture_output=True, text=True, timeout=30)
        self.trace.extend([p.stdout, p.stderr, f"exit={p.returncode}"])
        if p.returncode:
            raise RuntimeError(f"command failed ({p.returncode}): {shlex.join(args)}")
        return dict(stdout=p.stdout, stderr=p.stderr, exit=p.returncode)

    def credentials(self, work, openssl):
        records = {}
        for serial, name in enumerate(("proxy", "origin"), 1):
            self.command([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-noenc", "-sha256", "-days", "1", "-subj", f"/CN=haproxy-{name}-CA",
                          "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                          "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                          "-keyout", f"{name}-ca.key", "-out", f"{name}-ca.crt"], work)
            self.command([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-noenc", "-subj", f"/CN={name}.test", "-keyout", f"{name}.key",
                          "-out", f"{name}.csr"], work)
            (work / f"{name}.ext").write_text(
                f"subjectAltName=DNS:{name}.test\nbasicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
            self.command([openssl, "x509", "-req", "-in", f"{name}.csr", "-CA", f"{name}-ca.crt",
                          "-CAkey", f"{name}-ca.key", "-set_serial", serial, "-days", "1", "-sha256",
                          "-extfile", f"{name}.ext", "-out", f"{name}.crt"], work)
            self.command([openssl, "verify", "-CAfile", f"{name}-ca.crt", "-verify_hostname",
                          f"{name}.test", "-purpose", "sslserver", f"{name}.crt"], work)
            details = self.command([openssl, "x509", "-in", f"{name}.crt", "-noout", "-subject",
                                    "-issuer", "-serial", "-dates", "-ext", "subjectAltName"], work)
            records[name] = dict(sha256=digest(ssl.PEM_cert_to_DER_cert((work / f"{name}.crt").read_text())),
                                 details=details["stdout"])
        assert records["proxy"]["sha256"] != records["origin"]["sha256"]
        (work / "proxy.pem").write_bytes((work / "proxy.crt").read_bytes() + (work / "proxy.key").read_bytes())
        return records

    @staticmethod
    def config(spec, front, back):
        # No backend SNI in either positive or negative case. Static verifyhost
        # is therefore the expected name, rather than an SNI-overridden value.
        return f'''global
    nbthread 1
    maxconn 2
    log stdout format raw local0 info
    stats socket unix@admin.sock level admin
defaults
    log global
    mode tcp
    timeout connect 2s
    timeout client 4s
    timeout server 4s
    retries 0
    log-format "case={spec['id']} fc=%[ssl_fc_curve] bc=%[ssl_bc_curve] fp=%[ssl_fc_protocol] bp=%[ssl_bc_protocol] fr=%[ssl_fc_is_resumed] br=%[ssl_bc_is_resumed] fe=%[ssl_fc_err] be=%[ssl_bc_err] bcname=%[bc_err_name] sni=%[ssl_bc_sni] cert=%[ssl_s_der,sha2(256),hex] term=%ts bytes=%B"
    error-log-format "case={spec['id']} fc=%[ssl_fc_curve] bc=- fp=%[ssl_fc_protocol] bp=- fr=%[ssl_fc_is_resumed] br=- fe=%[ssl_fc_err] be=- bcname=- sni=- cert=- term=frontend_error bytes=0"
frontend f
    bind 127.0.0.1:{front} ssl crt proxy.pem curves {spec['front_groups']} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-tls-tickets
    default_backend b
backend b
    server origin 127.0.0.1:{back} ssl verify required ca-file origin-ca.crt verifyhost {spec['origin_hostname']} curves {spec['backend_groups']} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse
'''

    @staticmethod
    def admin(work, command):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(.25)
            s.connect(str(work / "admin.sock"))
            s.sendall((command + "\n").encode())
            s.shutdown(socket.SHUT_WR)
            result = b""
            while part := s.recv(65536):
                result += part
            return result.decode()

    def run_case(self, work, endpoint, spec):
        case = dict(id=spec["id"], status="failed", specification=spec, processes={})
        self.result["cases"].append(case)
        processes = {}
        with contextlib.ExitStack() as stack:
            listener = stack.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                front = reservation.getsockname()[1]
            config = self.config(spec, front, listener.getsockname()[1])
            cfg = work / f"{spec['id']}.cfg"
            cfg.write_text(config)
            case["config_sha256"] = digest(cfg.read_bytes())
            case["config"] = config
            case["validation"] = self.command([self.args.haproxy, "-c", "-f", cfg.name], work)
            (self.out / f"{spec['id']}.cfg").write_text(config)
            cancel_r, cancel_w = os.pipe()
            stack.callback(os.close, cancel_r)
            cancel_open = True

            def start(role, args, fds=()):
                out = stack.enter_context((work / f"{role}.out").open("w+"))
                err = stack.enter_context((work / f"{role}.err").open("w+"))
                cmd = list(map(str, args))
                p = subprocess.Popen(cmd, cwd=work, stdout=out, stderr=err, pass_fds=fds)
                processes[role] = (p, out, err)
                case["processes"][role] = dict(command=cmd, pid=p.pid, timed_out=False, cleanup_signal=None)

            try:
                (work / "admin.sock").unlink(missing_ok=True)
                start("origin", [endpoint, "origin", listener.fileno(), cancel_r,
                                 spec["origin_groups"], "origin.crt", "origin.key"], (listener.fileno(), cancel_r))
                start("haproxy", [self.args.haproxy, "-db", "-f", cfg.name])
                deadline = time.monotonic() + 4
                while True:
                    if processes["haproxy"][0].poll() is not None:
                        raise RuntimeError("HAProxy exited before readiness")
                    try:
                        case["startup_info"] = self.admin(work, "show info")
                        assert "Version:" in case["startup_info"]
                        break
                    except (OSError, AssertionError):
                        if time.monotonic() > deadline:
                            raise RuntimeError("HAProxy admin readiness timeout")
                        time.sleep(.02)
                start("client", [endpoint, "client", front, spec["client_groups"],
                                 "proxy-ca.crt" if spec["trusted_proxy"] else "origin-ca.crt",
                                 "proxy.test", "request.bin"])
                listener.close()
                try:
                    processes["client"][0].wait(timeout=10)
                except subprocess.TimeoutExpired:
                    case["processes"]["client"]["timed_out"] = True
                    raise
                os.close(cancel_w); cancel_open = False
                try:
                    processes["origin"][0].wait(timeout=7)
                except subprocess.TimeoutExpired:
                    case["processes"]["origin"]["timed_out"] = True
                    raise
                # The gateway remains a service until explicitly stopped. Wait
                # for the exchange log, then use soft-stop. This is normal cleanup.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    processes["haproxy"][1].seek(0)
                    if f"case={spec['id']} " in processes["haproxy"][1].read():
                        break
                    time.sleep(.02)
                case["final_stats"] = self.admin(work, "show stat")
                case["gateway_stop"] = "SIGUSR1 soft-stop after endpoint completion"
                processes["haproxy"][0].send_signal(signal.SIGUSR1)
                processes["haproxy"][0].wait(timeout=3)
            finally:
                if cancel_open:
                    os.close(cancel_w)
                for role, (p, out, err) in processes.items():
                    rec = case["processes"][role]
                    if p.poll() is None:
                        rec["cleanup_signal"] = "SIGTERM"
                        p.terminate()
                        try:
                            p.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            rec["cleanup_signal"] = "SIGKILL"; p.kill()
                    p.wait(timeout=2)
                    out.seek(0); err.seek(0)
                    rec.update(exit=p.returncode, stdout=out.read(), stderr=err.read(), reaped=p.poll() is not None)
                    self.trace.extend([f"CASE {spec['id']} ROLE {role}", "$ " + shlex.join(rec["command"]),
                                       rec["stdout"], rec["stderr"], f"exit={rec['exit']}"])
        for role in ("client", "origin"):
            case["processes"][role]["events"] = [json.loads(x) for x in case["processes"][role]["stdout"].splitlines()]
        return case

    def check(self, case, request):
        spec = case["specification"]
        procs = case["processes"]
        for role, p in procs.items():
            assert p["reaped"] and not p["timed_out"] and p["cleanup_signal"] is None, (role, p)
            assert p["exit"] in ((0,) if role == "haproxy" else (0, 20, 21)), (role, p)
        ev = lambda role, kind: [e for e in procs[role]["events"] if e["event"] == kind]
        for role in ("client", "origin"):
            stamps = [e["monotonic_ns"] for e in procs[role]["events"]]
            assert stamps == sorted(stamps) and stamps
        hellos = ev("origin", "client_hello")
        assert all(not e["psk_offered"] for e in hellos)
        assert all(not e["present"] for e in ev("origin", "server_name_extension"))
        expected_iana = {H: 4588, C: 29}[spec["backend_groups"]]
        assert all(e["iana_ids"] == [expected_iana] for e in ev("origin", "offered_groups"))
        fhs = ev("client", "handshake"); bhs = ev("origin", "handshake")
        assert len(fhs) == 1 and len(bhs) <= 1
        f = fhs[0]; b = bhs[0] if bhs else None
        logs = [line for line in procs["haproxy"]["stdout"].splitlines() if line.startswith("case=")]
        assert len(logs) == 1, logs
        log = dict(item.split("=", 1) for item in logs[0].split())
        client_frames, origin_frames = ev("client", "frame"), ev("origin", "frame")
        delivered = bool(ev("client", "exact_response_verified"))
        F = f["group"] if f["ok"] else None
        B = b["group"] if b and b["ok"] and log["be"] == "0" else None
        norm = lambda v: None if v is None else {H.casefold(): H, C.casefold(): C}[v.casefold()]
        F, B = norm(F), norm(B)
        front_progress = [e for e in ev("client", "write_progress") if e["kind"] == "request"]
        origin_progress = [e for e in ev("origin", "read_progress") if e["kind"] == "request"]
        front_payload = sum(e["bytes"] for e in front_progress if e["part"] == "payload")
        origin_payload = sum(e["bytes"] for e in origin_progress if e["part"] == "payload")
        if f["ok"]:
            assert f["verify_code"] == 0 and f["certificate_status"] == "verified"
            assert f["verified_hostname"] == "proxy.test" and not f["session_reused"]
            assert ev("client", "certificate")[0]["sha256"] == self.result["credentials"]["proxy"]["sha256"]
            assert norm(log["fc"]) == F and log["fp"] == "TLSv1.3" and log["fr"] == "0"
        if b:
            local = [e for e in ev("origin", "certificate") if e["kind"] == "local"]
            assert len(local) == 1 and local[0]["sha256"] == self.result["credentials"]["origin"]["sha256"]
        if delivered:
            stage = "delivery"
            assert B is not None and b["protocol"] == "TLSv1.3" and not b["session_reused"]
            assert log["bp"] == "TLSv1.3" and log["br"] == "0" and norm(log["bc"]) == B
            assert log["cert"].lower() == self.result["credentials"]["origin"]["sha256"]
            assert log["sni"] == "-"
            assert ev("origin", "client_hello") and all(not e["psk_offered"] for e in ev("origin", "client_hello"))
            assert procs["client"]["exit"] == 0 and procs["origin"]["exit"] == 0
            assert len(client_frames) == 2 and len(origin_frames) == 2
            for frames in (client_frames, origin_frames):
                assert frames[0]["hex"] == request.hex() and frames[1]["hex"] == (PREFIX + request).hex()
            assert front_payload == origin_payload == len(request)
        elif not f["ok"]:
            assert not bhs and ev("origin", "origin_cancelled_before_accept")
            if f["verify_code"] == 20:
                stage = "front_ca_rejected"
                assert any(e["description"] == 48 for e in ev("client", "alert"))
            else:
                stage = "front_group_rejected"
                assert any(e["description"] == 40 for e in ev("client", "alert"))
            assert not front_progress and not origin_progress
        else:
            assert b and not b["ok"] and not origin_progress
            assert log["be"] != "0"
            errors = ev("origin", "tls_error")
            if any(e["no_shared_group"] for e in errors):
                stage = "backend_group_rejected"
            else:
                stage = "backend_hostname_rejected"
                assert spec["origin_hostname"] == "wrong-origin.test"
                assert log["bcname"] == "SSL_MISMATCH", log
                # HAProxy's own hostname callback rejects with an internal_error
                # alert here. Do not substitute the baseline probe's alert 42.
                assert any(e["direction"] == "received" and e["description"] == 80 for e in ev("origin", "alert"))
        route_ok = delivered and not ((spec["required_mask"] & 1 and F != H) or
                                     (spec["required_mask"] & 2 and B != H))
        observed = dict(stage=stage, delivered=delivered, front_group=F, backend_group=B,
                        delivered_route_classification=("requirements_met" if route_ok else "group_requirement_violated") if delivered else "not_delivered",
                        original_temporal_property="not_certified",
                        frontend_request_payload_bytes_accepted=front_payload,
                        frontend_request_framing_bytes_accepted=sum(e["bytes"] for e in front_progress if e["part"] == "header"),
                        origin_request_payload_bytes_received=origin_payload,
                        origin_request_framing_bytes_received=sum(e["bytes"] for e in origin_progress if e["part"] == "header"),
                        client_write_without_authenticated_backend=bool(front_progress and B is None),
                        first_client_write_ns=front_progress[0]["monotonic_ns"] if front_progress else None,
                        origin_handshake_observed_ns=b["monotonic_ns"] if b else None,
                        gateway_internal_accepted_backend_writes="not_instrumented", gateway_log=log)
        case["observed"] = observed
        for key, expected in spec["expected"].items():
            assert observed[key] == expected, (spec["id"], key, observed, expected)
        case["status"] = "expected_observation_matched"
        print(case["id"], stage, observed["delivered_route_classification"], front_payload, origin_payload, flush=True)

    def main(self):
        if not __debug__:
            raise RuntimeError("Do not use Python -O")
        matrix = (HERE / "matrix.json").read_bytes()
        declaration = json.loads(matrix)
        assert len(declaration["cases"]) == 9 and len({c["id"] for c in declaration["cases"]}) == 9
        for spec in declaration["cases"]:
            assert all(spec[k] in (H, C) for k in ("client_groups", "front_groups", "backend_groups", "origin_groups"))
            assert spec["origin_hostname"] in ("origin.test", "wrong-origin.test")
            assert type(spec["trusted_proxy"]) is bool and spec["required_mask"] in range(4)
        assert matrix == (HERE / "preregistration/matrix.initial.json").read_bytes()
        self.result["matrix_sha256"] = digest(matrix)
        (self.out / "declared_matrix.json").write_bytes(matrix)
        self.result["source_sha256"] = {p.name: digest(p.read_bytes()) for p in (HERE / "endpoints.c", Path(__file__), HERE / "matrix.json")}
        self.result["haproxy_binary_sha256"] = digest(self.args.haproxy.read_bytes())
        self.result["gateway_scope"] = "Unmodified HAProxy Community; loopback TCP SSL termination and SSL backend; same OpenSSL as baseline; static verifyhost without backend SNI"
        with tempfile.TemporaryDirectory(prefix="haproxy-study-", dir="/tmp") as temp:
            work = Path(temp)
            self.redactions.extend([(str(work), "$TMP"), (str(work.resolve()), "$TMP")])
            self.result["haproxy_version"] = self.command([self.args.haproxy, "-vv"], work)
            prefix = self.args.openssl_prefix
            self.result["openssl_version"] = self.command([prefix / "bin/openssl", "version", "-a"], work)
            self.result["compiler_version"] = self.command([self.args.cc, "--version"], work)
            endpoint = work / "endpoints"
            self.result["build"] = self.command([self.args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
                                                  f"-I{prefix / 'include'}", HERE / "endpoints.c", f"-L{prefix / 'lib'}",
                                                  f"-Wl,-rpath,{prefix / 'lib'}", "-lssl", "-lcrypto", "-o", endpoint], work)
            self.result["endpoint_version"] = self.command([endpoint, "version"], work)
            self.result["credentials"] = self.credentials(work, prefix / "bin/openssl")
            request = b"haproxy-probe-v1\0" + secrets.token_bytes(32) + bytes(range(256))
            (work / "request.bin").write_bytes(request)
            self.result["payload"] = dict(request_bytes=len(request), request_hex=request.hex(),
                                          response_bytes=len(PREFIX + request), response_hex=(PREFIX + request).hex())
            for spec in declaration["cases"]:
                self.check(self.run_case(work, endpoint, spec), request)
        self.result["temporary_files_removed"] = not work.exists()
        assert self.result["temporary_files_removed"]
        self.result["status"] = "passed"

    def save(self):
        self.result["finished_utc"] = self.now()
        (self.out / "trace.txt").write_text(self.redact("\n".join(self.trace) + "\n"))
        (self.out / "results.json").write_text(self.redact(json.dumps(self.result, indent=2) + "\n"))
        if self.result["status"] == "passed":
            rows = [dict(id=c["id"], required_mask=c["specification"]["required_mask"],
                         **{k: v for k, v in c["observed"].items() if k != "gateway_log"}) for c in self.result["cases"]]
            with (self.out / "outcomes.csv").open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0]))
                writer.writeheader(); writer.writerows(rows)
            summary = dict(cases=len(rows), delivered=sum(r["delivered"] for r in rows),
                           delivered_requirements_met=sum(r["delivered_route_classification"] == "requirements_met" for r in rows),
                           delivered_group_violations=sum(r["delivered_route_classification"] == "group_requirement_violated" for r in rows),
                           not_delivered=sum(not r["delivered"] for r in rows),
                           frontend_writes_without_authenticated_backend=[r["id"] for r in rows if r["client_write_without_authenticated_backend"]],
                           original_temporal_property="not_certified", results_sha256=digest((self.out / "results.json").read_bytes()))
            (self.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--haproxy", required=True, type=Path)
    parser.add_argument("--openssl-prefix", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    args = parser.parse_args()
    args.haproxy = args.haproxy.resolve()
    run = Run(args)
    try:
        run.main()
    except BaseException:
        run.result["error"] = traceback.format_exc()
        run.trace.append(run.result["error"])
        raise
    finally:
        run.save()
