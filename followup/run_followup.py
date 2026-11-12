#!/usr/bin/env python3
"""Follow-up experiments for the revised paper (run after the second review).

Part A, verification controls in HTTP mode
    Does the origin ever accept a request when the gateway cannot verify it?
    V1 uses the normal configuration, V2 gives the gateway the wrong expected
    host name, V3 gives it the wrong CA file.

Part B, scanner baseline
    What do testssl.sh and SSLyze report for three scenarios whose backend
    legs differ?
    S1 = scenario A01 of the paper (origin accepts hybrid and classical)
    S2 = scenario A03 of the paper (origin accepts classical only)
    S3 = new: origin accepts both, but the gateway offers classical only

Everything runs on loopback with synthetic data. The origin program is the
frozen origin_http.c from the reproducibility package and is not edited.
For the scan phase only, a second copy is compiled with a longer run time,
because the frozen origin stops by itself after 60 seconds.

Example:
    python3 -B run_followup.py \
        --package /path/to/extracted/reproducibility/package \
        --haproxy /path/to/haproxy \
        --testssl /path/to/testssl.sh \
        --sslyze /path/to/sslyze \
        --work /path/to/empty/scratch/dir \
        --out results/NEW_RUN_NAME
"""
import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

H, C = "X25519MLKEM768", "X25519"

# name: restricted origin groups, gateway restricted-backend groups,
#       expected host name the gateway checks, CA file the gateway trusts
SCENARIOS = {
    "V1": dict(part="A", origin=f"{H}:{C}", backend=f"{H}:{C}", verifyhost="origin.test", ca="origin-ca.crt",
               note="positive control, normal verification"),
    "V2": dict(part="A", origin=f"{H}:{C}", backend=f"{H}:{C}", verifyhost="wrong.test", ca="origin-ca.crt",
               note="gateway expects the wrong origin name"),
    "V3": dict(part="A", origin=f"{H}:{C}", backend=f"{H}:{C}", verifyhost="origin.test", ca="proxy-ca.crt",
               note="gateway trusts the wrong CA"),
    "S1": dict(part="B", origin=f"{H}:{C}", backend=f"{H}:{C}", verifyhost="origin.test", ca="origin-ca.crt",
               note="same as paper scenario A01"),
    "S2": dict(part="B", origin=C, backend=f"{H}:{C}", verifyhost="origin.test", ca="origin-ca.crt",
               note="same as paper scenario A03"),
    "S3": dict(part="B", origin=f"{H}:{C}", backend=C, verifyhost="origin.test", ca="origin-ca.crt",
               note="origin supports hybrid, gateway offers classical only"),
}
# Same request pattern as the paper's HTTP study: four requests on the first
# client connection, two on the second, alternating the two paths.
REQUESTS = [(0, "/compat"), (0, "/restricted"), (0, "/compat"), (0, "/restricted"),
            (1, "/compat"), (1, "/restricted")]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(args, cwd, timeout=60, check=True):
    done = subprocess.run(list(map(str, args)), cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if check and done.returncode:
        raise RuntimeError(f"command failed: {args}\n{done.stdout}\n{done.stderr}")
    return done


def make_credentials(work, openssl):
    """Two separate CAs and one P-256 server certificate each, valid for one day."""
    for serial, name in enumerate(("proxy", "origin"), 1):
        run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
             "-sha256", "-days", "1", "-subj", f"/CN=followup-{name}-CA",
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", f"{name}-ca.key", "-out", f"{name}-ca.crt"], work)
        run([openssl, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
             "-subj", f"/CN={name}.test", "-keyout", f"{name}.key", "-out", f"{name}.csr"], work)
        (work / f"{name}.ext").write_text(
            f"subjectAltName=DNS:{name}.test\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
        run([openssl, "x509", "-req", "-in", f"{name}.csr", "-CA", f"{name}-ca.crt", "-CAkey", f"{name}-ca.key",
             "-set_serial", serial, "-days", "1", "-sha256", "-extfile", f"{name}.ext", "-out", f"{name}.crt"], work)
    (work / "proxy.pem").write_bytes((work / "proxy.crt").read_bytes() + (work / "proxy.key").read_bytes())
    return {name: ssl.PEM_cert_to_DER_cert((work / f"{name}.crt").read_text()) for name in ("proxy", "origin")}


def gateway_config(spec, front, legacy, restricted):
    """The paper's support-only layout. Only the restricted backend line varies."""
    return f'''global
    nbthread 1
    maxconn 32
    log stdout format raw local0 info
    stats socket unix@admin.sock level admin
defaults
    mode http
    log global
    timeout connect 2s
    timeout client 5s
    timeout server 5s
    timeout http-keep-alive 5s
    retries 0
    option http-keep-alive
    log-format "AUDIT id=%[var(txn.audit_id)] path=%[var(txn.audit_path)] cp=%cp fc=%[ssl_fc_curve] bc=%[ssl_bc_curve] fp=%[ssl_fc_protocol] bp=%[ssl_bc_protocol] fr=%[ssl_fc_is_resumed] br=%[ssl_bc_is_resumed] be=%[ssl_bc_err] bcname=%[bc_err_name] cert=%[ssl_s_der,sha2(256),hex] backend=%b status=%ST term=%ts"
frontend front
    bind 127.0.0.1:{front} ssl crt proxy.pem curves {H}:{C} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-tls-tickets alpn http/1.1
    http-request set-var(txn.audit_id) req.hdr(X-Audit-ID)
    http-request set-var(txn.audit_path) path
    acl protected path -m str /restricted
    use_backend restricted if protected
    default_backend legacy
backend legacy
    http-reuse always
    server origin 127.0.0.1:{legacy} ssl verify required ca-file {spec["ca"]} verifyhost {spec["verifyhost"]} curves {C} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse no-sni-auto
backend restricted
    http-reuse always
    server origin 127.0.0.1:{restricted} ssl verify required ca-file {spec["ca"]} verifyhost {spec["verifyhost"]} curves {spec["backend"]} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse no-sni-auto
'''


class Stack:
    """Two origins and one gateway for one scenario."""

    def __init__(self, work, haproxy, origin_binary, name, spec):
        self.work, self.haproxy, self.binary, self.name, self.spec = work, haproxy, origin_binary, name, spec
        self.children, self.listeners, self.cancel = {}, {}, {}

    def start(self):
        for origin in ("legacy", "restricted"):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            self.listeners[origin] = listener
            read_end, write_end = os.pipe()
            groups = C if origin == "legacy" else self.spec["origin"]
            self.children[origin] = subprocess.Popen(
                [self.binary, origin, str(listener.fileno()), str(read_end), "origin.crt", "origin.key", groups],
                cwd=self.work, pass_fds=(listener.fileno(), read_end),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            os.close(read_end)
            self.cancel[origin] = write_end
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.front = reservation.getsockname()[1]
        self.ports = dict(front=self.front, legacy=self.listeners["legacy"].getsockname()[1],
                          restricted=self.listeners["restricted"].getsockname()[1])
        self.config = gateway_config(self.spec, self.front, self.ports["legacy"], self.ports["restricted"])
        (self.work / "gateway.cfg").write_text(self.config)
        run([self.haproxy, "-c", "-f", "gateway.cfg"], self.work)
        self.children["gateway"] = subprocess.Popen([self.haproxy, "-db", "-f", "gateway.cfg"], cwd=self.work,
                                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 3
        while True:
            if self.children["gateway"].poll() is not None:
                raise RuntimeError("gateway exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", self.front), .25):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.02)

    def stop(self):
        records = {}
        gateway = self.children.get("gateway")
        if gateway and gateway.poll() is None:
            gateway.send_signal(signal.SIGUSR1)
        for name in ("gateway", "legacy", "restricted"):
            child = self.children.get(name)
            if child is None:
                continue
            if name != "gateway":
                os.close(self.cancel[name])
            forced = False
            try:
                stdout, stderr = child.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                forced = True
                child.kill()
                stdout, stderr = child.communicate(timeout=2)
            records[name] = dict(stdout=stdout, stderr=stderr, exit=child.returncode, forced_kill=forced)
            if name != "gateway":
                records[name]["events"] = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
        for listener in self.listeners.values():
            listener.close()
        admin = self.work / "admin.sock"
        if admin.exists():
            admin.unlink()
        return records


def send_requests(work, front, scenario):
    """Six sequential POSTs through two client connections, as in the paper."""
    sent = []
    for batch in (0, 1):
        context = ssl.create_default_context(cafile=str(work / "proxy-ca.crt"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.hostname_checks_common_name = False
        context.options |= ssl.OP_NO_TICKET
        context.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection(("127.0.0.1", front), 4)
        tls = context.wrap_socket(raw, server_hostname="proxy.test")
        connection = http.client.HTTPSConnection("proxy.test", front, context=context, timeout=4)
        connection.sock = tls
        front_group = tls.group() if hasattr(tls, "group") else None
        try:
            for index, (request_batch, path) in enumerate(REQUESTS):
                if request_batch != batch:
                    continue
                request_id = f"{scenario}-r{index}-{secrets.token_hex(4)}"
                body = bytes(range(256)) + secrets.token_bytes(256)
                record = dict(request_id=request_id, path=path, batch=batch, body_sha256=sha(body),
                              client_local_port=tls.getsockname()[1], client_front_group=front_group)
                sent.append(record)
                try:
                    connection.request("POST", path, body=body,
                                       headers={"X-Audit-ID": request_id, "Content-Type": "application/octet-stream",
                                                "Connection": "keep-alive"})
                    response = connection.getresponse()
                    echoed = response.read()
                    record.update(http_status=response.status, echo_matches=echoed == body,
                                  origin_connection=response.getheader("X-Origin-Connection"))
                except Exception as error:  # a refused request may also close the connection
                    record.update(http_status=None, client_error=repr(error))
                    break
        finally:
            connection.close()
    return sent


def summarise_requests(sent, records):
    """Join each request to the gateway log line and to the origin's events."""
    log = {}
    for line in records["gateway"]["stdout"].splitlines():
        if line.startswith("AUDIT "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            log[fields.get("id")] = fields
    for origin in ("legacy", "restricted"):
        events = records[origin]["events"]
        completed = {e["connection_id"]: e for e in events if e["event"] == "tls" and e.get("ok")}
        for event in events:
            if event["event"] != "application_accept":
                continue
            for request in sent:
                if request["request_id"] == event.get("request_id"):
                    handshake = completed.get(event["connection_id"])
                    request.update(origin=origin, origin_connection_id=event["connection_id"],
                                   origin_group=handshake["group"] if handshake else None,
                                   origin_tls_before_accept=bool(handshake)
                                   and handshake["monotonic_ns"] < event["monotonic_ns"],
                                   ns_between_tls_and_accept=event["monotonic_ns"] - handshake["monotonic_ns"]
                                   if handshake else None)
    for request in sent:
        fields = log.get(request["request_id"], {})
        request.update(gateway_front_group=fields.get("fc"), gateway_backend_group=fields.get("bc"),
                       gateway_backend=fields.get("backend"), gateway_status=fields.get("status"),
                       gateway_backend_error=fields.get("be"), gateway_backend_error_name=fields.get("bcname"),
                       gateway_term=fields.get("term"), admitted_by_origin="origin" in request)
    return sent


def origin_counts(records):
    counts = {}
    for origin in ("legacy", "restricted"):
        events = records[origin]["events"]
        tls = [e for e in events if e["event"] == "tls"]
        counts[origin] = dict(tls_completed=sum(1 for e in tls if e.get("ok")),
                              tls_failed=sum(1 for e in tls if not e.get("ok")),
                              tls_failure_reasons=sorted({str(e.get("reason")) for e in tls if not e.get("ok")}),
                              application_accept=sum(1 for e in events if e["event"] == "application_accept"))
    return counts


def scan(tool, args, cwd, timeout):
    started = time.monotonic()
    try:
        done = subprocess.run(list(map(str, args)), cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return dict(tool=tool, exit=done.returncode, seconds=round(time.monotonic() - started, 1),
                    stdout=done.stdout, stderr=done.stderr)
    except subprocess.TimeoutExpired as error:
        return dict(tool=tool, exit=None, seconds=timeout, timed_out=True,
                    stdout=(error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes)
                    else (error.stdout or ""), stderr="")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--haproxy", type=Path, required=True)
    parser.add_argument("--testssl", type=Path, required=True)
    parser.add_argument("--sslyze", type=Path, required=True)
    parser.add_argument("--openssl-prefix", type=Path, default=Path("/opt/homebrew/opt/openssl@3"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--only", nargs="*", default=list(SCENARIOS))
    args = parser.parse_args()

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)      # never overwrite an earlier run
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    haproxy = args.haproxy.resolve()
    prefix = args.openssl_prefix.resolve()
    openssl = prefix / "bin/openssl"
    source = (args.package / "extensions/http_policy/origin_http.c").resolve()

    result = dict(started_utc=now(), platform=platform.platform(), python=sys.version,
                  python_ssl=ssl.OPENSSL_VERSION, scenarios={})
    try:
        build = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread",
                 f"-I{prefix / 'include'}", f"-L{prefix / 'lib'}", f"-Wl,-rpath,{prefix / 'lib'}"]
        run(build + [source, "-lssl", "-lcrypto", "-o", work / "origin_http"], work)
        # Scan-phase copy: identical except for the built-in 60 second run time.
        long_source = work / "origin_http_scan.c"
        text = source.read_text()
        assert text.count("#define RUN_SECONDS 60U") == 1
        long_source.write_text(text.replace("#define RUN_SECONDS 60U", "#define RUN_SECONDS 900U"))
        run(build + [long_source, "-lssl", "-lcrypto", "-o", work / "origin_http_scan"], work)
        result["runtime"] = dict(
            openssl=run([openssl, "version"], work).stdout.strip(),
            gateway=run([haproxy, "-v"], work).stdout.strip().splitlines()[0],
            gateway_sha256=sha(haproxy.read_bytes()),
            origin_source_sha256=sha(source.read_bytes()),
            scan_origin_change="RUN_SECONDS 60U -> 900U, nothing else",
            testssl=run(["git", "-C", args.testssl.resolve().parent, "log", "-1", "--format=%H %cI"], work,
                        check=False).stdout.strip(),
            sslyze=run([args.sslyze.parent / "python3", "-c",
                        "import importlib.metadata as m; print(m.version('sslyze'), m.version('nassl'))"],
                       work, check=False).stdout.strip())
        result["certificate_sha256"] = {k: sha(v) for k, v in make_credentials(work, openssl).items()}

        for name in args.only:
            spec = SCENARIOS[name]
            entry = dict(specification=spec)
            result["scenarios"][name] = entry
            raw = out / "raw" / name
            raw.mkdir(parents=True)

            # Phase 1: audited requests against the unmodified origin program.
            stack = Stack(work, haproxy, work / "origin_http", name, spec)
            sent = []
            try:
                stack.start()
                (out / f"{name}.cfg").write_text(stack.config)
                entry["ports"] = stack.ports
                sent = send_requests(work, stack.front, name)
            finally:
                records = stack.stop()
            entry["requests"] = summarise_requests(sent, records)
            entry["origin_counts"] = origin_counts(records)
            entry["process_exit"] = {k: dict(exit=v["exit"], forced_kill=v["forced_kill"]) for k, v in records.items()}
            for process, record in records.items():
                (raw / f"{process}.stdout.txt").write_text(record["stdout"])
                (raw / f"{process}.stderr.txt").write_text(record["stderr"])
            print(name, spec["note"], [r.get("http_status") for r in entry["requests"]],
                  [r.get("gateway_backend_group") for r in entry["requests"]], entry["origin_counts"], flush=True)

            # Phase 2 (Part B only): scanners against a fresh copy of the same setup.
            if spec["part"] != "B":
                continue
            stack = Stack(work, haproxy, work / "origin_http_scan", name, spec)
            entry["scans"] = {}
            try:
                stack.start()
                entry["scan_ports"] = stack.ports
                targets = {"frontend": ("proxy.test", stack.ports["front"]),
                           "origin": ("origin.test", stack.ports["restricted"])}
                for target, (host, port) in targets.items():
                    json_path = raw / f"testssl-{target}.json"
                    done = scan("testssl.sh", ["bash", args.testssl.resolve(), "--quiet", "--color", "0",
                                               "--warnings", "batch", "--openssl", openssl, "--ip", "127.0.0.1",
                                               "-p", "-f", "--jsonfile", json_path, f"{host}:{port}"], work, 420)
                    (raw / f"testssl-{target}.txt").write_text(done.pop("stdout") + "\n--- stderr ---\n" + done.pop("stderr"))
                    entry["scans"][f"testssl-{target}"] = done
                    json_path = raw / f"sslyze-{target}.json"
                    done = scan("sslyze", [args.sslyze.resolve(), "--tlsv1_3", "--elliptic_curves",
                                           "--json_out", json_path, f"127.0.0.1:{port}"], work, 240)
                    (raw / f"sslyze-{target}.txt").write_text(done.pop("stdout") + "\n--- stderr ---\n" + done.pop("stderr"))
                    entry["scans"][f"sslyze-{target}"] = done
                    print("  scanned", name, target, {k: (v["exit"], v["seconds"]) for k, v in entry["scans"].items()
                                                      if k.endswith(target)}, flush=True)
            finally:
                scan_records = stack.stop()
            entry["scan_process_exit"] = {k: dict(exit=v["exit"], forced_kill=v["forced_kill"])
                                          for k, v in scan_records.items()}
        result["status"] = "collected"
    finally:
        result["finished_utc"] = now()
        text = json.dumps(result, indent=2) + "\n"
        text = text.replace(str(work), "$WORK").replace(str(Path.home()), "$HOME")
        (out / "results.json").write_text(text)
        shutil.rmtree(work, ignore_errors=True)   # private keys are not kept
        for path in out.rglob("*.txt"):
            path.write_text(path.read_text().replace(str(work), "$WORK").replace(str(Path.home()), "$HOME"))


if __name__ == "__main__":
    main()
