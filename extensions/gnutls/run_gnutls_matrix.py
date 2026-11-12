#!/usr/bin/env python3
"""Native GnuTLS loopback policy matrix. No external test destinations.
Command/credential/supervisor helpers adapt ../run_policy_matrix.py unchanged in
TLS-independent behaviour; this runner never imports or executes its TLS code.
"""
import argparse, contextlib, datetime, hashlib, json, os, platform, re, secrets
import shlex, shutil, socket, ssl, subprocess, sys, tempfile, time, traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent
TRACE=[]
REDACTIONS=[(str(HERE),"$SRC"),(str(Path.home()),"$HOME")]
HYBRID="X25519MLKEM768"
CLASSICAL="X25519"
PREFIX=b"origin-response\0"
def redact(text):
    for actual,label in sorted(REDACTIONS,key=lambda x:-len(x[0])):
        text=text.replace(actual,label)
    return text

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
                record.update(exit=p.returncode, reaped=p.poll() is not None, stderr=stderr, stdout=stdout)
                TRACE.extend([f"[{name}/{role}] $ {shlex.join(record['command'])}",
                              "stdout:\n" + stdout, "stderr:\n" + stderr,
                              f"exit={p.returncode} cleanup={record['cleanup_signal']}"])
                record["stdout"] = stdout
    # Parse after cleanup so malformed output cannot interrupt child reaping.
    for record in case["processes"].values():
        record["events"] = [json.loads(line) for line in record["stdout"].splitlines()]
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

def policy_ok(mask, front, backend):
    return (not mask & 1 or front.casefold() == HYBRID.casefold()) and (
            not mask & 2 or backend.casefold() == HYBRID.casefold())

def native_group(name):
    mapping={'X25519-MLKEM768':HYBRID,'X25519':CLASSICAL,'none':None}
    if name not in mapping: raise ValueError('Unknown negotiated group: '+str(name))
    return mapping[name]

def check_case(case, request):
    ps=case['processes']
    for role,p in ps.items():
        assert p['reaped'] and not p['timed_out'] and p['cleanup_signal'] is None
        for h in events(case,role,'handshake'):
            assert not h['session_reused']
            if h['ok']:
                assert h['protocol']=='TLS1.3' and native_group(h['group']) in (HYBRID,CLASSICAL)
        assert all(not e['psk_offered'] for e in events(case,role,'client_hello'))
        assert all(e['type']!=4 for e in events(case,role,'handshake_message'))
    ch=one(case,'client','handshake','front')
    ph=one(case,'proxy','handshake','front')
    be=events(case,'proxy','handshake','backend'); bh=be[0] if be else None
    F=native_group(ch['group']) if ch['ok'] else None
    B=native_group(bh['group']) if bh and bh['ok'] else None
    for role,leg,h,cert_role in [('client','front',ch,'proxy'),('proxy','backend',bh,'origin')]:
        if h and h['ok']:
            assert h['verify_called'] and h['verify_code']==0 and h['certificate_status']=='verified'
            assert h['verified_hostname']==cert_role+'.test'
            v=one(case,role,'verification',leg)
            assert v['san_exact'] and v['server_purpose'] and v['status']==0 and v['rc']==0
            assert one(case,role,'certificate',leg)['sha256']==RESULT['credentials'][cert_role]['sha256']
            received={e['type'] for e in events(case,role,'handshake_message',leg) if e['direction']=='received'}
            assert {11,15,20}<=received,received
    # All wire offers must implement the declared list, even if GnuTLS changes key-share count/order.
    ids={HYBRID:4588,CLASSICAL:29}
    for role,leg,field in [('proxy','front','client_groups'),('origin','backend','proxy_backend_groups')]:
        offered=events(case,role,'offered_groups',leg)
        shares=events(case,role,'offered_key_shares',leg)
        if events(case,role,'accepted'): assert offered
        assert len(shares)==len(offered)
        for e in offered:
            assert set(e['iana_ids'])=={ids[g] for g in case['configuration'][field].split(':')}
        for e in shares: assert set(e['iana_ids']) <= {ids[g] for g in case['configuration'][field].split(':')}
    if not ch['ok']:
        assert not be and events(case,'origin','origin_cancelled_before_accept')
        assert not events(case,'origin','accepted')
        if ch['verify_called'] and ch['verify_code']:
            assert ch['verify_code'] & 64, ch  # GNUTLS_CERT_SIGNER_NOT_FOUND
            stage='front_ca_rejected'
        else:
            assert any(e['gnutls_rc']==-423 for e in events(case,'proxy','tls_error','front'))
            stage='front_group_rejected'
    else:
        assert ph['ok'] and native_group(ph['group'])==F and bh
        if not bh['ok']:
            if bh['verify_called'] and bh['verify_code']:
                assert bh['verify_code'] & (1<<14),bh  # GNUTLS_CERT_UNEXPECTED_OWNER
                stage='backend_name_rejected'
            else:
                assert any(e['gnutls_rc']==-423 for e in events(case,'origin','tls_error','backend'))
                stage='backend_group_rejected'
        else:
            oh=one(case,'origin','handshake','backend')
            assert oh['ok'] and native_group(oh['group'])==B
            gate=events(case,'proxy','release_policy'); assert len(gate)==1
            mask=case['declared_policy'] if case['guard_enabled'] else 0
            assert gate[0]['guard_mask']==mask and gate[0]['allowed']==policy_ok(mask,F,B)
            stage='delivered' if gate[0]['allowed'] else 'release_blocked'
    delivered=bool(events(case,'client','exact_response_verified'))
    progress=[e for r in ps for e in events(case,r,'write_progress') if e['kind'] in ('request','response')]
    frames=[e for r in ps for e in events(case,r,'frame') if e['kind'] in ('request','response')]
    attempts=[e for r in ps for e in events(case,r,'payload_write_attempt')]
    if stage=='delivered':
        assert delivered and len(attempts)==4 and len(frames)==8
        for kind,data,route in [
            ('request',request,[('client','front','sent'),('proxy','front','received'),('proxy','backend','sent'),('origin','backend','received')]),
            ('response',PREFIX+request,[('origin','backend','sent'),('proxy','backend','received'),('proxy','front','sent'),('client','front','received')])]:
            for role,leg,direction in route:
                e=[e for e in events(case,role,'frame',leg) if e['kind']==kind and e['direction']==direction]
                assert len(e)==1 and e[0]['bytes']==len(data) and e[0]['hex']==data.hex()
        assert sum(e['bytes'] for e in progress if e['part']=='payload')==2*(len(request)+len(PREFIX+request))
        assert sum(e['bytes'] for e in progress if e['part']=='header')==16
        assert all(p['exit']==0 for p in ps.values())
        for role in ps:
            ev=ps[role]['events']; first=next(i for i,e in enumerate(ev) if e['event']=='payload_write_attempt')
            assert all(i<first for i,e in enumerate(ev) if e['event']=='handshake')
        ev=ps['proxy']['events']; gate=next(i for i,e in enumerate(ev) if e['event']=='release_policy')
        assert all(i>gate for i,e in enumerate(ev) if e['event'] in ('frame','write_progress','payload_write_attempt'))
        ev=ps['client']['events']; ready=next(i for i,e in enumerate(ev) if e['event']=='frame' and e['kind']=='ready')
        assert all(i>ready for i,e in enumerate(ev) if e['event']=='payload_write_attempt')
        assert events(case,'client','clean_eof') and events(case,'proxy','clean_eof')
        assert all(not events(case,r,'tls_error') for r in ps)
    else:
        assert not delivered and not progress and not frames and not attempts
        assert all(not events(case,r,'frame') and not events(case,r,'write_progress') for r in ps)
    conforms=not progress or (ch['ok'] and bh and bh['ok'] and policy_ok(case['declared_policy'],F,B))
    verdict=('satisfied_with_delivery' if delivered else 'satisfied_by_rejection') if conforms else 'violated'
    obs=dict(stage=stage,front_group=F,backend_group=B,delivered=delivered,conformance=verdict,
        payload_write_attempts=len(attempts),correlated_payload_frames=len(frames),
        payload_bytes_accepted=sum(e['bytes'] for e in progress if e['part']=='payload'),
        framing_bytes_accepted=sum(e['bytes'] for e in progress if e['part']=='header'),
        native_process_exits={r:p['exit'] for r,p in ps.items()},
        offered_groups={r:events(case,r,'offered_groups') for r in ('proxy','origin')},
        key_shares={r:events(case,r,'offered_key_shares') for r in ('proxy','origin')},
        hello_retry_requests={r:events(case,r,'hello_retry_request') for r in ps})
    case['observed']=obs
    case['prediction_differences']={k:{'expected':v,'observed':obs[k]} for k,v in case['expected'].items() if obs[k]!=v}
    case['status']='prediction_differs' if case['prediction_differences'] else 'expected_observation_matched'
    print(case['name'],stage,verdict,case['status'],flush=True)

def main():
    global RESULT,OUT
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--matrix',type=Path,default=HERE/'matrix.exploratory.json')
    parser.add_argument('--prefix',type=Path,default=HERE/'.local/prefix')
    args=parser.parse_args();OUT=args.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
    data=args.matrix.read_bytes(); matrix=json.loads(data)
    assert __debug__ and len(matrix['cases'])==16 and len({c['id'] for c in matrix['cases']})==16
    assert matrix['phase'] in ('exploratory','confirmatory')
    assert matrix['declared_utc'] < datetime.datetime.now(datetime.timezone.utc).isoformat()
    (OUT/'declared_matrix.json').write_bytes(data)
    RESULT=dict(status='failed',phase=matrix['phase'],started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        matrix_sha256=hashlib.sha256(data).hexdigest(),platform=platform.platform(),python=sys.version,cases=[],
        scope='Local IPv4 loopback; native GnuTLS client, relay and origin; TLS1.3 certificate authentication; one cooperative synthetic exchange per case; no performance inference')
    try:
        prefix=args.prefix.resolve();REDACTIONS.append((str(prefix),'$GNUTLS'))
        RESULT['source_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE/'proxy_probe_gnutls.c',Path(__file__))}
        cc=shlex.split(os.environ.get('CC','cc'))
        openssl=Path('/opt/homebrew/opt/openssl@3/bin/openssl')
        with tempfile.TemporaryDirectory(prefix='gnutls-policy-') as temp:
            work=Path(temp);REDACTIONS.append((str(work),'$TMP'))
            RESULT['compiler_version']=command([*cc,'--version'],work)
            RESULT['credential_tool_version']=command([openssl,'version','-a'],work)
            binary=work/'proxy_probe_gnutls'
            build=[*cc,'-std=c11','-O2','-Wall','-Wextra','-Werror','-pedantic',f'-I{prefix / "include"}',HERE/'proxy_probe_gnutls.c',f'-L{prefix / "lib"}',f'-Wl,-rpath,{prefix / "lib"}','-lgnutls','-o',binary]
            RESULT['build_command']=list(map(str,build));command(build,work)
            RESULT['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
            RESULT['native_version']=command([binary,'version'],work)
            RESULT['binary_linkage']=command(['otool','-L',binary],work)
            RESULT['library_linkage']=command(['otool','-L',prefix/'lib/libgnutls.dylib'],work)
            RESULT['library_sha256']=hashlib.sha256((prefix/'lib/libgnutls.dylib').read_bytes()).hexdigest()
            RESULT['crypto_backend']={'pqc':'leancrypto 1.5.0; portable C with runtime self-tests',
                'classical':'Nettle/Hogweed 4.0 and GMP', 'liboqs':'not used; removed by upstream GnuTLS 3.8.10',
                'credential_generation':'OpenSSL CLI only; not used for TLS connections',
                'independence_limit':'Second TLS state-machine implementation; same macOS host, compiler, framing and supervision lineage. No claim of fully independent software/hardware trust base.'}
            RESULT['dependency_linkage']={}
            for label,path in [('leancrypto',prefix/'lib/libleancrypto.dylib'),
                               ('nettle',Path('/opt/homebrew/opt/nettle/lib/libnettle.dylib')),
                               ('hogweed',Path('/opt/homebrew/opt/nettle/lib/libhogweed.dylib')),
                               ('gmp',Path('/opt/homebrew/opt/gmp/lib/libgmp.dylib'))]:
                RESULT['dependency_linkage'][label]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'otool':command(['otool','-L',path],work)}
            RESULT['dependency_build_manifest_sha256']=hashlib.sha256((HERE/'dependency_build.json').read_bytes()).hexdigest()
            assert 'libssl' not in RESULT['binary_linkage'] and 'libcrypto' not in RESULT['library_linkage']
            RESULT['credentials']=credentials(work,openssl)
            request=b'proxy-probe-v1\0'+secrets.token_bytes(32)+bytes(range(256))
            (work/'request.bin').write_bytes(request)
            RESULT['payload']=dict(request_bytes=len(request),request_hex=request.hex(),response_bytes=len(PREFIX+request),response_hex=(PREFIX+request).hex())
            for spec in matrix['cases']:
                try:
                    case=run_case(work,binary,spec);check_case(case,request)
                except Exception:
                    # Preserve every case and continue exploratory collection instead of hiding later outcomes.
                    if RESULT['cases'] and RESULT['cases'][-1]['name']==spec['id']:
                        RESULT['cases'][-1]['check_error']=traceback.format_exc()
                    TRACE.append(traceback.format_exc());print(spec['id'],'CHECK FAILURE',flush=True)
            RESULT['temporary_files_removed']=not work.exists()
        RESULT['temporary_files_removed']=not work.exists()
        assert RESULT['temporary_files_removed']
        errors=[c['name'] for c in RESULT['cases'] if 'check_error' in c]
        differences=[c['name'] for c in RESULT['cases'] if c.get('prediction_differences')]
        RESULT['failed_checks']=errors;RESULT['prediction_differences']=differences
        RESULT['status']='failed' if errors else 'prediction_differences' if differences else 'passed'
    except BaseException:
        RESULT['error']=traceback.format_exc();TRACE.append(RESULT['error']);raise
    finally:
        RESULT['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT/'trace.txt').write_text(redact('\n'.join(TRACE)+'\n'))
        (OUT/'results.json').write_text(redact(json.dumps(RESULT,indent=2)+'\n'))
        raw=OUT/'raw';raw.mkdir()
        for c in RESULT['cases']:
            for role,p in c['processes'].items():
                for stream in ('stdout','stderr'):
                    (raw/f'{c["name"]}.{role}.{stream}.txt').write_text(redact(p.get(stream,'')))
    if RESULT['status']!='passed': sys.exit(1)

if __name__=='__main__':main()
