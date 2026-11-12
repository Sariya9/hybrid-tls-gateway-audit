#!/usr/bin/env python3
"""Collect bounded HTTP admission traces from unmodified HAProxy on loopback."""
import argparse
import datetime
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
H, C = 'X25519MLKEM768', 'X25519'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LoopbackHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def configuration(spec, front_port, legacy_port, restricted_port):
    policy = spec['policy']
    guard = ''
    if policy == 'blanket_hybrid':
        guard = '    http-request deny deny_status 403 if !front_hybrid\n'
    elif policy == 'route_aware':
        guard = '    http-request deny deny_status 403 if protected !front_hybrid\n'
    restricted_groups = f'{H}:{C}' if policy == 'support_only' else H
    legacy_groups = H if policy == 'blanket_hybrid' else C
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
    log-format "AUDIT id=%[var(txn.audit_id)] path=%[var(txn.audit_path)] cp=%cp fc=%[ssl_fc_curve] bc=%[ssl_bc_curve] fp=%[ssl_fc_protocol] bp=%[ssl_bc_protocol] fr=%[ssl_fc_is_resumed] br=%[ssl_bc_is_resumed] cert=%[ssl_s_der,sha2(256),hex] backend=%b status=%ST term=%ts"
frontend front
    bind 127.0.0.1:{front_port} ssl crt proxy.pem curves {H}:{C} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-tls-tickets alpn http/1.1
    http-request set-var(txn.audit_id) req.hdr(X-Audit-ID)
    http-request set-var(txn.audit_path) path
    acl protected path -m str /restricted
    acl front_hybrid ssl_fc_curve -m str {H}
{guard}    use_backend restricted if protected
    default_backend legacy
backend legacy
    http-reuse always
    server origin 127.0.0.1:{legacy_port} ssl verify required ca-file origin-ca.crt verifyhost origin.test curves {legacy_groups} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse
backend restricted
    http-reuse always
    server origin 127.0.0.1:{restricted_port} ssl verify required ca-file origin-ca.crt verifyhost origin.test curves {restricted_groups} ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3 no-ssl-reuse
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--haproxy', type=Path, required=True)
    parser.add_argument('--openssl-prefix', type=Path, default=Path('/opt/homebrew/opt/openssl@3'))
    args = parser.parse_args()
    if not __debug__:
        parser.error('Assertions must remain enabled')
    # Reuse the frozen credential and command helper; its original runner is not executed.
    helper_path = HERE.parent / 'haproxy/run_matrix.py'
    loader = importlib.util.spec_from_file_location('frozen_gateway_helpers', helper_path)
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    helper = module.Run(SimpleNamespace(out=args.out, haproxy=args.haproxy))
    out = args.out.resolve()
    declaration_bytes = (HERE / 'declaration.json').read_bytes()
    declaration = json.loads(declaration_bytes)
    (out / 'declaration.json').write_bytes(declaration_bytes)
    source_files = {'run_http.py': Path(__file__), 'origin_http.c': HERE / 'origin_http.c',
                    'declaration.json': HERE / 'declaration.json', 'frozen_gateway_helper.py': helper_path}
    (out / 'source').mkdir()
    for name, source in source_files.items():
        (out / 'source' / name).write_bytes(source.read_bytes())
    assert declaration['phase'] == 'predeclared' and len(declaration['cases']) == 12
    assert sum(len(c['requests']) for c in declaration['cases']) == 72
    result = dict(schema_version=1, status='failed', started_utc=helper.now(),
                  declaration=declaration, declaration_sha256=sha(declaration_bytes),
                  source_sha256={name: sha(path.read_bytes()) for name, path in source_files.items()},
                  runtime=dict(platform=platform.platform(), python=sys.version,
                               python_ssl=ssl.OPENSSL_VERSION), scenarios=[])

    def save():
        encoded = json.dumps(result, indent=2) + '\n'
        encoded = helper.redact(encoded).replace(str(Path.home()), '$HOME')
        (out / 'results.json').write_text(encoded)
        (out / 'commands.txt').write_text(helper.redact('\n'.join(helper.trace))
                                         .replace(str(Path.home()), '$HOME') + '\n')

    try:
        with tempfile.TemporaryDirectory(prefix='http-admission-', dir='/tmp') as temp:
            work = Path(temp)
            helper.redactions += [(str(work), '$TMP'), (str(work.resolve()), '$TMP'),
                                  (str(HERE), '$SRC')]
            prefix = args.openssl_prefix.resolve()
            result['runtime']['openssl'] = helper.command([prefix / 'bin/openssl', 'version', '-a'], work)
            result['runtime']['compiler'] = helper.command(['cc', '--version'], work)
            result['runtime']['gateway'] = helper.command([args.haproxy, '-vv'], work)
            result['runtime']['gateway_sha256'] = sha(args.haproxy.read_bytes())
            result['runtime']['libssl_sha256'] = sha((prefix / 'lib/libssl.dylib').read_bytes())
            result['runtime']['libcrypto_sha256'] = sha((prefix / 'lib/libcrypto.dylib').read_bytes())
            native = work / 'origin_http'
            result['runtime']['build'] = helper.command([
                'cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread',
                f'-I{prefix / "include"}', HERE / 'origin_http.c', f'-L{prefix / "lib"}',
                f'-Wl,-rpath,{prefix / "lib"}', '-lssl', '-lcrypto', '-o', native], work)
            result['runtime']['origin_version'] = helper.command([native, '--version'], work)
            result['runtime']['origin_binary_sha256'] = sha(native.read_bytes())
            result['runtime']['origin_linkage'] = helper.command(['otool', '-L', native], work)
            result['runtime']['parser_self_test'] = helper.command([native, '--self-test'], work)
            result['credentials'] = helper.credentials(work, prefix / 'bin/openssl')
            for spec in declaration['cases']:
                case = dict(id=spec['id'], specification=spec, processes={}, requests=[])
                result['scenarios'].append(case)
                listeners, cancels, children = {}, {}, {}
                try:
                    for name in ('legacy', 'restricted'):
                        listener = socket.socket()
                        listener.bind(('127.0.0.1', 0))
                        listener.listen(16)
                        listeners[name] = listener
                        rfd, wfd = os.pipe()
                        cancels[name] = (rfd, wfd)
                        groups = C if name == 'legacy' or spec['restricted_origin'] == 'C' else f'{H}:{C}'
                        children[name] = subprocess.Popen([
                            native, name, str(listener.fileno()), str(rfd), 'origin.crt', 'origin.key', groups],
                            cwd=work, pass_fds=(listener.fileno(), rfd), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
                        os.close(rfd)
                        cancels[name] = (None, wfd)
                    with socket.socket() as reservation:
                        reservation.bind(('127.0.0.1', 0))
                        front = reservation.getsockname()[1]
                    cfg = configuration(spec, front, listeners['legacy'].getsockname()[1],
                                        listeners['restricted'].getsockname()[1])
                    case['config'] = cfg
                    case['config_sha256'] = sha(cfg.encode())
                    config_path = work / (spec['id'] + '.cfg')
                    config_path.write_text(cfg)
                    (out / config_path.name).write_text(cfg)
                    case['configuration_validation'] = helper.command([
                        args.haproxy, '-c', '-f', config_path.name], work)
                    children['gateway'] = subprocess.Popen([args.haproxy, '-db', '-f', config_path.name],
                        cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    ready_deadline = time.monotonic() + 3
                    while True:
                        if children['gateway'].poll() is not None:
                            raise RuntimeError('Gateway exited during startup')
                        try:
                            helper.admin(work, 'show info')
                            break
                        except OSError:
                            if time.monotonic() > ready_deadline:
                                raise RuntimeError('Gateway admin readiness deadline')
                            time.sleep(.01)
                    for batch in (0, 1):
                        context = ssl.create_default_context(cafile=str(work / 'proxy-ca.crt'))
                        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
                        context.hostname_checks_common_name = False
                        context.options |= ssl.OP_NO_TICKET
                        context.set_alpn_protocols(['http/1.1'])
                        if spec['client_mode'] == 'C':
                            context.set_ecdh_curve(C)
                        connection = LoopbackHTTPS('proxy.test', front, context=context, timeout=4)
                        try:
                            for index, request_spec in enumerate(spec['requests']):
                                if request_spec['batch'] != batch:
                                    continue
                                request_id = f'{spec["id"]}-r{index}-{secrets.token_hex(4)}'
                                body = bytes(range(256)) + secrets.token_bytes(256)
                                request = dict(request_id=request_id, path=request_spec['path'],
                                               batch=batch, body_hex=body.hex(), client={})
                                case['requests'].append(request)
                                try:
                                    connection.request('POST', request_spec['path'], body=body,
                                        headers={'X-Audit-ID': request_id, 'Content-Type': 'application/octet-stream',
                                                 'Connection': 'keep-alive'})
                                    peer = connection.sock
                                    request['client'].update(local_port=peer.getsockname()[1],
                                        tls_version=peer.version(), session_reused=peer.session_reused,
                                        peer_certificate_sha256=sha(peer.getpeercert(binary_form=True)),
                                        certificate_verified=context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname,
                                        expected_dns_name='proxy.test')
                                    response = connection.getresponse()
                                    request['client'].update(http_status=response.status,
                                        response_request_id=response.getheader('X-Audit-ID'),
                                        response_origin_connection=response.getheader('X-Origin-Connection'),
                                        response_hex=response.read().hex(), exception=None)
                                except Exception:
                                    request['client']['exception'] = traceback.format_exc()
                                    raise
                        finally:
                            connection.close()
                finally:
                    gateway = children.get('gateway')
                    if gateway and gateway.poll() is None:
                        gateway.send_signal(signal.SIGUSR1)
                    for name in ('gateway', 'legacy', 'restricted'):
                        child = children.get(name)
                        if child is None:
                            continue
                        if name != 'gateway':
                            rfd, wfd = cancels[name]
                            os.close(wfd)
                            cancels[name] = (rfd, None)
                        timed_out, cleanup = False, None
                        try:
                            stdout, stderr = child.communicate(timeout=7)
                        except subprocess.TimeoutExpired:
                            timed_out, cleanup = True, 'SIGKILL'
                            child.kill()
                            stdout, stderr = child.communicate(timeout=2)
                        record = dict(stdout=stdout, stderr=stderr, exit=child.returncode,
                                      reaped=child.poll() is not None, timed_out=timed_out,
                                      cleanup_signal=cleanup)
                        if name != 'gateway':
                            record['events'] = [json.loads(line) for line in stdout.splitlines()]
                        case['processes'][name] = record
                    for listener in listeners.values():
                        listener.close()
                    for rfd, wfd in cancels.values():
                        for fd in (rfd, wfd):
                            if fd is not None:
                                os.close(fd)
                    admin = work / 'admin.sock'
                    if admin.exists():
                        admin.unlink()
                assert len(case['requests']) == 6
                assert len(case['processes']) == 3
                assert all(c['exit'] == 0 and c['reaped'] and not c['timed_out'] and c['cleanup_signal'] is None
                           for c in case['processes'].values()), case['processes']
                print(spec['id'], spec['policy'], spec['restricted_origin'], spec['client_mode'],
                      [r['client']['http_status'] for r in case['requests']], flush=True)
            result['temporary_files_removed'] = False
        result['temporary_files_removed'] = not work.exists()
        assert result['temporary_files_removed']
        result['status'] = 'collected'
    except BaseException:
        result['error'] = traceback.format_exc()
        raise
    finally:
        result['finished_utc'] = helper.now()
        save()
        for case in result['scenarios']:
            raw = out / 'raw' / case['id']
            raw.mkdir(parents=True, exist_ok=True)
            for name, proc in case['processes'].items():
                for stream in ('stdout', 'stderr'):
                    (raw / (name + '.' + stream + '.txt')).write_text(helper.redact(proc[stream]))


if __name__ == '__main__':
    main()
