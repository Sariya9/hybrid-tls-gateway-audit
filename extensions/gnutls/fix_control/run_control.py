#!/usr/bin/env python3
"""Build the pinned GnuTLS backport against an existing local dependency prefix.

Run the unchanged sixteen-case collector with the frozen fix-control matrix.
The original dependency_build.json remains historical lineage, not this build.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
COLLECTOR = HERE.parent
TARGET = 'lib/ext/supported_groups.c'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def tree(root):
    return {str(p.relative_to(root)): sha(p)
            for p in sorted(root.rglob('*')) if p.is_file()}


def same_configurations(base, control):
    assert len(base['cases']) == len(control['cases']) == 16
    changed = []
    for old, new in zip(base['cases'], control['cases']):
        assert {k: v for k, v in old.items() if k != 'expected'} == {
            k: v for k, v in new.items() if k != 'expected'}
        if old['expected'] != new['expected']:
            changed.append(old['id'])
    assert changed == ['M10'], changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-prefix', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    assert __debug__, 'Assertions must remain enabled'
    work, out, deps = args.work.resolve(), args.out.resolve(), args.base_prefix.resolve()
    if work.exists() or out.exists():
        parser.error('--work and --out must both be new paths')
    pin = json.loads((HERE / 'source-provenance.json').read_text())
    matrix = HERE / 'matrix.confirmatory.json'
    base_matrix = COLLECTOR / 'matrix.confirmatory.json'
    assert sha(matrix) == pin['matrix_sha256']
    assert sha(base_matrix) == pin['base_matrix_sha256']
    same_configurations(json.loads(base_matrix.read_text()), json.loads(matrix.read_text()))
    for name, expected in pin['frozen_collector_sha256'].items():
        assert sha(COLLECTOR / name) == expected, name
    patch = HERE / pin['applied_patch']
    assert sha(patch) == pin['applied_patch_sha256']
    baseline = json.loads(args.baseline.read_text())
    assert baseline['status'] == 'passed' and len(baseline['cases']) == 16
    assert baseline['matrix_sha256'] == pin['base_matrix_sha256']
    assert baseline['source_sha256'] == {
        n: pin['frozen_collector_sha256'][n]
        for n in ('proxy_probe_gnutls.c', 'run_gnutls_matrix.py')}
    assert sha(deps / 'lib/libleancrypto.dylib') == baseline['dependency_linkage']['leancrypto']['sha256']
    work.mkdir(parents=True, exist_ok=False)
    prefix = work / 'prefix'
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    commands = []
    record = dict(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  status='failed', patch_sha256=sha(patch), matrix_sha256=sha(matrix),
                  source_provenance_sha256=sha(HERE / 'source-provenance.json'),
                  helper_sha256=sha(Path(__file__)), commands=commands,
                  original_dependency_manifest_note=pin['dependency_build_note'])

    def run(label, argv, cwd, timeout=300):
        argv = list(map(str, argv))
        commands.append(dict(label=label, argv=argv, cwd=str(cwd)))
        print(label, flush=True)
        with (work / (label + '.log')).open('w') as log:
            log.write(shlex.join(argv) + '\n')
            log.flush()
            subprocess.run(argv, cwd=cwd, env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=timeout)

    try:
        archive = work / 'gnutls-3.8.13.tar.xz'
        cached = args.archive or COLLECTOR / '.local/gnutls-3.8.13.tar.xz'
        if cached.is_file():
            shutil.copyfile(cached, archive)
        else:
            with urllib.request.urlopen(pin['source_archive_url'], timeout=45) as response:
                archive.write_bytes(response.read())
        assert sha(archive) == pin['source_archive_sha256']
        record['archive_sha256'] = sha(archive)
        with tarfile.open(archive) as bundle:
            bundle.extractall(work, filter='data')
        source = work / 'gnutls-3.8.13'
        before = tree(source)
        save(work / 'source-before.json', before)
        record['source_pre_sha256'] = before[TARGET]
        run('patch-dry-run', ['patch', '--dry-run', '--batch', '--forward', '-F0', '-p1', '-i', patch], source)
        run('patch-apply', ['patch', '--batch', '--forward', '-F0', '-p1', '-i', patch], source)
        after = tree(source)
        save(work / 'source-after.json', after)
        changed = [n for n in sorted(set(before) | set(after)) if before.get(n) != after.get(n)]
        assert changed == [TARGET], changed
        record['changed_source_files'] = changed
        record['source_post_sha256'] = after[TARGET]
        record['source_tree_before_sha256'] = sha(work / 'source-before.json')
        record['source_tree_after_sha256'] = sha(work / 'source-after.json')
        # Reuse the exact existing PQ backend; no rebuild or install into that prefix.
        (prefix / 'lib').mkdir(parents=True)
        (prefix / 'lib/libleancrypto.dylib').symlink_to(deps / 'lib/libleancrypto.dylib')
        env['PKG_CONFIG'] = str(deps / 'bin/pkgconf')
        names = ('nettle', 'gmp', 'libtasn1', 'libunistring', 'gettext')
        env['PKG_CONFIG_PATH'] = ':'.join([str(deps / 'lib/pkgconfig')] + [
            f'/opt/homebrew/opt/{n}/lib/pkgconfig' for n in names])
        env['PKG_CONFIG_ALLOW_SYSTEM_CFLAGS'] = '1'
        env['PKG_CONFIG_ALLOW_SYSTEM_LIBS'] = '1'
        env['CPPFLAGS'] = ' '.join(f'-I/opt/homebrew/opt/{n}/include' for n in names)
        env['LDFLAGS'] = ' '.join(f'-L/opt/homebrew/opt/{n}/lib' for n in names) + f' -Wl,-rpath,{deps / "lib"}'
        env['LEANCRYPTO_CFLAGS'] = f'-I{deps / "include"}'
        env['LEANCRYPTO_LIBS'] = f'-L{deps / "lib"} -lleancrypto'
        env['CFLAGS'] = '-g -O2'
        record['build_environment'] = {k: env[k] for k in (
            'PKG_CONFIG', 'PKG_CONFIG_PATH', 'PKG_CONFIG_ALLOW_SYSTEM_CFLAGS',
            'PKG_CONFIG_ALLOW_SYSTEM_LIBS', 'CPPFLAGS', 'LDFLAGS',
            'LEANCRYPTO_CFLAGS', 'LEANCRYPTO_LIBS', 'CFLAGS')}
        build = work / 'gnutls-build'
        build.mkdir()
        flags = ['--with-leancrypto', '--disable-doc', '--disable-tools', '--disable-tests',
                 '--disable-cxx', '--disable-nls', '--disable-libdane', '--without-p11-kit',
                 '--without-tpm', '--with-tpm2=no', '--without-idn', '--with-zlib=no',
                 '--with-brotli=no', '--with-zstd=no', '--disable-hardware-acceleration']
        run('configure', [source / 'configure', f'--prefix={prefix}', *flags], build)
        run('make', ['make', '-j4'], build)
        run('install-local', ['make', 'install'], build)
        record['runtime_library_sha256'] = sha(prefix / 'lib/libgnutls.dylib')
        record['leancrypto_sha256'] = sha(prefix / 'lib/libleancrypto.dylib')
        record['runtime_prefix'] = str(prefix)
        record['status'] = 'built'
    finally:
        record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(work / 'build.json', record)

    print('Run frozen collector', flush=True)
    with (work / 'collector.log').open('w') as log:
        execution = subprocess.run([sys.executable, '-B', COLLECTOR / 'run_gnutls_matrix.py',
            '--matrix', matrix, '--prefix', prefix, '--out', out],
            env=env, stdout=log, stderr=subprocess.STDOUT)
    result = json.loads((out / 'results.json').read_text())
    assert result['library_sha256'] == record['runtime_library_sha256']
    assert result['matrix_sha256'] == pin['matrix_sha256']
    assert result['source_sha256'] == baseline['source_sha256']
    assert result['dependency_build_manifest_sha256'] == pin['frozen_collector_sha256']['dependency_build.json']
    assert {k: v['sha256'] for k, v in result['dependency_linkage'].items()} == {
        k: v['sha256'] for k, v in baseline['dependency_linkage'].items()}
    rows = []
    fields = ('stage', 'front_group', 'backend_group', 'delivered', 'conformance')
    for old, new in zip(baseline['cases'], result['cases']):
        assert old['name'] == new['name']
        for field in ('configuration', 'declared_policy', 'guard_enabled'):
            assert old[field] == new[field]
        rows.append(dict(case=new['name'], before={k: old['observed'][k] for k in fields},
                         after={k: new.get('observed', {}).get(k) for k in fields},
                         changed=any(old['observed'][k] != new.get('observed', {}).get(k) for k in fields)))
    difference = [r['case'] for r in rows if r['changed']]
    expected = execution.returncode == 0 and result['status'] == 'passed' and difference == ['M10']
    summary = dict(status='hypothesis_supported' if expected else 'unexpected_result',
                   baseline_results_sha256=sha(args.baseline), results_sha256=sha(out / 'results.json'),
                   collector_exit=execution.returncode, changed_cases=difference,
                   outcomes=dict(Counter(c.get('observed', {}).get('conformance', 'check_error') for c in result['cases'])),
                   cases=rows, limits='Same host/compiler/dependencies and collector. Task-local upstream source backport, not a new released version. No full upstream regression or performance claim.')
    # Packaged descriptors redact private paths without changing any retained collector record.
    descriptor = json.dumps(dict(build=record, source=pin), indent=2)
    for path, label in ((str(work), '$BUILD'), (str(deps), '$BASE_DEPS'),
                        (str(COLLECTOR), '$SRC'), (str(Path.home()), '$HOME')):
        descriptor = descriptor.replace(path, label)
    (out / 'control-provenance.json').write_text(descriptor + '\n')
    save(out / 'comparison.json', summary)
    print(json.dumps({k: summary[k] for k in ('status', 'changed_cases', 'outcomes')}, indent=2))
    if not expected:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
