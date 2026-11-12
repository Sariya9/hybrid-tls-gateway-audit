#!/usr/bin/env python3
"""Build task-local GnuTLS/leancrypto on this macOS host. Never installs globally.
Network access downloads pinned upstream sources and a local Meson package only.
Usage: python3 build_local_dependencies.py --work .local/rebuild-01
"""
import argparse, datetime, hashlib, json, os, shutil
from pathlib import Path
import shlex, subprocess, sys, tarfile, urllib.request
HERE=Path(__file__).resolve().parent
SOURCES=[
 ('pkgconf-2.5.1.tar.xz','https://distfiles.ariadne.space/pkgconf/pkgconf-2.5.1.tar.xz','cd05c9589b9f86ecf044c10a2269822bc9eb001eced2582cfffd658b0a50c243'),
 ('leancrypto-1.5.0.tar.gz','https://codeload.github.com/smuellerDD/leancrypto/tar.gz/refs/tags/v1.5.0','186252a6251c653e9550387e80e066e9002b59657b224d38a7abd63679ea0d52'),
 ('gnutls-3.8.13.tar.xz','https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.13.tar.xz','ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e')]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args();work=args.work.resolve();work.mkdir(parents=True,exist_ok=False)
    prefix=work/'prefix';env=os.environ.copy();commands=[]
    record={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'failed','sources':SOURCES,'commands':commands,
      'limits':'Local research build; portable leancrypto C, runtime self-tests enabled; GnuTLS upstream full test suite not run; not a certified/FIPS build.'}
    def run(label,args,cwd):
        args=list(map(str,args));commands.append({'label':label,'argv':args,'cwd':str(cwd)})
        print(label,flush=True)
        with (work/(label+'.log')).open('w') as log:
            log.write(shlex.join(args)+'\n');log.flush()
            subprocess.run(args,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    try:
        for name,url,expected in SOURCES:
            archive=work/name
            cached=HERE/'.local'/name
            if cached.is_file(): shutil.copyfile(cached,archive)
            else:
                with urllib.request.urlopen(url,timeout=90) as response:archive.write_bytes(response.read())
            if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected: raise ValueError('Archive hash mismatch: '+name)
            with tarfile.open(archive) as archive_file:archive_file.extractall(work,filter='data')
        run('pkgconf-configure',['./configure',f'--prefix={prefix}','--disable-shared'],work/'pkgconf-2.5.1')
        run('pkgconf-make',['make','-j4'],work/'pkgconf-2.5.1')
        run('pkgconf-install',['make','install'],work/'pkgconf-2.5.1')
        run('meson-install',[sys.executable,'-m','pip','install','--target',work/'python','meson==1.9.2'],work)
        env['PYTHONPATH']=str(work/'python');env['PATH']=str(prefix/'bin')+':'+env['PATH']
        env['PKG_CONFIG']=str(prefix/'bin/pkgconf')
        env['PKG_CONFIG_PATH']=':'.join(str(p/'lib/pkgconfig') for p in [prefix,*[Path('/opt/homebrew/opt')/n for n in ('nettle','gmp','libtasn1','libunistring','gettext')]])
        # pkgconf's own prefix is filtered as a system path; allow explicit local flags.
        env['PKG_CONFIG_ALLOW_SYSTEM_CFLAGS']='1';env['PKG_CONFIG_ALLOW_SYSTEM_LIBS']='1'
        record['build_environment']={k:v for k,v in env.items() if k in ('PKG_CONFIG','PKG_CONFIG_PATH','PKG_CONFIG_ALLOW_SYSTEM_CFLAGS','PKG_CONFIG_ALLOW_SYSTEM_LIBS')}
        run('leancrypto-darwin-patch',['patch','-p1','-i',HERE/'leancrypto-darwin-build.patch'],work/'leancrypto-1.5.0')
        run('leancrypto-configure',[sys.executable,'-m','mesonbuild.mesonmain','setup',work/'lean-build',work/'leancrypto-1.5.0',f'--prefix={prefix}','--libdir=lib','--buildtype=release','-Dtests=disabled','-Ddisable-asm=true'],work)
        run('leancrypto-make',['ninja','-C',work/'lean-build','-j4'],work)
        run('leancrypto-install',['ninja','-C',work/'lean-build','install'],work)
        env['CPPFLAGS']=' '.join(f'-I/opt/homebrew/opt/{n}/include' for n in ('nettle','gmp','libtasn1','libunistring','gettext'))
        env['LDFLAGS']=' '.join(f'-L/opt/homebrew/opt/{n}/lib' for n in ('nettle','gmp','libtasn1','libunistring','gettext'))+f' -Wl,-rpath,{prefix / "lib"}'
        env['LEANCRYPTO_CFLAGS']=f'-I{prefix / "include"}';env['LEANCRYPTO_LIBS']=f'-L{prefix / "lib"} -lleancrypto'
        record['build_environment'].update({k:env[k] for k in ('CPPFLAGS','LDFLAGS','LEANCRYPTO_CFLAGS','LEANCRYPTO_LIBS')})
        build=work/'gnutls-build';build.mkdir()
        run('gnutls-configure',[work/'gnutls-3.8.13/configure',f'--prefix={prefix}','--with-leancrypto','--disable-doc','--disable-tools','--disable-tests','--disable-cxx','--disable-nls','--disable-libdane','--without-p11-kit','--without-tpm','--with-tpm2=no','--without-idn','--with-zlib=no','--with-brotli=no','--with-zstd=no','--disable-hardware-acceleration'],build)
        run('gnutls-make',['make','-j4'],build);run('gnutls-install',['make','install'],build)
        record['status']='built';print('Runtime prefix:',prefix)
    finally:
        record['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        (work/'build.json').write_text(json.dumps(record,indent=2)+'\n')
if __name__=='__main__':main()
