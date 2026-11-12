#!/usr/bin/env python3
"""Build the pinned upstream gateway in a fresh local directory; never install it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

VERSION = "3.4.7"
SHA256 = "ccfd342f3724c2cd659574044d788f44e20b212467c6bd5edbbfc517a2775dca"
URL = f"https://www.haproxy.org/download/3.4/src/haproxy-{VERSION}.tar.gz"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--openssl-prefix", type=Path, required=True)
    parser.add_argument("--target", choices=("osx", "linux-glibc"), default="osx")
    args = parser.parse_args()
    assert (args.openssl_prefix / "include/openssl/ssl.h").is_file()
    args.out.mkdir(parents=True, exist_ok=False)
    archive = args.out / f"haproxy-{VERSION}.tar.gz"
    with urllib.request.urlopen(URL, timeout=60) as response:
        archive.write_bytes(response.read())
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != SHA256:
        raise ValueError(f"upstream archive checksum mismatch: {actual}")
    with tarfile.open(archive) as source:
        source.extractall(args.out, filter="data")
    folder = args.out / f"haproxy-{VERSION}"
    command = ["make", "-j4", f"TARGET={args.target}", "USE_OPENSSL=1", "USE_THREAD=1",
               f"SSL_INC={args.openssl_prefix.resolve() / 'include'}",
               f"SSL_LIB={args.openssl_prefix.resolve() / 'lib'}"]
    with (args.out / "build.log").open("w") as log:
        result = subprocess.run(command, cwd=folder, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("HAProxy build failed; see build.log")
    binary = folder / "haproxy"
    version = subprocess.run([str(binary.resolve()), "-vv"], capture_output=True,
                             text=True, check=True).stdout
    provenance = {"url": URL, "source_sha256": actual, "target": args.target,
                  "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                  "compiler": os.environ.get("CC", "cc"), "version_output": version}
    (args.out / "build.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(binary.resolve())


if __name__ == "__main__":
    main()
