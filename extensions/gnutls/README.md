# Native GnuTLS loopback evaluation

This adapter runs the client, terminating relay and origin as three native
GnuTLS processes. It adapts the bounded socket supervision, framing and synthetic
exchange from the OpenSSL probe in the parent directory. It does not use
OpenSSL to establish or carry a TLS connection.

The tested library is a task-local GnuTLS 3.8.13 build with leancrypto 1.5.0.
The installed Homebrew GnuTLS 3.8.13_2 lacks PQ groups and rejects a priority
containing X25519-MLKEM768. Its capability result is retained separately.
GnuTLS removed liboqs support in 3.8.10, as recorded in the upstream NEWS file.
Installed liboqs 0.15.0 is not used here. The local library links to leancrypto,
Nettle/Hogweed 4.0 and GMP. Recorded linkage has no libssl or libcrypto dependency.
OpenSSL 3.6.3 is used only for temporary test certificate generation.

## Run the declared matrix

Run from the project root. Python assertions must remain enabled.

```sh
python3 testbed/icete2027/gnutls/run_gnutls_matrix.py \
  --matrix testbed/icete2027/gnutls/matrix.confirmatory.json \
  --out results/icete2027/2026-10-24-gnutls-rerun-01
```

The default runtime prefix is `testbed/icete2027/gnutls/.local/prefix`.
The output directory must not exist. The runner refuses to overwrite a run.
Use a fresh name for each execution. An extracted copy must contain
`proxy_probe_gnutls.c`, `run_gnutls_matrix.py`, the selected matrix and
`dependency_build.json` in the same directory. Pass `--prefix` when using an
alternative locally built runtime.

```sh
python3 testbed/icete2027/gnutls/check_records.py \
  results/icete2027/2026-10-24-gnutls-rerun-01
```

The checker reparses each saved stdout stream and compares it with the
structured events before checking policy and byte correlation. It also rejects
four modified copies containing a corrupted payload, accepted bytes on a blocked
route, failed SAN evidence or a resumed session. This is a consistency check
using the adapter's checker, not an independently implemented oracle.

## Local dependency build

The dependency directory is ignored and must be excluded from public packages.
No Homebrew packages or global services are changed. This command downloads
pinned upstream archives and installs Meson into a private Python directory.
It uses the existing compiler, Ninja, Nettle, GMP, libtasn1 and libunistring.

```sh
python3 testbed/icete2027/gnutls/build_local_dependencies.py \
  --work testbed/icete2027/gnutls/.local/rebuild-new-01
python3 testbed/icete2027/gnutls/run_gnutls_matrix.py \
  --prefix testbed/icete2027/gnutls/.local/rebuild-new-01/prefix \
  --matrix testbed/icete2027/gnutls/matrix.confirmatory.json \
  --out results/icete2027/2026-10-24-gnutls-rebuilt-01
```

The work directory must not exist. Archive hashes are checked before extraction.
Cached original archives in `.local/` may be reused if their hashes match.
The leancrypto patch excludes Darwin from two LTO conditions. It changes no
algorithm source. Portable C implementations and runtime self-tests are enabled.
This is a research build. The full upstream regression suites were not run.
The helper records commands, local environment and build output in its work
folder. `dependency_build.json` records the original evaluated build's provenance;
each run also records the actual runtime and dependency hashes.

## Contract and observations

All sockets bind or connect to IPv4 loopback. Each case creates fresh sessions
and uses separate P-256 CAs and keys for `proxy.test` and `origin.test`. The
initiating endpoint on each leg verifies its explicit CA store, exact DNS SAN
and serverAuth purpose. The two expected identities are checked independently.
T01 selects the wrong trust store; T02 keeps origin SNI fixed while checking
`wrong-origin.test`. Neither case disables verification.

The priority mapping enables only TLS 1.3 and certificate-based ECDHE-ECDSA.
Tickets, automatic ticket issuance and early data are disabled. No saved sessions
or PSK credentials are supplied. A ClientHello hook records and rejects any
pre_shared_key extension. Successful records must show no session reuse and
received Certificate, CertificateVerify and Finished messages.

The client waits for a framed READY control message. The relay checks its two
completed handshakes and the configured release mask before sending READY or
attempting a request/response write. Frames carry a 4-byte length prefix. Writes
are bounded to 37-byte chunks. The records retain accepted write progress and
exact bytes at both ends of both legs, in both directions. Rejected cases must
have no READY, payload attempt, accepted framing byte or accepted payload byte.
The delivered request has 303 bytes and the response has 319 bytes. Accepted
payload progress totals 1,244 bytes across both legs, plus 16 framing bytes.

The adapter preserves native group names. `X25519-MLKEM768` is GnuTLS internal
ID 514 and wire IANA ID 4588. `X25519` is internal ID 6 and wire IANA ID 29.
The summary normalises the hybrid name to the baseline's X25519MLKEM768 spelling.
Internal IDs are not wire group IDs.

## Retained results

The exploratory matrix was declared before the first full native run. The
confirmatory matrix retains the same 16 configurations and changes only M10's
prediction following exploration. It was frozen before confirmatory execution.
The original exploratory declaration and observations remain intact.

| Result | Observation |
|---|---|
| Capability check | Installed GnuTLS lacks PQ groups; hybrid priority returns -50 |
| Classical-build exploration | M11's mixed client priority cannot be configured on that build; retained failure |
| Full exploration | All 16 case checks completed; M10 differed from the baseline prediction |
| Confirmation | All 16 native predictions matched; 5 conforming deliveries, 3 violating deliveries and 8 rejections |

M10 offers both groups everywhere. Under the unchanged GnuTLS priority mapping,
both servers select X25519 through HelloRetryRequest and the guard blocks.
The OpenSSL baseline selected hybrid on both legs and delivered. M05 and M06
retain H/C negotiation, including the backend retry from hybrid to classical.
M05 forwards the exchange; M06 rejects before READY. T01 yields certificate
status 66 and `bad_certificate` alert 42. T02 yields status 16386 and alert 42.
These native codes are retained rather than substituted with OpenSSL codes.

This establishes a second TLS state-machine implementation on the same host.
It does not establish complete independence of software provenance, compiler,
operating system or application harness. The relay is a controlled research
program. This slice does not evaluate a production gateway, remote system,
performance, concurrency or an eager/uncooperative application client.

## Package contents

Include the source files, patch, both matrices, dependency manifest and this
README. Include the selected result directory with its raw streams and declared
matrix. Exclude `.local/`, `__pycache__/`, binaries and temporary credentials.
The retained results contain synthetic application bytes and public certificate
fingerprints. No private keys are packaged. Local source, temporary and home
paths are redacted as `$SRC`, `$TMP`, `$GNUTLS` and `$HOME`.

API and source references are the [GnuTLS 3.8.13 manual](https://www.gnutls.org/manual/gnutls.html),
the [upstream GnuTLS release archive](https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.13.tar.xz)
and the [leancrypto 1.5.0 release](https://github.com/smuellerDD/leancrypto/releases/tag/v1.5.0).
