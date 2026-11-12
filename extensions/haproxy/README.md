# HAProxy Community gateway evaluation

This extension runs an unmodified HAProxy Community executable between an eager
TLS client and a TLS origin on IPv4 loopback. HAProxy terminates the frontend
TLS connection and establishes a separate authenticated backend TLS connection.
The endpoint fixture was derived from the existing probe. It contains no relay
role and sends no READY message.

The retained confirmatory run is `results/icete2027/2026-10-24-haproxy-primary-01`
relative to the project root. All nine predeclared delivery or rejection
predictions matched. Five cases delivered exact bytes. Three met their declared
route group requirements and two intentionally violated the both-leg requirement.
Four cases did not deliver a request to the origin.

A parent-executed reproduction from extracted final source also matched all
nine cases in `results/icete2027/2026-10-24-haproxy-parent-01`. It used a
separately rebuilt gateway binary, fresh local credentials and a fresh payload
on the same host. Its executable-source and matrix hashes match the primary
run. Both executions had zero timeouts and no forced cleanup.

## Reproduce

Requirements are Python 3, a C11 compiler, OpenSSL 3.5 or later with
X25519MLKEM768 support and HAProxy Community with OpenSSL enabled. The retained
run used HAProxy 3.4.7-8872a26, OpenSSL 3.6.3, Apple Clang 21.0.0 and Python
3.14.5 on macOS arm64. HAProxy and the endpoints used the same OpenSSL library.
This adds gateway-software coverage, rather than another TLS implementation.

From `testbed/icete2027`, build the pinned gateway if necessary:

```sh
python3 build_haproxy.py --out /tmp/haproxy-fresh-build --openssl-prefix /opt/homebrew/opt/openssl@3
python3 -B haproxy/run_matrix.py --haproxy /tmp/haproxy-fresh-build/haproxy-3.4.7/haproxy --out /tmp/haproxy-new-run
```

Both output directories must be new. For an existing gateway build, pass its
executable with `--haproxy`. Use `--openssl-prefix` to select another installed
OpenSSL prefix and `--cc` to select a C compiler. The matrix runner installs
nothing and does not operate global services.

## Declared cases

H denotes X25519MLKEM768 and C denotes X25519. The declared requirement mask uses
1 for the frontend leg and 2 for the backend leg. It is an input to the route
checker. HAProxy is not configured with the reference probe's release guard.

| Case | Client / frontend groups | Backend / origin groups | Required legs | Prediction |
|---|---|---|---|---|
| H01 | H / H | H / H | Both | H/H delivery |
| H02 | H / H | C / C | Both | H/C delivery, group requirement violated |
| H03 | H / H | C / H | Both | Backend group rejection |
| H04 | H / H | H / H | Both | H/H recovery after replacing the C backend offer |
| H05 | H / C | H / H | Both | Frontend group rejection |
| H06 | H / H | H / H | Both | Client rejects the gateway's unknown CA |
| H07 | H / H | H / H | Both | Gateway rejects the origin's expected hostname |
| H08 | C / C | H / H | Both | C/H delivery, group requirement violated |
| H09 | H / H | C / C | Front only | H/C delivery meets the declared group requirement |

H02 and H09 have the same TLS and trust settings. Their declared requirement
differs. Every case uses its own gateway process, configuration and endpoint
processes. H04 compares a fresh execution with H03, not a live configuration
reload. The fresh local CA and leaf credentials are shared within one matrix
run and regenerated for the next run. All payloads are synthetic.

The matrix was recorded before the first execution in `matrix.json` and copied
to `preregistration/matrix.initial.json`. Both are byte-identical. Delivery
and failure-stage predictions were unchanged during development. Accepted-write
counts on backend failures were measured without a predetermined expected value.
`preregistration/confirmatory-freeze.json` records the final executable-source
hashes and the development corrections made before the confirmatory run.

## Release boundary and observations

The original cooperative property requires authentication and required groups
on both legs before any accepted application write. HAProxy's eager client can
write before backend negotiation finishes. This extension therefore reports
delivered-route authentication/group classification separately from accepted
frontend writes and origin reads. It does not certify the original temporal
property and does not implement or claim READY behaviour.

In H03 and H07, the frontend client accepted 305 request payload bytes and four
framing bytes into successful SSL_write_ex calls. The origin received zero
request payload or framing bytes. Rejection prevented origin delivery while
allowing the frontend write boundary to be crossed. Accepted client writes do
not prove that HAProxy read those bytes. HAProxy's internal backend accepted
writes are uninstrumented.

The five delivery cases correlate the exact 305-byte request at the client and
origin with the exact 321-byte response at both endpoints. The response is the
16-byte `origin-response` prefix including its NUL byte, followed by the request.
The retained hex payloads and chunk-level progress events support these counts.

Endpoint JSON events contain CLOCK_MONOTONIC observation timestamps in
nanoseconds. These use the same host clock across the two endpoint processes.
They are not packet timestamps. A logged origin handshake completion is not a
timestamp for HAProxy's internal certificate-verification completion. Concatenated
stdout order is not used as cross-process chronology.

## Identity and negotiated-group evidence

The client verifies the gateway's separate CA and `proxy.test` DNS SAN. HAProxy
uses `verify required`, a separate origin CA and static `verifyhost origin.test`.
Backend SNI is omitted in every case, including H07, where only the expected
name changes to `wrong-origin.test`. This avoids SNI taking precedence over
`verifyhost`. The origin records that the backend ClientHello has no server_name
extension. Frontend SNI remains `proxy.test`.

In the five delivered cases, HAProxy's ssl_fc_curve and ssl_bc_curve log fields
agree with the groups recorded independently at the endpoints. HAProxy's
backend certificate SHA-256 agrees with the origin's local certificate
fingerprint. Full TLS 1.3 handshakes and non-reuse are checked. The origin rejects
PSK offers and records the actual supported-group and key-share IANA IDs.

H07 records HAProxy's `SSL_MISMATCH` connection error and TLS error
`0A000086` for certificate verification failure. The origin receives alert 80
(internal_error) from HAProxy's hostname-check callback. This differs from the
reference probe's hostname failure alert. Do not replace it with alert 42 or
claim a directly logged backend X.509 verification code of 62.

The configuration includes no-tls-tickets for the frontend and no-ssl-reuse for
the backend. HAProxy can still emit TLS 1.3 NewSessionTicket messages. Fresh
processes, fresh endpoint contexts and the observed non-reuse fields establish
that these exchanges did not resume sessions; the experiment does not claim
that HAProxy's TLS 1.3 ticket emission is disabled.

The configuration and sample-fetch semantics were checked against the
[official HAProxy 3.4 configuration manual](https://docs.haproxy.org/3.4/configuration.html),
particularly `curves`, `verify`, `verifyhost`, `ssl_fc_curve`, `ssl_bc_curve`,
`ssl_s_der`, `bc_err_name` and `error-log-format`.

## Retained evidence and process controls

Each run contains the declared matrix, results.json and stdout/stderr in
trace.txt. Successful runs also contain outcomes.csv and summary.json. All
generated HAProxy configurations are retained. Source, matrix, executable and
configuration SHA-256 hashes bind the records to their inputs. Private home
and temporary paths are replaced with $SRC, $TMP and $HAPROXY in public records.
No private keys are copied into the output directory.

Each configuration is validated with HAProxy -c before process startup. Readiness
is checked through a local Unix admin socket without generating a probe TLS
connection. There are no health checks or retries. Endpoint I/O, accept waits
and supervisor waits are bounded. An idle origin is explicitly cancelled after
the client exits. The gateway is soft-stopped with SIGUSR1 after endpoint
completion. Unexpected timeout, SIGTERM or SIGKILL cannot count as successful
policy rejection. All children are reaped and temporary credential files are
deleted.

Development attempts 01-04 are preserved separately. Attempt 01 failed
configuration validation. Attempt 02 exposed a missing custom frontend error
log. Attempt 03 exposed the checker's incorrect alert expectation. Attempt 04
matched all nine matrix predictions. The final checker added explicit SNI,
PSK, offered-group and fingerprint checks before the confirmatory primary run.
These corrections did not change the predeclared delivery predictions.

## Limits

This is one local gateway configuration on one host, with one exchange per
case and classical P-256 certificate authentication. It establishes neither a
population failure rate nor commercial gateway behaviour. The records support
authenticated delivered routes and endpoint byte observations. They do not
provide full instrumentation of HAProxy's accepted-write timing or demonstrate
the original cooperative temporal property for this gateway.
