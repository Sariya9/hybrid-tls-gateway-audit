# HTTP route-admission study

This extension tests a declared requirement at complete origin application
acceptance through unmodified HAProxy 3.4.7. The legacy endpoint is C-only.
The restricted endpoint accepts H,C or C only. A restricted request requires
H on both legs; a compatibility request has no hybrid minimum. Both routes
still require certificate-path and origin-name verification.

## Run and audit

Run from the project root with Python assertions enabled. Use new output paths.
The runner compiles the native C origin and generates temporary credentials.
All sockets use IPv4 loopback. Existing libraries and the supplied HAProxy
binary are reused; no global service or package is changed.

```sh
python3 -B testbed/icete2027/http_policy/run_http.py \
  --haproxy /absolute/path/to/haproxy \
  --out /tmp/http-admission-new
python3 -B testbed/icete2027/http_policy/audit_http.py \
  /tmp/http-admission-new --out /tmp/http-admission-audit-new
AUDIT_HTTP_RUN_DIRECTORY=/tmp/http-admission-new \
  python3 -m unittest discover -s testbed/icete2027/http_policy \
  -p test_audit_http.py -v
```

The default OpenSSL prefix is /opt/homebrew/opt/openssl@3. A C11 compiler,
pthreads and Python SSL linked to a hybrid-capable OpenSSL are required.
Python SSL is not another TLS implementation. The runner retains the actual
OpenSSL, Python and gateway versions, build commands and runtime hashes.
Its native origin has a bounded Content-Length POST parser, 16 workers,
3-second socket I/O timeouts and a process watchdog. It is a fixture, not a
general HTTP server. The parser self-test runs during every native execution.

## Declaration and policies

The declaration was frozen before the first full collection. Twelve scenarios
cross three configurations with the two restricted-origin states and H/C
frontend negotiation. Each sends six sequential 512-byte POSTs through two
client connection batches, alternating /compat and /restricted.

Support only advertises both backend groups without enforcing a protected
minimum. Blanket H requires H everywhere. Per-route enforcement requires H
for restricted frontend requests and uses a strict-H restricted backend pool,
while preserving a C-compatible legacy pool. These are ordinary gateway ACLs
and group settings, not a new mitigation algorithm.

All HTTP backends explicitly use no-sni-auto, verify required and verifyhost
origin.test. HAProxy HTTP mode otherwise derives SNI from Host and can change
the certificate reference name. The first preserved development run exposed
that confound. Adding no-sni-auto changed neither declarations nor predictions.
The native no_shared_group failure fields and refusal checks were then added.
execution-freeze.json binds the final sources before primary confirmation.
The exploratory records remain separate and are not reclassified as confirmation.

## Evidence and result boundaries

The auditor reparses origin stdout and joins request IDs, paths, frontend
source ports, actual gateway TLS groups and native origin connection IDs.
Admitted requests require exact payload and echo matches, certificate binding,
TLS 1.3 and no resumption. A 503 requires native no-shared-group failure on
that selected origin, not a status-only inference. A rejection has no complete
origin admission; absence of that event does not prove absence of partial
input or buffering. Malformed evidence raises ValidationError. Predictions
are compared after policy classification and are never used as its verdict.

Both frozen executions have 72 requests and 36 reaped native children with
zero timeouts or forced cleanup. Per execution, support only admits 24 with
9 violating admissions; blanket H admits 3 and excessively refuses 12
admissible compatibility requests; per route admits all 15 admissible requests
without either outcome. Matched positive controls establish compatibility
feasibility. Ineligible means unable to meet the declared minimum under that
condition, not physically undeliverable or a network outage. Fourteen backend
TLS connections each serve three requests across the two frontend connections.
The counts are controlled cases, not deployment prevalence or statistical rates.

The native origins suppress tickets, PSKs and early data. Persistent connection
sharing is distinct from TLS resumption. Frontend session tickets emitted by
HAProxy are not reused. Distinct connections do not establish distinct users.
The test is sequential and does not cover concurrency, HTTP/2, live policy
changes, mixed H/C frontend populations within one pool or production banking.
A rejected classical frontend may already have accepted an eager client's body.
Origin admission compliance therefore does not establish PQ confidentiality
of all submitted bytes. A client needing protection before transmission must
require hybrid locally. Gateway internal write timing remains uninstrumented.

## Retained records and integrity

Each native result contains exact declaration bytes, source snapshots, raw
streams, per-request TLS/client evidence and the generated gateway config.
Private keys and temporary executables are removed. The separate primary and
extracted-source executions use fresh credentials and payloads on the same host.
Publication outputs are generated from the primary audit. The package's
HTTP_RUNS.json maps aliases to original run identifiers.

The 30 auditor tests include a live-record mutation control. Without the live
path, one test is skipped. The auditor's ValidationError checks remain active
under Python -O, while the collection runner requires assertions enabled.
Source snapshots are hash-bound for reproducibility, not remote attestation.
