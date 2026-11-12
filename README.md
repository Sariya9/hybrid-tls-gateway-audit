# Hybrid TLS gateway audit artefact, revision 9

Revision 9 (12 November 2026) keeps every revision 8 file unchanged, except
for corrected command paths in analysis/README.md, and adds three folders.
The revision 8 text follows below and still describes the retained records.

## Added in revision 9

| Folder | What it holds |
|---|---|
| followup/ | Two follow-up experiments run on 12 November 2026: scripts and the full record of the one run |
| analysis_addendum/ | Recomputation of the Section VIII grouping with the gateway policy added |
| figures_rev9/ | The four paper figures with roles written out, and the script that draws them |

### Follow-up run (followup/)

`run_followup.py` runs six scenarios through unmodified HAProxy 3.4.7 in HTTP
mode, using the frozen `extensions/http_policy/origin_http.c` without edits.

* V1, V2, V3 test what happens when the gateway cannot verify the origin.
  V1 is the normal configuration, V2 gives the gateway the wrong expected
  host name, V3 gives it the wrong CA file.
* S1, S2, S3 are a scanner baseline. S1 and S2 repeat scenarios A01 and A03.
  In S3 the origin accepts hybrid and classical but the gateway offers
  classical only. testssl.sh and SSLyze are run against the gateway frontend
  and against the restricted origin.

Result of the retained run `followup/results/2026-11-12-followup-01`
(see its `summary.json`):

* V1: six requests admitted, each after the origin's handshake completed.
  V2 and V3: six HTTP 503 each, six failed origin handshakes, no completed
  origin handshake, no accepted request.
* testssl.sh gives the same frontend report for S1, S2 and S3 although only
  S1 conforms. The three frontends are configured identically, so this is
  expected by construction. Its origin report separates S2 but is identical
  for S1 and S3. SSLyze 6.3.1 does not test hybrid groups and reported only
  X25519 for every target.
* The record stores the testssl.sh commit (1bf1fe1, branch 3.2). The tool
  printed version 3.2.5 when it was installed; that number is not in the
  record.

Limits of this run: it was executed once, on a second macOS arm64 host
(macOS 26.3.1), with a gateway binary built on that host from the same
checksum-verified source archive, so its binary hash differs from the one in
the revision 8 records. For the scan phase only, a copy of the origin is
compiled with `RUN_SECONDS` raised from 60 to 900 so that it stays up while
the scanners run; the audited requests use the unmodified source.

How this run differs from the revision 8 studies: no expected outcomes were
written before it; it joins requests to gateway and origin records by
request identifier only and does not use the 30-test HTTP auditor; and the
scanners ran against a second instance of each scenario, started by the same
code, whose configuration file and gateway and origin logs were not saved.
The record also lacks the compiler version, library hashes and the HAProxy
build log. The scripts were written and launched with an AI coding
assistant. The records are written by the test programs and were not edited,
apart from the script's automatic replacement of local paths by $WORK and
$HOME in results.json and the raw text files.

To repeat it from the package root (the scanners are not included):

```sh
python3 -B extensions/build_haproxy.py \
  --openssl-prefix /opt/homebrew/opt/openssl@3 \
  --out /tmp/hybrid-tls-haproxy-build-new
python3 -B followup/run_followup.py --package . \
  --haproxy /tmp/hybrid-tls-haproxy-build-new/haproxy-3.4.7/haproxy \
  --testssl /path/to/testssl.sh/testssl.sh \
  --sslyze /path/to/venv/bin/sslyze \
  --work /tmp/hybrid-tls-followup-work \
  --out followup/results/NEW-RUN-NAME
python3 -B followup/summarise_followup.py followup/results/NEW-RUN-NAME
python3 -B followup/make_scanner_table.py followup/results/NEW-RUN-NAME
```

The last command prints the rows of the paper's scanner-baseline table.

Python must be linked against an OpenSSL that supports X25519MLKEM768.
The work directory holds temporary private keys and is deleted at the end.

### Grouping recomputation (analysis_addendum/)

```sh
python3 analysis_addendum/recompute_projection.py \
  reports/http-primary/request_outcomes.csv \
  reports/http-reproduction/request_outcomes.csv
```

It reads the two CSV files only. In both executions the minimum number of
unavoidable errors is 3 for the frontend summary, still 3 when the gateway
policy is added (scenarios A01 and A03, whose gateway configuration files
differ only in port numbers) and 0 when the backend group is added.

### Figures (figures_rev9/)

`redesign_figures_rev9.py` is `figures/redesign_figures.py` with changed
labels only: client, gateway and origin are written out, and "prediction"
is now "expected outcome". The inputs and checks are the same.

```sh
python3 -B figures_rev9/redesign_figures_rev9.py \
  --primary-results results/rerun-openssl/results.json \
  --http-results results/http-primary/results.json \
  --http-audit reports/http-primary/summary.json \
  --out /tmp/hybrid-figures-rev9-new
```

### Licence

The authors' code, scripts and records are released under the MIT licence
(see LICENSE). Three files are excerpts of other projects and keep their
upstream licences: `extensions/gnutls/fix_control/upstream-mr2111.diff` and
`extensions/gnutls/fix_control/upstream-supported-groups.patch` come from
GnuTLS, and `extensions/gnutls/leancrypto-darwin-build.patch` is a patch
against leancrypto. HAProxy, OpenSSL, GnuTLS, leancrypto, testssl.sh and
SSLyze are not included in this package.

### Notes on the older material

* The revision 8 text below says the experiments ran on one host. That is
  true for the revision 8 records; the follow-up run used a second host.
* Folder and field names such as `preregistration` and `prediction` are
  historical. The paper calls these expected outcomes fixed before the
  confirmation runs, after pilot runs, and does not describe the study as
  preregistered.
* `extensions/gnutls/MANIFEST.sha256` and
  `extensions/gnutls/fix_control/MANIFEST.sha256` are the original
  sub-manifests from the working tree. They name a few files that are not
  in this package and one README that changed afterwards. Use the top-level
  MANIFEST.sha256, which covers every file here.
* Some retained records contain the local host names `Mac.lan` and
  `localhost.lan` and `$HOME`-relative folder names. They are part of the
  hashed records and were left as collected.

---

# Revision 8 description (unchanged)

Native records collected on 25 October 2026; post-collection analysis and package updated on 2 November 2026. This package retains the earlier evidence and
adds four fresh native reruns covering 57 configurations. The current tables
and figures use those new runs. NATIVE_RERUNS.json maps portable aliases to
original run identifiers. RUNS.json and EXTENSION_RUNS.json retain the earlier
execution identities. The manuscript source ZIP compiles separately.



## Current observation analysis and redesigned figures

Revision 8 adds a post-collection observation analysis. It does not add native
trials or rewrite frozen declarations. Read analysis/README.md for the bounded
claim. Complete admissions have reference labels from the trusted full-evidence
auditor. Refusals retain a separate matched-control and service check.

Regenerate the new outputs from this extracted directory using fresh paths.

```sh
python3 -B analysis/observation_analysis.py \
  results/http-primary results/http-reproduction \
  --auditor extensions/http_policy/audit_http.py \
  --out /tmp/hybrid-observation-new
python3 -B -m unittest discover -s analysis -p test_observation_analysis.py -v
python3 -B figures/redesign_figures.py \
  --primary-results results/rerun-openssl/results.json \
  --http-results results/http-primary/results.json \
  --http-audit reports/http-primary/summary.json \
  --out /tmp/hybrid-figures-new
```

The new generator produces all four current vector diagrams and a manifest.
The older figure generators below remain for historical reproduction. Their
outputs are not the current diagram designs. The matched positive controls
and scenario-level refusal checks are in the observation report. The source
ZIP includes the revised paper and all ready-made vector figures.

## New HTTP application study

The current manuscript adds route-specific origin admission with persistent
HTTP/1.1 and observed backend sharing. HTTP_RUNS.json maps its two frozen
confirmation executions and three preserved development runs. Native code,
declaration and freeze are under extensions/http_policy. Each confirmation
contains 72 sequential requests across 12 scenarios; there are 36 native
children per execution. Do not interpret repetitions as independent field
scenarios, statistical rates or performance measurements.

Regenerate the HTTP audit and publication outputs from this extracted root.
Choose fresh output directories.

```sh
python3 -B extensions/http_policy/audit_http.py results/http-primary \
  --out /tmp/http-admission-audit-new
AUDIT_HTTP_RUN_DIRECTORY=results/http-primary \
  python3 -m unittest discover -s extensions/http_policy -p test_audit_http.py -v
python3 figures/build_http_figure.py \
  --results results/http-primary/results.json \
  --audit /tmp/http-admission-audit-new/summary.json \
  --out /tmp/http-admission-publication-new
```

Repeat the audit with results/http-reproduction to check the extracted native
execution. The new generator produces the observed request/session figure
and formatted HTTP table. The original framed figure generator below still
produces four historical figures; the current manuscript uses framework,
methodology and execution plus the new http_admission figure. The old nine-case
gateway table is retained in reports/extensions, while the manuscript's second
table is now the HTTP policy comparison.

Support-only, blanket-hybrid and per-route configurations use ordinary HAProxy
controls. This is a correlated audit/case study, not a new enforcement algorithm.
HTTP backends explicitly disable automatic SNI while retaining verify required
and verifyhost origin.test. A 503 needs native no-shared-group evidence.
Overblocking is checked against matched successful compatibility controls in
reports/http-primary/overblocking_controls.json. Rejected classical clients
may already have submitted their bodies; origin-admission compliance does not
establish confidentiality of every submitted byte. See the extension README
for native rerun commands and scope. Source snapshots bind the collector used
by each run. Current record tests include live malformed-evidence controls.

## Retained framed-control evidence

| Portable result alias | Native experiment | Configurations |
|---|---|---:|
| results/rerun-openssl | OpenSSL 3.6.3 cooperative relay | 16 |
| results/rerun-gnutls | Unmodified GnuTLS 3.8.13 cooperative relay | 16 |
| results/rerun-gnutls-fixed | GnuTLS 3.8.13 with upstream runtime fix | 16 |
| results/rerun-haproxy | Unmodified HAProxy 3.4.7 | 9 |

All configurations retain their frozen source and declaration. Each rerun
uses freshly generated synthetic payloads and local credentials. The existing
baseline TLS libraries and gateway binary are reused; the upstream-fix control
is rebuilt into a fresh private prefix. All 171 children were reaped without
timeout or forced cleanup. The same-host results repeat the retained findings.

Expected-observation agreement is separate from route conformance. M02, M05
and M07 intentionally deliver in violation of their declared hybrid policy.
Q_D checks completed delivered routes. P_D requires authentication and required
groups before every accepted application write, including length framing.
The seven HAProxy barrier counterexamples concern that declared boundary;
they are not a new TLS vulnerability or forwarding to an unverified origin.
H05/H06 remain uncertified under partial gateway observation.

The GnuTLS runtime patch is the pinned upstream supported_groups.c hunk. Its
new control-provenance.json binds archive, patch, changed source and actual
runtime hashes. Only M10 changes relative to the new unmodified baseline.
The original dependency_build.json records historical lineage and does not
describe a patched runtime. Fresh prefixes need their own unmodified baseline
before the paired control. No full upstream regression suite was run.

## Regenerate the publication outputs

Use Python with assertions enabled. Output directories must be new.

```sh
python3 -B extensions/report_extensions.py \
  --openssl results/rerun-openssl/results.json \
  --gnutls results/rerun-gnutls/results.json \
  --gnutls-fixed results/rerun-gnutls-fixed/results.json \
  --haproxy results/rerun-haproxy/results.json \
  --out /tmp/hybrid-tls-tables-new
python3 -B figures/build_figures.py \
  --results results/rerun-openssl/results.json \
  --out /tmp/hybrid-tls-figures-new
```

The table generator invokes the supplemental causal checker before producing
tables, CSVs and causal_evidence.json. Figure regeneration uses Matplotlib;
the separate source ZIP supplies ready-made vector figures for compilation.
Current generated outputs are in reports/extensions, reports/rerun-reference
and figures. Historical reference outputs remain in reports and the original
runs remain under their earlier aliases.

## Record checks and negative controls

```sh
python3 -m unittest discover -s extensions -p test_release_order.py -v
python3 -B extensions/gnutls/check_records.py results/rerun-gnutls
python3 -B extensions/gnutls/check_records.py results/rerun-gnutls-fixed
```

The default causal suite replays the earlier packaged corpus. The same suite
was also bound to the fresh records, with 16 methods passing. To reproduce
that fresh-record test without editing the frozen sources, run this from the
extracted root. The historical fixture labels below are only lookup keys.

```python
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path('extensions').resolve()))
import test_release_order as tests
bindings = {
    '2026-10-24-primary-02': 'rerun-openssl',
    '2026-10-24-gnutls-confirmatory-01': 'rerun-gnutls',
    '2026-10-24-haproxy-primary-01': 'rerun-haproxy',
}
tests.REFERENCE_RUNS = tuple(list(bindings)[:2])
tests.GATEWAY_RUNS = (list(bindings)[2],)
tests.record_path = lambda key: Path('results') / bindings[key] / 'results.json'
result = unittest.TextTestRunner(verbosity=2).run(
    unittest.defaultTestLoader.loadTestsFromTestCase(tests.ReleaseOrderTests))
assert result.wasSuccessful()
```

New analysis records are in reports/native-rerun, including explicit test path
bindings, comparisons with retained runs and runtime identities. Negative
controls reorder events, corrupt payloads or remove authentication evidence.
Input records are checked for preservation. GnuTLS's raw-record checker is a
consistency check using its collector's rules, not an independent oracle.

## Execute the native matrices again

Use a C11 compiler, Python and installed OpenSSL 3.5+ with hybrid support.
The retained host is macOS arm64 with Apple Clang 21.0.0 and Python 3.14.5.
The runners compile temporary native fixtures, generate local credentials
and remove temporary files. All traffic uses IPv4 loopback. They install no
global service and require fresh result paths.

```sh
python3 -B run_policy_matrix.py --out /tmp/hybrid-tls-openssl-new
```

Build the pinned GnuTLS/leancrypto runtime using the supplied local helper
when a compatible prefix is unavailable, then run the unmodified matrix.
The helper requires the documented Homebrew build dependencies on macOS.

```sh
python3 -B extensions/gnutls/build_local_dependencies.py \
  --work /tmp/hybrid-tls-gnutls-build-new
python3 -B extensions/gnutls/run_gnutls_matrix.py \
  --prefix /tmp/hybrid-tls-gnutls-build-new/prefix \
  --matrix extensions/gnutls/matrix.confirmatory.json \
  --out /tmp/hybrid-tls-gnutls-new
python3 -B extensions/gnutls/fix_control/run_control.py \
  --base-prefix /tmp/hybrid-tls-gnutls-build-new/prefix \
  --baseline /tmp/hybrid-tls-gnutls-new/results.json \
  --work /tmp/hybrid-tls-gnutls-fixed-build-new \
  --out /tmp/hybrid-tls-gnutls-fixed-new
python3 -B extensions/build_haproxy.py \
  --openssl-prefix /opt/homebrew/opt/openssl@3 \
  --out /tmp/hybrid-tls-haproxy-build-new
python3 -B extensions/haproxy/run_matrix.py \
  --haproxy /tmp/hybrid-tls-haproxy-build-new/haproxy-3.4.7/haproxy \
  --out /tmp/hybrid-tls-haproxy-new
```

The GnuTLS collector uses GnuTLS for TLS and OpenSSL only to make test
credentials. HAProxy uses the baseline OpenSSL library, so it adds gateway
coverage rather than a third TLS state machine. See the implementation
READMEs for build limits, failure controls and the preserved exploration.

## Integrity and scope

MANIFEST.sha256 covers packaged files. Actual collector, source, matrix,
configuration and runtime hashes remain in the records. Private credentials,
local binaries, dependency trees and private research context are excluded.
The experiments use classical certificate authentication and finite synthetic
loopback exchanges on one host. They do not establish production prevalence,
platform independence, concurrency performance or general conformance.
