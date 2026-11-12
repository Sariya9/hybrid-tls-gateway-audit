# GnuTLS upstream-fix control

This control builds GnuTLS 3.8.13 with the runtime source hunk from upstream
merge request !2111. It uses the existing leancrypto dependency and the frozen
native collector. It is an additional control on the existing implementation,
not a new platform or released GnuTLS version.

The upstream records are [issue #1828](https://gitlab.com/gnutls/gnutls/-/work_items/1828)
and [merge request !2111](https://gitlab.com/gnutls/gnutls/-/merge_requests/2111).
The merge commit is `33356a545e83c90eb225eee4ee2745277de0bd58`.
`source-provenance.json` pins the downloaded full diff and the applied patch.
The patch contains the verbatim `lib/ext/supported_groups.c` hunk. The full
upstream diff also changes CI and an upstream test script; those hunks are
retained for inspection but are not applied. No protocol hunk is hand-edited.

## Frozen hypothesis

`matrix.confirmatory.json` preserves all sixteen baseline configurations.
Only M10's expected outcome changes, from C/C refusal to H/H delivery, on the
basis of the published fix. Other expectations are unchanged. The inherited
M10 question label remains historical text; `expected` is the operative
prediction. Predictions must remain frozen even if this hypothesis fails.

## Local reproduction

Run from the project root. Both output paths must be new.

```sh
python3 -B testbed/icete2027/gnutls/fix_control/run_control.py \
  --base-prefix testbed/icete2027/gnutls/.local/prefix \
  --baseline results/icete2027/2026-10-24-gnutls-confirmatory-01/results.json \
  --work testbed/icete2027/gnutls/.local/fix-control \
  --out results/icete2027/2026-10-25-gnutls-fix-control-01
```

The helper reuses a checksum-verified cached GnuTLS archive or downloads the
same pinned archive from upstream. `--archive` can supply an explicit copy.
An extracted package must include the unchanged collector, C adapter,
original confirmation matrix and `dependency_build.json` in the parent
directory. The base prefix must supply the existing compatible leancrypto
library, headers and pkgconf. Nettle/Hogweed, GMP and the other dependencies
remain at the Homebrew paths used by the original macOS build. A different
dependency prefix may be supplied after the existing dependency build helper
has constructed it. First run the unmodified collector against that fresh
prefix, then pass that new run as --baseline. Binary hashes can differ across
installation paths; a historical run is not interchangeable with the fresh
baseline. The control checks its leancrypto bytes against the chosen
baseline. This is a bounded macOS reproduction helper, not a general
dependency installer.

Only GnuTLS is rebuilt. Installation is confined to the new work prefix.
The helper refuses existing work or result paths, checks the matrix change,
applies the patch with zero fuzz and checks that only the named source file
changes. Local build logs and source-tree manifests remain under the work
directory. The collector creates fresh credentials and application bytes.
Unexpected outcomes remain in its records and produce a failed hypothesis
comparison; the helper never updates predictions after execution.

## Provenance boundaries

The collector's `dependency_build_manifest_sha256` still identifies the
original, unchanged `dependency_build.json`. That file describes original
dependency lineage and must not be presented as a descriptor of this patched
build. `control-provenance.json` in the result directory separately binds the
patch, source archive, pre/post source hashes, runtime library hash and
collector/matrix hashes. It also records build flags and command provenance.
`comparison.json` compares the new observations with the selected retained
unmodified run. Different output prefixes affect install paths; the source
control changes only the recorded upstream runtime hunk.

The local `prestate.json` audit records baseline artefact hashes and is excluded
from the public package. The full source archive, source trees and local build executables belong
under `.local/`, outside the manuscript source package. Include the small
control sources, patch, provenance and retained observations in the empirical
reproducibility package if the parent integrates this control.

No global installation, upstream full regression suite, performance study or
external endpoint test is included. All TLS traffic remains synthetic loopback.

## Retained execution on 25 October 2026

The first build and execution completed successfully. The patch applied without
fuzz or offset. Its resulting Git blob is
`d1182b2bc8b419465045169b4a67d5ce416bd441`, matching the upstream diff.
Before configuration, the source-tree check found only one changed file.
The applied patch SHA-256 is
`24e145ebdec8a68334a032c6e9ff210e14032a8a280159b2d8fc3400d57741a5`.

All sixteen frozen predictions matched. Only M10 changed its negotiated groups
and route verdict relative to the retained unmodified run.

| Observation | Unmodified GnuTLS 3.8.13 | 3.8.13 with the upstream runtime fix |
|---|---|---|
| M10 support and initial shares | H,C lists with H initial shares on both legs | Same |
| M10 negotiated groups | C/C through HRR on both legs | H/H without HRR |
| M10 both-leg guard | Blocks before READY | Permits delivery after verification |
| M10 application result | Zero accepted application bytes | Exact 303-byte request and 319-byte response |
| Other 15 group and verdict outcomes | Retained baseline | Unchanged |
| Outcomes per 16-case execution | 5 conforming deliveries, 3 violations and 8 refusals | 6 conforming deliveries, 3 violations and 7 refusals |

The M10 initiators independently verified `proxy.test` and `origin.test`.
The delivered exchange has 1,244 accepted payload bytes across both legs,
plus 16 length-framing bytes. Each direction's exact payload was correlated
at all four observations. Classical P-256 certificate authentication remains
unchanged. The successful run used fresh payload bytes and fresh certificates.
All 48 native processes were reaped without timeouts or cleanup signals.

The supplemental `check_release_order.py` was called read-only on the new
records. It derived the same outcomes and checked 1,778 local-order constraints
under its declared cooperative-fixture assumptions. Its exact hash is retained
in `causal-check.json`; it is not a proof for all possible executions.

The result directory is
`results/icete2027/2026-10-25-gnutls-fix-control-01/`. It contains the unchanged
collector's `results.json`, `trace.txt`, per-process raw streams and declaration,
plus `control-provenance.json`, `comparison.json`, `outcomes.csv` and supplemental
checks. Redacted build logs are retained alongside them. The runtime GnuTLS
library SHA-256 is
`c7a41e84e8601809dd7b437fec8f37dc5771ead8ebc0c88418ac732fbc497811`.
The compiler version and all recorded crypto-dependency library hashes match
the selected baseline. A preservation check found no changes to 431 retained
baseline files, including the collector, matrices, original metadata and runs.

This supports the known-fix hypothesis for this configuration and build.
It does not evaluate a newly released GnuTLS version or establish a broader
platform result. New certificates, payloads and installation paths are recorded
procedural differences. No additional protocol or priority-string change was
used to obtain the result.
