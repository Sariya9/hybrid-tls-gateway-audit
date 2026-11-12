# Request-correlated observation analysis

This is a post-collection analysis of validated native HTTP records. It does
not change the frozen collector, auditor, declaration or native predictions.
It compares three diagnostic rules on complete admissions only and computes
the minimum binary errors forced by the explicitly listed observation
projection. The reference labels use the full auditor under its trusted local
observer and gateway execution assumptions. No prior tool is reproduced.

It also requires a matched conforming control for every excessive-refusal
claim, checks finite-cohort service separately from admission safety and
requires every failed TLS attempt at each selected origin with a 503 to show
no shared group. Refusal reasons retain scenario-level attribution. There is
no per-request join to a specific failed backend attempt.

From the package root, use fresh output directories.

```sh
python3 -B analysis/observation_analysis.py \
  results/http-primary results/http-reproduction \
  --auditor extensions/http_policy/audit_http.py \
  --out /tmp/hybrid-tls-observation-new
python3 -B -m unittest discover -s analysis \
  -p test_observation_analysis.py -v
```

Each execution has 42 complete admissions, comprising 33 conforming and nine
violating requests. Delivery only produces nine false compliance decisions;
the declared frontend minimum produces three; requiring H/H while ignoring
the route declaration produces 24 false violations. One projection class
contains nine conforming and three violating admissions, giving a minimum of
three binary errors. Abstaining can avoid a wrong verdict but leaves those
requests uncertified. These are controlled case counts, not field rates or
cryptographic indistinguishability claims. All 12 excessive refusals have
matched positive controls. The three policies each have 15 eligible requests;
blanket H serves three, while the other policies serve all 15. Support-only
also admits nine violating requests, so service success alone is insufficient.
