# Author submission checklist

Complete and verify every item before changing repository visibility or submitting artifacts.

## Git history and distribution

- [ ] Purge restricted historical Git blobs, including deleted registry-derived content, or replace the repository with
      a verified clean snapshot. A deletion in the current tree is not history cleanup.
- [ ] Inspect the complete final diff and all distributed files; confirm there are no unrelated fixture rewrites or
      generated artifacts.
- [ ] Recheck Semgrep Rules License v1.0, OWASP GPL-2.0 obligations, and all third-party provenance notices.

## Judge, repository, model, and adapter access

- [ ] Confirm judges can access the intended code repository and offline tiny example without private credentials.
- [ ] Explicitly arrange and test any intended judge access to the private repository and private `r2_s7` adapter; do
      not assume public access.
- [ ] Record adapter checksums and verify the adapter at `/vol/outputs/r2_s7/adapter` matches the reviewed artifact.
- [ ] Pin `VV_BASE_MODEL_REVISION` to an immutable base-model commit and record the adapter identifier, Semgrep 1.183.0,
      dependency pins, and relevant volume names. Do not present a floating model or registry version as immutable.

## Rules, terms, and honest claims

- [ ] Recheck the current hackathon rules, eligibility/deadline requirements, and Meta API terms immediately before
      submission, including synthetic-data, trained-output, and redistribution restrictions.
- [ ] Separate the offline judge quickstart from author-only online reproduction. Do not claim private evaluation or
      historical online metrics were reproduced unless they actually were.
- [ ] Disclose dev-based selection, real-set targeted-data non-independence, the 0.933 always-TP accuracy and 0.5
      balanced-accuracy baselines, and the seven-FP limitation beside real-set claims.
- [ ] Describe 83/87 only as historical Semgrep clearance under the earlier same-rule check, not semantic fixes or a
      stricter-verifier result.
- [ ] Describe successful remediation only as **“Semgrep-cleared; not compiled or tested.”** Never imply compilation,
      project tests, semantic correctness, or original-repository modification.

## Secret and output hygiene

- [ ] Never commit or expose credentials, API keys, signed URLs, spend logs, caches, generated SARIF/reports/state,
      patches, private datasets, model weights, or evaluation repositories.
- [ ] Check command output, CI logs, screenshots, demos, and environment/configuration examples for secrets and private
      paths before sharing them.
- [ ] Keep generated demo output in ignored directories and use mocks for offline Semgrep/Meta tests.
- [ ] Verify all six tiny alerts remain in annotated SARIF and reports with `neverSuppressed=true` and no suppressions.
- [ ] Confirm original source hashes remain unchanged and crashed-process stale spend reservations are handled only
      after confirming no harness processes are running.
