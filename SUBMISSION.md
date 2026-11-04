# Author submission checklist

Complete and verify every item before changing repository visibility or submitting artifacts.

## Git history and distribution

- [x] Purge restricted historical Git blobs, including deleted registry-derived content, or replace the repository with
      a verified clean snapshot. A deletion in the current tree is not history cleanup.
- [x] Inspect the complete final diff and all distributed files; confirm there are no unrelated fixture rewrites or
      generated artifacts.

  Completed by verified clean-snapshot recreation. The clean root snapshot was
  `38030a86a5234ac941f7919f0f9633a2e18b4076`; the tracked-tree audit passed, all nine checked historical commits
  returned HTTP 422 through the replacement repository, both affected blobs returned HTTP 404, and offline-tests run
  `41690341437` succeeded.

- [ ] Recheck Semgrep Rules License v1.0, OWASP GPL-2.0 obligations, and all third-party provenance notices.

## Judge, repository, model, and adapter access

- [ ] Confirm judges can access the intended code repository and offline tiny example without private credentials.
- [ ] Make the Hugging Face adapter repo public and confirm `scripts/run_real_model.sh fetch` works without a token.
      The script was tested on Modal with a token while the adapter was still private.
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

`PUBLIC_EVALUATION.md` records two public live runs. That document does not close judge access, private reproduction,
or the adapter-identity comparison above. Fresh public Semgrep clearance does not replace the historical private 83/87
figure. Run B's MD5 observations are pre-fix evidence, not a measured accuracy gain.

## Secret and output hygiene

- [ ] Never commit or expose credentials, API keys, signed URLs, spend logs, caches, generated SARIF/reports/state,
      patches, private datasets, model weights, or evaluation repositories.
- [ ] Check command output, CI logs, screenshots, demos, and environment/configuration examples for secrets and private
      paths before sharing them.
- [ ] Keep generated demo output in ignored directories and use mocks for offline Semgrep/Meta tests.
- [ ] Verify all six tiny alerts remain in annotated SARIF and reports with `neverSuppressed=true` and no suppressions.
- [ ] Confirm original source hashes remain unchanged and crashed-process stale spend reservations are handled only
      after confirming no harness processes are running.
