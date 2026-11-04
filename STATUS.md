# vuln-verdict-harness status

The GitHub repository `amoghng7/vuln-verdict-harness` and Hugging Face adapter repository
`amoghng7/vuln-verdict-muse-glimmer-30b-lora` remain **private**.

## Historical status — 2 Nov 2026

The following records the original 2 Nov status; it is not a claim that those online runs were reproduced during
hardening. All five original stages were reported done, with no Modal apps left running at that time.

### Stage 1 — triage CLI, lanes, annotated SARIF and report
- CLI wrote annotated SARIF, Markdown, and HTML reports.
- With `--scrub`, harness prompts matched the private real dataset for 105/105 alerts.
- Historical Modal checks reported the expected tiny lanes and 100/105 matching real-set lanes (mean |Δp| 0.012), with
  0.924 real-set argmax accuracy.

### Stage 2 — Muse Spark audit
- Structured verdict, explanation, attack path, and severity; likely-FP alerts received a confirmation prompt.
- Cap priority was needs review, likely FP, then confident TP. Unaudited alerts remained visible.

### Stage 3 — remediation with Semgrep re-check
- Search/replace edits were applied to sandbox copies, with baseline/patched Semgrep scans, parse checks, and original
  SHA-256 checks.
- Tiny 5/5 and real-set 83/87 were historical Semgrep-clearance reports under the earlier same-rule check. They were
  not compiled or tested and were not reproduced under the stricter any-new-rule verifier.

### Stage 4 — demo and stage 5 — evaluation
- The historical user-repository demo reported 105 alerts, all audited, and 10/10 Semgrep-cleared proposals under the
  then-current check. One likely-FP alert was re-flagged by Muse as SQL injection.
- Aggregate historical evaluation results are in `EVAL.md`.
- Historical spend disclosures were $1.91 harness Muse spend (413 calls) and $23.72 total in the then-selected spend
  file, under the historical $45 cap. These scopes differ from the default per-spend-file `$5` budget.

### Tests at that time
- 10 offline pytest tests passed without GPU, API key, or Semgrep.

## Hardening — 3 Nov 2026

- Replaced bundled registry-derived demo text with self-written metadata and documented the omitted restricted rule
  catalog. Historical blobs were subsequently removed from the published repository by verified clean-snapshot
  recreation; see below.
- Hardened canonical SARIF/repository/sandbox containment, classifier input validation, lane/cap validation, original
  source-integrity checks, Semgrep exit handling, cache fingerprints, persistent spend reservations, and multi-run alert
  retention.
- New alerts of any rule now block remediation clearance. Successful remediation is described only as
  **“Semgrep-cleared; not compiled or tested.”**
- Added classifier recalls/balanced accuracy, always-TP baselines, Semgrep-clearance evaluation disclosures, pinned
  dependency sets, offline CI, and adversarial regression tests.
- **56 offline tests passed.** No Meta API calls, live Semgrep runs, private evaluation, or reproduction of the
  historical online evaluation were performed for this hardening. Patched Java projects were not compiled or tested.

## Repository history cleanup — completed 3 Nov 2026

- Recreated the repository under the same name with a new internal repository ID and pushed only the verified clean
  snapshot `38030a86a5234ac941f7919f0f9633a2e18b4076`.
- At cleanup, that snapshot had the tested tree `3e43efc2d61f4f2225840752a391c02235b8dbad` and exactly one parentless
  commit. Later reviewed dependency and documentation commits do not reintroduce the old history.
- All nine checked historical commit IDs returned GitHub's explicit HTTP 422 no-commit-found response through the
  replacement repository. Both restricted historical blobs returned HTTP 404.
- A fresh mirror confirmed that neither affected blob was reachable from any remote ref. The offline-tests workflow run
  `41690341437` completed successfully on the clean snapshot.
- The repository remained private. Private Git and metadata backups were retained outside the repository; no generated
  outputs, credentials, private datasets, weights, caches, spend logs, or local configuration were added to the clean
  snapshot.

## Correctness fixes — 4 Nov 2026

- Java class anonymization is token-exact. It renames the alerted type and its constructors, and it no longer rewrites
  string literals, character literals, text blocks, comments, or longer identifiers. `neutral_literal()` is unchanged.
- A later CLI invocation reloads fingerprint-valid audit and fix caches before writing `annotated.sarif`, `report.md`,
  `report.html`, and `state.jsonl`. Changed alert content and a different alert ID are not reused.
- **69 offline tests passed.** The tiny demo retained six unsuppressed alerts and wrote all four report artifacts.
  No Meta API calls, live Semgrep runs, or bulk paid evaluation were performed for these fixes.
- Two public live runs are documented in `PUBLIC_EVALUATION.md`. Run B's MD5 classifier and audit notes are pre-fix
  evidence. The anonymization fix is not an accuracy result. Isolated Java compilation was **NOT RUN**: no container
  runtime or Java build tool was available, and the projects were not executed on the host.
