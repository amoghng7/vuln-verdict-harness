# vuln-verdict harness

Triage for Semgrep findings on Java code. A fine-tuned classifier (Muse Glimmer 30B + the `r2_s7` LoRA adapter) sorts
each SARIF alert into a lane. Muse Spark can audit alerts and propose fixes. Successful remediation is reported only as
**“Semgrep-cleared; not compiled or tested.”** It is not a claim of semantic correctness.

> **vuln-verdict never silently drops, suppresses or hides an alert.** Every input SARIF result stays in the
> annotated SARIF (`properties.vulnVerdict.neverSuppressed = true`, no `suppressions` added) and is listed in the
> report. The *likely false positive* lane only lowers an alert's priority: it gets a short explanation and still needs
> a human to confirm it. The classifier has missed real bugs at high false-positive confidence (2 of the 3 alerts in
> this lane on our historical real-world set were real bugs).

## Lanes (adapter r2_s7, calibrated band [0.44, 0.98])

| p_true | lane | what the harness does |
|---|---|---|
| >= 0.98 | **confident TP** | Muse audit + remediation (verifiable rule types) |
| 0.44 - 0.98 | **needs review** | Muse audit (explanation, attack path, severity), flagged for a human |
| < 0.44 | **likely FP - confirm** | short Muse explanation of why it looks safe + what to check; never auto-suppressed |
| missing | **unclassified** | kept and shown; treat as needs review |

Use `--lo` and `--hi` to change the band. Invalid, non-finite, duplicate, or ambiguous classifier inputs fail closed.

## Offline judge quickstart

The bundled tiny example uses precomputed probabilities and needs no GPU, Modal, Meta API key, live Semgrep scan, or
private data. Dependency installation may need network access.

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
MODEL_API_KEY= python -m vuln_verdict triage examples/tiny/semgrep.sarif \
    --repo examples/tiny --probs-file examples/tiny/probs_r2_s7.jsonl --out out/tiny
```

This writes `annotated.sarif`, `report.md`, `report.html`, and `state.jsonl`. All six input results remain visible and
unsuppressed. The tests mock Semgrep and Meta API behavior and run entirely offline.

`requirements-semgrep.txt` pins Semgrep OSS **1.183.0** for users who want fresh scans or remediation re-checks;
installing it is not part of the offline quickstart.

## Author-only online reproduction

The published evaluation is historical, not freshly reproduced from this checkout. The repository and
`amoghng7/vuln-verdict-muse-glimmer-30b-lora` adapter remain private. Training/evaluation JSONL, predictions, and the
real-world evaluation repository are not distributed, so `scripts/evaluate.py` cannot recreate the published metrics
without those author-held inputs. See `DATA.md` and `EVAL.md`.

For an authorized Modal classifier run:

```bash
python -m pip install -r requirements-modal.txt
python -m vuln_verdict triage results.sarif --repo path/to/repo --out out/x --modal
```

The ephemeral app stops when the local Modal call returns. Pinning `modal==1.6.3` alone is not a runtime-validation
claim. Modal configuration:

| variable | default / meaning |
|---|---|
| `VV_BASE_MODEL` | `meta-models/Muse-Glimmer-30B` |
| `VV_BASE_MODEL_REVISION` | unset; set an immutable Hugging Face commit for reproducible inference |
| `VV_GPU` | `A100-80GB` |
| `VV_HF_VOLUME` | `muse-glimmer-hf-cache` |
| `VV_ADAPTER_VOLUME` | `vuln-verdict-outputs` |
| `--adapter` | `r2_s7`; adapter path is `/vol/outputs/r2_s7/adapter` on the selected volume |

`MODEL_API_KEY` is separately required for Meta Muse Spark audit/remediation calls. A full online command is:

```bash
python -m vuln_verdict triage results.sarif --repo path/to/repo --out out/x \
    --modal --audit --remediate
```

`scripts/demo.sh` runs the tiny example. Given a repository path, it also copies that repository, deletes the stale
destination SARIF, and fails if the fresh Semgrep scan fails. With `PROBS` unset, repository classification uses Modal.
Set `MODEL_API_KEY` only when Meta audit/remediation is intended.

## Outputs, caches, and spend

Outputs in `--out`:
- `annotated.sarif`: every result gets `properties.vulnVerdict` with lane, probability, audit, and fix fields.
- `report.md`, `report.html`, and `state.jsonl`.
- `audits.jsonl` and `fixes.jsonl` caches when online stages run.
- `remediation/*/patches/*.patch` when a patch is generated.

Cache reuse requires both the alert ID and a fingerprint of its file, lines, rule ID, message, and formatted code.
Legacy rows and content-fingerprint mismatches are ignored. A later invocation reloads every fingerprint-valid
audit and fix row before it writes the four report artifacts, including when that invocation runs only one stage.
Changed alert content and a different alert ID are not reused. Model/prompt/experiment and Semgrep configuration
changes are not complete cache keys; use a fresh output directory when changing those settings.

Main flags:
- `--max-audits` (default 100) and `--max-fixes` (default 30), both non-negative.
- `--remediate-lanes confident_tp[,needs_review]`.
- `--effort low` for Muse reasoning effort.
- `--semgrep-bin` and `--semgrep-config p/java`.
- `--scrub`, an evaluation-only identifier scrub matching the real-set dataset.

Muse spend controls:
- `VV_SPEND_FILE` (default `./vv_spend.json`) stores actual spend and worst-case reservations under a file lock.
- `VV_BUDGET_USD` (default `$5`) caps total recorded spend plus reservations; it is not a fresh allowance per command.
- `VV_MUSE_MODEL`, `VV_MUSE_BASE`, `VV_PRICE_IN_PER_M`, and `VV_PRICE_OUT_PER_M` configure the Meta endpoint and prices.
- A reservation is persisted before each API call and released afterward. **A crashed process may leave a conservative
  stale reservation.** Reset or remove spend state only after confirming no harness processes are running.

Keep spend files, caches, generated reports/SARIF, patches, and credentials out of submissions and public artifacts.

### Classifier input

`vuln_verdict/sarif.py` and `vuln_verdict/snippet.py` rebuild the training prompt layout: comments are stripped, the
alerted class is renamed `RequestHandler` only as a whole identifier (constructors and other type uses included),
code is line-numbered, snippets are windowed/elided, and the header carries Semgrep rule, severity/confidence, CWE,
and message. That rename does not rewrite string literals, character literals, text blocks, or comments. Ordinary
single-line strings still pass through the documented `neutral_literal()` scrub. `--probs-file` accepts JSONL rows
keyed by `alert_id`, by `file`/`line`/`rule_id`, or by integer `idx`.

The historical prompt-parity and Modal comparisons are recorded in `EVAL.md`. Two later public live runs are in
`PUBLIC_EVALUATION.md`. They are not fresh reproductions of the historical metrics.

## Repository containment and remediation

SARIF artifact paths are untrusted. Absolute and `file://` paths are accepted only when their canonical resolved target
is inside the repository. Parent traversal, outside absolute paths, percent-encoded escapes, NUL bytes, unsupported URI
schemes, and symlinks escaping the repository are rejected. Alerts with unavailable or unsafe context remain visible
with an error and are not sent to a model.

Patch and sandbox writes use the same canonical containment beneath their output roots. This is filesystem path
containment, not an OS-level security sandbox. Muse edits are applied only to sandbox copies. The original repository
is never written to, and SHA-256 hashes before and after remediation verify that original source files are unchanged.

A raw status of `fix verified` requires all of the following:
1. The baseline Semgrep scan reproduces the original alert.
2. The patched scan no longer reports that alert at its mapped line.
3. No new alert of **any rule** appears in the patched file.
4. Semgrep reports no new parse error, delimiters are balanced, and `javalang` parses the patch when it parsed the original.

The user-facing result is exactly **“Semgrep-cleared; not compiled or tested.”** Otherwise the status is
`fix suggested, unverified` or `no fix attempted`. No compilation, project tests, or semantic-correctness verification
is performed.

Remediation guidance is purpose-specific:
- SQL injection: parameterised queries and allow-lists for identifiers that cannot be bound.
- XXE: disable external entities/DTDs as appropriate for the parser.
- Password storage: use **Argon2id, bcrypt, scrypt, or PBKDF2** with unique salts and appropriate cost, never a fast
  SHA-256 digest.
- Non-password integrity: SHA-256/SHA-512 may be appropriate for unkeyed integrity; use HMAC when authentication by a
  shared key is required.
- Confidentiality and authenticated encryption: use an AEAD mode such as AES-GCM with fresh random nonces, not a hash or
  unauthenticated CBC/ECB encryption.
- Optional redirect and path-traversal fixes use fixed allow-lists and canonical containment.

Some fixes change behavior or require data migration. Muse records these as caveats; humans must review every patch.

## What is new work

Project code and the fine-tuning/evaluation work were developed during the Meta hackathon. They build on third-party
inputs including OWASP Benchmark code and labels, Semgrep engine/rules, six public development repositories, the Muse
base model, and Muse-generated synthetic data. Those inputs have separate licenses and provenance; see `DATA.md`.

The dev set influenced model and band selection. The real set was excluded from direct selection scores but influenced
targeted training-data design, so it is not an independent test set.

## Layout

```
vuln_verdict/   cli.py sarif.py snippet.py lanes.py classifier.py muse.py audit.py remediate.py pipeline.py report.py
modal_app/      classifier_modal.py (ephemeral Modal app; needs base + adapter volumes)
examples/tiny/  self-written Java, self-written demo SARIF metadata, bundled probabilities
scripts/        demo.sh, evaluate.py (private-data evaluation entry point)
tests/          offline pytest suite (no GPU, API key, Modal, network, or Semgrep)
```

See `EVAL.md` for historical metrics, `PUBLIC_EVALUATION.md` for the separate public live runs, and `SUBMISSION.md`
for the author submission checklist.
