# Historical evaluation (adapter r2_s7, band [0.44, 0.98])

**These are historical results from 1 Nov 2026, not metrics freshly reproduced from this checkout or under the 3 Nov
hardening changes.** The labelled datasets, predictions, and real-world repository are private. Historical inference
used Muse Spark `muse-spark-1.3` with low reasoning effort and Semgrep OSS 1.183.0 with `p/java`.

Two later public live runs are recorded separately in `PUBLIC_EVALUATION.md`. Their metrics are not pooled with each
other or with the tables below, and they do not replace the historical private 83/87 Semgrep-clearance figure.

The dev set influenced model and band selection. The real set was excluded from direct selection scores but influenced
targeted training-data design after round-1 failures, so it is **not an independent test set**.

The classifier probabilities came from round-2 dataset-prompt runs with batch size 1. A historical fresh Modal run with
unscrubbed harness prompts put 100/105 real alerts in the same lane (mean |Δp| 0.012) with the same argmax accuracy
(0.924). The default batch-8 prediction path can drift; this historical comparison is not a new reproduction.

## Lanes vs labels

| set | alerts | confident TP (lane 1) | needs review (lane 2) | likely FP (lane 3) | lane-1 precision | lane-3 precision | auto-lane accuracy | coverage |
|---|---|---|---|---|---|---|---|---|
| dev (6 public repos) | 82 | 31 (31 TP) | 20 (11 TP / 9 FP) | 31 (31 FP) | 1.000 | 1.000 | 1.000 | 0.756 |
| real (private repo) | 105 | 72 (72 TP) | 30 (24 TP / 6 FP) | 3 (2 TP / 1 FP) | 1.000 | **0.333** | 0.973 | 0.714 |

- Historical classifier argmax accuracy: dev 0.890, real 0.924.
- **Beside that real-set claim:** always predicting TP scores **0.933 accuracy** (98 TP / 105) and **0.5 balanced
  accuracy**. The real set has only **seven FP**, so its accuracy and FP-rejection estimates are highly limited.
- Argmax errors routed to review: dev 9/9, real 6/8.
- **2 real bugs landed in the likely-FP lane.** This is why that lane is never suppressed and requires human review.

## Historical Muse Spark audit vs labels

Every alert was audited; the likely-FP lane used the short confirmation prompt.

| | dev | real |
|---|---|---|
| audit agrees with label (all) | 75/82 (91%) | 98/105 (93%) |
| on confident TP lane | 31/31 | 71/72 |
| on needs review lane | 18/20 | 25/30 |
| on likely FP lane | 26/31 | 2/3 |
| on labelled TPs | 41/42 | 95/98 |
| on labelled FPs | 34/40 | 3/7 |
| classifier argmax on the same alerts | 73/82 | 97/105 |
| audit agrees with classifier | 68/82 | 100/105 |
| real bugs in likely FP lane re-flagged by audit | - | 1/2 |

The historical audit was slightly more accurate than classifier argmax on these sets but confirmed only 3/7 real FP.
It explains and flags; it never suppresses an alert or decides alone.

## Historical remediation on real-set true positives

All 87 labelled TPs of verifiable rule types were attempted across lanes. **83/87 is historical Semgrep clearance under
the earlier same-rule check.** It is not a count of semantic fixes and was not reproduced under the stricter verifier
that rejects new alerts of any rule.

| category | attempted | historically Semgrep-cleared | fix suggested, unverified |
|---|---|---|---|
| SQL injection (formatted-sql-string) | 31 | 29 | 2 |
| XXE (DocumentBuilder / SAXParser / Transformer factories) | 26 | 26 | 0 |
| weak crypto (MD5, SHA-1, DES/3DES, RC4, ECB, static IV, CBC padding, RSA-512, SSL context) | 26 | 26 | 0 |
| open redirect | 2 | 2 | 0 |
| path traversal | 2 | 0 | 2 |
| **total** | **87** | **83 (95.4%)** | **4** |

The four unverified historical proposals were two ORDER BY cases still reported by Semgrep and two path-traversal
cases still reported and/or producing new same-rule alerts. Original files had matching SHA-256 hashes before and after.

For these historical results and for any current successful re-check, the claim is only **“Semgrep-cleared; not compiled
or tested.”** Spot checks found minimal rather than ideal changes. In particular, fast SHA-256 is inappropriate for
password storage; use Argon2id, bcrypt, scrypt, or PBKDF2. Non-password integrity/HMAC and authenticated encryption are
separate use cases. An SSL→TLSv1.2 change can also leave a trust-all TrustManager in place.

## Historical cost

The 1 Nov evaluation (187 audits + 87 remediation proposals) recorded **$1.32** Muse Spark spend, about $0.0036 per
audit and $0.006 per fix proposal. This is an aggregate historical disclosure, not a newly reproduced run.
